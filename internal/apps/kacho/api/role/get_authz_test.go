// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// get_authz_test.go — RoleService.Get read==enforce + no existence-leak for
// CUSTOM roles.
//
// The bug: RoleService.Get treated the role catalog as tenant-wide and did NO
// per-object Check, so Get(<ungranted-custom-id>) returned the full body
// INCLUDING rules[] (a snapshot of another account's policy). List already hides
// ungranted custom roles; Get leaked them → read!=enforce + existence-leak,
// contradicting the contract ("an object outside all grants → NOT_FOUND on Get;
// absent from List").
//
// Fix (custom roles are tenant-secret, system roles are the catalog floor):
//   - SYSTEM role (is_system=true) → served to every authenticated caller
//     (catalog floor; deterministic seed ids, not tenant-secret) — exempt.
//   - CUSTOM role (is_system=false) → per-object enforce via the SAME FGA
//     ListObjects(subject,"viewer","iam_role") set that drives List (read==enforce,
//     single source of truth). The `viewer` tier cascades from the account
//     tier so a role's creator / account-admin resolves their own roles; id ∉ set
//     → NOT_FOUND "Role <id> not found" (NOT PERMISSION_DENIED — no existence
//     leak). Foreign-account custom → same.
//   - Fail-closed: a nil FGA port or an FGA error on a custom-role Get → Unavailable
//     (never a body leak).
//
// read==enforce invariant: {role : Get(role) success} == {role : role ∈ List}
// for custom roles (system roles → both always succeed). The parity test below
// asserts the two sets coincide for the same subject.

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

// ───────────── tests ─────────────

// system exempt: a system role is served to any authenticated caller even
// with an EMPTY FGA grant-set (catalog floor). rules[] are returned as usual.
func TestGetRole_D1_SystemRole_ServedToAll(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000sys1"] = domain.Role{
		ID:        domain.RoleID("rol0000000000000sys1"),
		Name:      domain.RoleName("editor"),
		IsSystem:  true,
		Rules:     domain.Rules{{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"get"}}},
		CreatedAt: time.Now().UTC(),
	}

	fga := newRoleFGAStub() // empty grant-set
	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)

	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000sys1"))
	require.NoError(t, err, "system role is the catalog floor — served to every authenticated caller")
	require.True(t, got.IsSystem)
	require.Len(t, got.Rules, 1, "system role body (rules[]) returned as usual")
	require.Equal(t, 0, fga.calls, "system role Get must NOT consult FGA (exempt catalog floor)")
}

// granted custom: a custom role the caller has v_list on → served with body.
func TestGetRole_D1_GrantedCustom_Served(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000cst1"] = domain.Role{
		ID:        domain.RoleID("rol0000000000000cst1"),
		Name:      domain.RoleName("net-ops"),
		IsSystem:  false,
		AccountID: domain.AccountID("acc-A"),
		Rules:     domain.Rules{{Module: "vpc", Resources: []string{"address"}, Verbs: []string{"get"}}},
		CreatedAt: time.Now().UTC(),
	}

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol0000000000000cst1"})

	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)
	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000cst1"))
	require.NoError(t, err, "granted custom role is served")
	require.Equal(t, "rol0000000000000cst1", string(got.ID))
	require.Len(t, got.Rules, 1)
	// custom Get enforces via the SAME viewer ∪ v_list union as List
	// (read==enforce) — the owner resolves `viewer` via the account-tier
	// cascade; a v_list-only selector grant resolves `v_list`.
	require.GreaterOrEqual(t, fga.relations["viewer"], 1,
		"custom Get must consult the `viewer` tier relation (account-tier cascade)")
	require.GreaterOrEqual(t, fga.relations["v_list"], 1,
		"custom Get must ALSO consult the `v_list` verb relation (object-only selector grant, union)")
	require.Equal(t, "iam_role", fga.lastObjType)
	require.Equal(t, "user:usr-u1", fga.lastSubject)
}

// ungranted custom: caller has NO v_list grant → NOT_FOUND, and the body
// (rules[]) is NOT leaked. This is the core case of the bug.
func TestGetRole_D1_UngrantedCustom_NotFound_NoLeak(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000cst9"] = domain.Role{
		ID:        domain.RoleID("rol0000000000000cst9"),
		Name:      domain.RoleName("secret-policy"),
		IsSystem:  false,
		AccountID: domain.AccountID("acc-A"),
		Rules:     domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"*"}}},
		CreatedAt: time.Now().UTC(),
	}

	fga := newRoleFGAStub() // no grant for the caller
	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)

	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000cst9"))
	require.Error(t, err, "ungranted custom role must NOT be served")
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.NotFound, st.Code(),
		"ungranted custom → NOT_FOUND (NOT PermissionDenied — no existence leak)")
	require.Contains(t, st.Message(), "rol0000000000000cst9", "NOT_FOUND message references the role id")
	// no-leak: the returned role MUST be the zero value (no rules[] of a foreign policy).
	require.Empty(t, got.Rules, "ungranted custom Get must NOT leak rules[] (policy of another account)")
	require.Empty(t, string(got.ID))
}

// foreign-account custom: a role that exists in another account, ungranted →
// NOT_FOUND (same no-leak path; the principal can't tell it exists).
func TestGetRole_D1_ForeignAccountCustom_NotFound(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000frgn"] = domain.Role{
		ID:        domain.RoleID("rol0000000000000frgn"),
		Name:      domain.RoleName("other-acc-role"),
		IsSystem:  false,
		AccountID: domain.AccountID("acc-B"), // foreign account
		Rules:     domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"delete"}}},
		CreatedAt: time.Now().UTC(),
	}

	fga := newRoleFGAStub() // caller has no grant in acc-B
	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)

	_, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000frgn"))
	st, _ := status.FromError(err)
	require.Equal(t, codes.NotFound, st.Code(),
		"foreign-account custom role ungranted → NOT_FOUND (no existence leak)")
}

// fail-closed: an FGA error on a CUSTOM-role Get → Unavailable, never a body leak.
func TestGetRole_D1_FGAUnavailable_FailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000cst1"] = domain.Role{
		ID: domain.RoleID("rol0000000000000cst1"), IsSystem: false,
		AccountID: domain.AccountID("acc-A"),
		Rules:     domain.Rules{{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"get"}}},
	}
	fga := newRoleFGAStub()
	fga.err = stderrors.New("openfga listObjects: status 503")

	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)
	got, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000cst1"))
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "want grpc status; got %v", err)
	require.Equal(t, codes.Unavailable, st.Code(),
		"FGA outage on custom Get → UNAVAILABLE fail-closed (no body leak)")
	require.Empty(t, got.Rules, "fail-closed must not leak rules[]")
}

// nil FGA port on a CUSTOM-role Get → fail-closed Unavailable.
func TestGetRole_D1_NilFGA_CustomFailClosed(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000cst1"] = domain.Role{
		ID: domain.RoleID("rol0000000000000cst1"), IsSystem: false,
		AccountID: domain.AccountID("acc-A"),
	}
	uc := NewGetRoleUseCase(repo) // NO WithRelationStore
	_, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("rol0000000000000cst1"))
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unavailable, st.Code(), "nil FGA port on custom Get → fail-closed Unavailable")
}

// malformed id → INVALID_ARGUMENT first (before any repo/FGA work). Unchanged
// behaviour, asserted so the fix keeps the first-statement contract.
func TestGetRole_D1_MalformedID_InvalidArgFirst(t *testing.T) {
	repo := newRoleListFakeRepo()
	fga := newRoleFGAStub()
	uc := NewGetRoleUseCase(repo).WithRelationStore(fga)

	_, err := uc.Execute(ctxUser("usr-u1"), domain.RoleID("not-a-role"))
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code(), "malformed id → InvalidArgument first")
	require.Equal(t, 0, fga.calls, "malformed id rejected before any FGA call")
}

// read==enforce parity: for the SAME subject, the set of custom roles
// Get-able == the set returned by List. Drives both off the same FGA grant-set
// and asserts the two surfaces never diverge (single source of truth).
func TestGetRole_D45_ReadEnforceParity_GetSetEqualsListSet(t *testing.T) {
	repo := newRoleListFakeRepo()
	seedSystemRole(repo, "rol0000000000000sys1")
	seedCustomRole(repo, "rol0000000000000cgr1", "acc-A") // granted
	seedCustomRole(repo, "rol0000000000000cgr2", "acc-A") // granted
	seedCustomRole(repo, "rol0000000000000cun3", "acc-A") // ungranted

	fga := newRoleFGAStub()
	fga.set("user:usr-u1", []string{"rol0000000000000cgr1", "rol0000000000000cgr2"})

	listUC := NewListRolesUseCase(repo).WithRelationStore(fga)
	getUC := NewGetRoleUseCase(repo).WithRelationStore(fga)

	// List visibility for the subject.
	rows, _, err := listUC.Execute(ctxUser("usr-u1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)
	inList := map[string]bool{}
	for _, r := range rows {
		inList[string(r.ID)] = true
	}

	// For EVERY role in the repo, Get-success must coincide with List-membership.
	for id := range repo.roles {
		_, gerr := getUC.Execute(ctxUser("usr-u1"), domain.RoleID(id))
		getOK := gerr == nil
		require.Equal(t, inList[id], getOK,
			"read==enforce: Get(%s) success (%v) must equal List-membership (%v)", id, getOK, inList[id])
	}
}
