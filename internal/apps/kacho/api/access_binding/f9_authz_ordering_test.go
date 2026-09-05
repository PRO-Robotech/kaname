// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// f9_authz_ordering_test.go — AccessBinding.Create must be AUTHZ-FIRST.
//
// The RPC is `permission = "<exempt>"` in proto: the api-gateway runs NO per-RPC
// Check for it, and the kacho-iam handler is the authoritative gate. So every
// statement that READS another tenant's object (the F9 structural gates read the
// role, and the hierarchy-down resolution reads the scope project) must run AFTER
// requireGrantAuthority — otherwise ANY authenticated principal can probe foreign
// role / project ids and tell them apart by the distinguishable reject:
//
//	role absent      → FAILED_PRECONDITION "Role <id> not found"
//	role present     → FAILED_PRECONDITION "role <id> (definitionTier iam.account) is not assignable …"
//	both fine        → PERMISSION_DENIED
//
// which is a cross-tenant existence + metadata oracle (security.md hardening
// invariant 6: a distinguishable text IS the oracle).
//
// Residual, for a caller who DOES hold grant-authority on their own scope: the
// actionable IsRoleAssignable text still discloses the existence + tier of a role
// belonging to a FOREIGN account, contradicting RoleService.Get's hide-existence
// contract (role/get.go: an unreadable custom role → "Role <id> not found"). A role
// outside the scope's account tree is structurally never assignable there, so it
// collapses to the same not-found text.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// accountScopeBinding builds an account-scoped, allInScope grant of roleID on acc.
func accountScopeBinding(roleID, acc, subject string) domain.AccessBinding {
	return domain.AccessBinding{
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   acc,
		Scope:        domain.ScopeAccount,
		Target:       domain.AccessTarget{AllInScope: true},
		Subjects:     []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(subject)}},
	}
}

// newCustomRoleRepo builds a fake whose Roles().Get serves ONE custom (non-system)
// account-tier role owned by `homeAccount`; any other role id is a canonical
// not-found.
func newCustomRoleRepo(ownerUserID, homeAccount, roleID string) *abFakeRepo {
	repo := newABFakeRepo(ownerUserID, homeAccount, "", roleID, "custom_role",
		domain.Permissions{"iam.users.get"})
	repo.roleIsCustom = true
	return repo
}

// TestCreate_AuthzBeforeStructuralGates_NoRoleOracle — an UNAUTHORIZED caller must
// get the SAME byte-identical PERMISSION_DENIED whether the probed role exists or
// not, and whether it is assignable on the probed scope or not.
func TestCreate_AuthzBeforeStructuralGates_NoRoleOracle(t *testing.T) {
	const ownerID, homeAcct, roleID = "usr_owner", "acc_home", "rol_home_custom"
	// Grants nothing: neither the cluster super-relation nor scope admin. The
	// account owner is usr_owner, the caller is a stranger → no grant authority.
	deny := func() clients.RelationStore { return &scopedFGA{allow: map[string]bool{}} }

	cases := []struct {
		name   string
		roleID string
	}{
		{"foreign role that EXISTS (and is not assignable here)", roleID},
		{"role that does NOT exist", "rol_ghost_00000000000"},
	}
	msgs := make([]string, 0, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newCustomRoleRepo(ownerID, homeAcct, roleID)
			opsRepo := newFakeOpsRepo()
			uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(deny(), nil)

			// Probing a FOREIGN scope (acc_other) with a foreign / absent role id.
			_, err := uc.Execute(newOwnerContext("usr_stranger"),
				accountScopeBinding(tc.roleID, "acc_other", "usr_target"))
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.PermissionDenied, st.Code(),
				"an unauthorized caller must be denied BEFORE any foreign object is read")
			assert.NotContains(t, st.Message(), "definitionTier",
				"the role's tier must never leak to an unauthorized caller")
			assert.NotContains(t, st.Message(), "not found",
				"role existence must never leak to an unauthorized caller")
			require.Empty(t, opsRepo.ops, "no Operation on a sync reject")
			msgs = append(msgs, st.Message())
		})
	}
	require.Len(t, msgs, 2)
	assert.Equal(t, msgs[0], msgs[1],
		"present-vs-absent role must be byte-identical for an unauthorized caller")
}

// TestCreate_ForeignRoleHiddenFromAuthorizedCaller — the residual oracle: a caller
// WITH grant-authority on their own scope must not be able to tell a foreign
// account's role apart from a non-existent one (parity with RoleService.Get's
// hide-existence contract).
func TestCreate_ForeignRoleHiddenFromAuthorizedCaller(t *testing.T) {
	const ownerID, homeAcct, roleID = "usr_owner", "acc_home", "rol_home_custom"

	// The fake account reader reports ownerID as the owner of ANY account, so the
	// caller holds grant-authority on the probed scope (Path 1).
	newUC := func(repo *abFakeRepo) *CreateAccessBindingUseCase {
		return NewCreateAccessBindingUseCase(repo, newFakeOpsRepo()).
			WithRelationStore(&scopedFGA{allow: map[string]bool{}}, nil)
	}

	t.Run("existing role of a FOREIGN account → not-found, no tier disclosure", func(t *testing.T) {
		repo := newCustomRoleRepo(ownerID, homeAcct, roleID)
		// Scope belongs to a DIFFERENT account than the role's home account.
		_, err := newUC(repo).Execute(newOwnerContext(ownerID),
			accountScopeBinding(roleID, "acc_other", "usr_target"))
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "Role "+roleID+" not found", st.Message(),
			"a role outside the scope's account tree is indistinguishable from an absent one")
		assert.NotContains(t, st.Message(), "definitionTier")
	})

	t.Run("absent role → the same text", func(t *testing.T) {
		repo := newCustomRoleRepo(ownerID, homeAcct, roleID)
		_, err := newUC(repo).Execute(newOwnerContext(ownerID),
			accountScopeBinding("rol_ghost_00000000000", "acc_other", "usr_target"))
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Equal(t, "Role rol_ghost_00000000000 not found", st.Message())
	})

	t.Run("own-account role stays assignable (no over-tightening)", func(t *testing.T) {
		repo := newCustomRoleRepo(ownerID, homeAcct, roleID)
		op, err := newUC(repo).Execute(newOwnerContext(ownerID),
			accountScopeBinding(roleID, homeAcct, "usr_target"))
		require.NoError(t, err, "the role's own account scope must still pass the gates")
		require.NotNil(t, op)
	})
}
