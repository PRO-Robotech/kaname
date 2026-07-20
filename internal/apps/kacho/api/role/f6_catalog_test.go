// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// f6_catalog_test.go — redesign-2026 F6 (IAM-1-15/16). The canonical system-role
// catalog: RoleService.List leads with the canonical four (viewer→editor→admin→
// owner) ahead of custom roles; each carries displayName/purpose + the honest
// authoredVerbs/effectiveVerbs preview; system roles are immutable (Update →
// FAILED_PRECONDITION). Pre-Phase-0 the canonical four map to the extant
// cluster-scoped roles by name (view/edit/admin/owner); hyphen-ids are B3-gated.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

func sysRole(name string) domain.Role {
	return domain.Role{
		ID:        domain.RoleID("rol0000000000000sys" + name[:1]),
		ClusterID: "cluster_kacho_root", // system tier ⇒ isSystemDerived
		IsSystem:  true,                 // stored flag matches the tier in real data
		Name:      domain.RoleName(name),
		Rules:     domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}}},
	}
}

// IAM-1-15: the dto surfaces catalog metadata + the derived verb preview. A
// canonical system role gets its curated displayName/purpose; a custom role
// defaults displayName to its name and has an empty purpose.
func TestRole_IAM_1_15_DtoCatalogFields(t *testing.T) {
	t.Run("canonical editor derives delete* + Editor label", func(t *testing.T) {
		r := domain.Role{
			ID: "rol0000000000000edit", ClusterID: "cluster_kacho_root", Name: "edit",
			Rules: domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list", "create", "update"}}},
		}
		pb, err := roleToPb(r)
		require.NoError(t, err)
		assert.Equal(t, "Editor", pb.GetDisplayName())
		assert.NotEmpty(t, pb.GetPurpose())
		assert.Equal(t, []string{"get", "list", "create", "update"}, pb.GetAuthoredVerbs())
		assert.Equal(t, []string{"get", "list", "create", "update", "delete*"}, pb.GetEffectiveVerbs())
		assert.Equal(t, domain.EditorDeleteNote, pb.GetVerbNotes()["delete*"])
		assert.True(t, pb.GetIsSystem())
	})
	t.Run("custom role: displayName=name, empty purpose", func(t *testing.T) {
		r := domain.Role{ID: "rol-c", AccountID: "acc-A", Name: "app-deployer", Rules: f4Rules()}
		pb, err := roleToPb(r)
		require.NoError(t, err)
		assert.Equal(t, "app-deployer", pb.GetDisplayName())
		assert.Empty(t, pb.GetPurpose())
	})
}

// IAM-1-15: RoleService.List presents system roles first, and among them the
// canonical four in viewer→editor→admin→owner order, ahead of custom roles.
func TestRole_IAM_1_15_ListCanonicalFirst(t *testing.T) {
	repo := newRoleListFakeRepo()
	for _, n := range []string{"admin", "owner", "view", "edit"} { // insertion order scrambled
		r := sysRole(n)
		repo.roles[string(r.ID)] = r
	}
	// a non-canonical system role + a custom role
	repo.roles["rol0000000000000other"] = domain.Role{ID: "rol0000000000000other", ClusterID: "cluster_kacho_root", IsSystem: true, Name: "iam.user.view", Rules: f4Rules()}
	repo.roles["rol00000000000000cust"] = domain.Role{ID: "rol00000000000000cust", AccountID: "acc-A", Name: "custom-role", Rules: f4Rules()}

	fga := newRoleFGAStub()
	fga.set("user:usr-1", []string{"rol00000000000000cust"}) // custom visible to caller

	uc := NewListRolesUseCase(repo).WithRelationStore(fga)
	out, _, err := uc.Execute(ctxUser("usr-1"), reporole.ListFilter{PageSize: 100})
	require.NoError(t, err)

	names := make([]string, 0, len(out))
	for _, r := range out {
		names = append(names, string(r.Name))
	}
	// canonical four first, in rank order; custom role last.
	require.GreaterOrEqual(t, len(names), 5)
	assert.Equal(t, []string{"view", "edit", "admin", "owner"}, names[:4], "canonical four lead in viewer→editor→admin→owner order")
	assert.Equal(t, "custom-role", names[len(names)-1], "custom role sorts after all system roles")
}

// IAM-1-16: an Update on a system (cluster-tier) role → FAILED_PRECONDITION.
func TestRole_IAM_1_16_SystemRoleUpdateImmutable(t *testing.T) {
	repo := newRoleListFakeRepo()
	repo.roles["rol0000000000000sys1"] = domain.Role{
		ID: "rol0000000000000sys1", ClusterID: "cluster_kacho_root", Name: "admin", IsSystem: true,
	}
	uc := NewUpdateRoleUseCase(repo, newRlFakeOps())

	newName := domain.RoleName("hacked")
	_, err := uc.Execute(ctxUser("usr-1"), UpdateRoleInput{
		ID:         "rol0000000000000sys1",
		Name:       &newName,
		UpdateMask: []string{"name"},
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code(), "system role Update → FAILED_PRECONDITION (immutable)")
}
