// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_group_derivation_integration_test.go — ListSubjectPrivileges must
// resolve GROUP-derived access, not only DIRECT grants.
//
// The reported failure, end-to-end: an administrator adds a user to a group,
// grants the GROUP a role, then asks "what can this user do" and gets an EMPTY
// list — while enforcement (which resolves the group userset in FGA) happily lets
// the user in. The report contradicts reality; an off-boarding or access review
// driven by it silently misses the access.
//
// Coverage:
//   GD-1  a binding held via group membership IS returned, marked GROUP + the
//         carrying group id.
//   GD-2  a direct binding is still returned and still marked DIRECT (no
//         regression, no double-count when the user holds both).
//   GD-3  a NON-member of the group does NOT inherit the group's binding
//         (the join must not widen access).
//   GD-4  a REVOKED group binding stays excluded (status filter still applies on
//         the derived path).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

func TestAB_GD_GroupDerivedPrivilegesResolved(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "gd0o")
	acc := seedAccount(t, ctx, repo, "acc-gd0", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "gd0m")
	outsider := seedUserInAccount(t, ctx, pool, acc.ID, "gd0x")
	proj := seedProject(t, ctx, repo, acc.ID, "proj-gd0")

	grp := seedGroup(t, ctx, repo, acc.ID, "gd0-team")
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID: grp.ID, MemberType: "user", MemberID: domain.SubjectID(member),
	}))
	require.NoError(t, w.Commit(ctx))

	roleViaGroup := seedCustomRole(t, ctx, repo, acc.ID, "gd0_viagroup")
	roleDirect := seedCustomRole(t, ctx, repo, acc.ID, "gd0_direct")
	roleRevoked := seedCustomRole(t, ctx, repo, acc.ID, "gd0_revoked")

	// The grant that the administrator actually made: role → GROUP.
	groupBinding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(grp.ID),
		RoleID: roleViaGroup.ID, ResourceType: "project", ResourceID: string(proj.ID),
		GrantedByUserID: owner,
	})
	// A plain direct grant to the same user — must keep working, marked DIRECT.
	directBinding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleDirect.ID, ResourceType: "account", ResourceID: string(acc.ID),
		GrantedByUserID: owner,
	})
	// A REVOKED grant to the group — the derived path must not resurrect it.
	revokedBinding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(grp.ID),
		RoleID: roleRevoked.ID, ResourceType: "project", ResourceID: string(proj.ID),
		GrantedByUserID: owner,
	})
	_, err = pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings
		    SET status='REVOKED', revoked_at=now(), revoked_by_user_id=$2
		  WHERE id=$1`,
		string(revokedBinding.ID), string(owner))
	require.NoError(t, err, "revoke the group binding")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	rows, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{PageSize: 50})
	require.NoError(t, err)

	byID := map[domain.AccessBindingID]domain.SubjectPrivilege{}
	for _, r := range rows {
		byID[r.BindingID] = r
	}

	// GD-1 — the group-derived privilege is visible and attributed.
	viaGroup, ok := byID[groupBinding.ID]
	require.True(t, ok,
		"GD-1: the privilege the user holds THROUGH the group must be reported (it was invisible before)")
	assert.Equal(t, domain.DerivationGroup, viaGroup.Derivation,
		"GD-1: derivation must say GROUP, not DIRECT")
	assert.Equal(t, grp.ID, viaGroup.ViaGroupID,
		"GD-1: the carrying group must be named so a revoke is actionable")

	// GD-2 — direct grants unchanged.
	direct, ok := byID[directBinding.ID]
	require.True(t, ok, "GD-2: the direct grant must still be returned")
	assert.Equal(t, domain.DerivationDirect, direct.Derivation)
	assert.Empty(t, direct.ViaGroupID)

	// GD-4 — a revoked group binding is still excluded.
	_, revokedPresent := byID[revokedBinding.ID]
	assert.False(t, revokedPresent,
		"GD-4: the status filter must still apply on the group-derived path")

	// Exactly the two live privileges, no duplicates.
	assert.Len(t, rows, 2, "one row per binding — the group join must not duplicate rows")

	// GD-3 — a non-member inherits nothing.
	outRows, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(outsider), repoab.PageFilter{PageSize: 50})
	require.NoError(t, err)
	assert.Empty(t, outRows,
		"GD-3: a user who is NOT in the group must not inherit the group's binding")
}
