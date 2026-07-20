// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_list_unified_integration_test.go — redesign-2026 F11 (IAM-1-32) DB
// side. The unified repo List honours the optional predicate fields (subject/role/
// scope-type/scope-id) + the VisibleIDs push-down, keyset-paginated by (created_at,
// id). Mirrors the well-tested ListByScope/listWithConds pattern.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestAB_IAM_1_32_UnifiedListRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "abul32")
	other := mustSeedUser(t, ctx, pool, "abul32b")
	acc := seedAccount(t, ctx, repo, "acc-abul32", owner)

	bOwner := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc.ID),
	})
	bOther := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(other),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// (1) subject= predicate → only that subject's binding.
	rows, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, SubjectID: string(other)})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, bOther.ID, rows[0].ID)

	// (2) role= predicate → only bindings carrying that role.
	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, RoleID: seedSystemRoleIDIAMAdmin})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, bOwner.ID, rows[0].ID)

	// (3) scope-type + scope-id predicates → both bindings on this account anchor.
	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, ScopeType: "account", ScopeID: string(acc.ID)})
	require.NoError(t, err)
	assert.Len(t, rows, 2)

	// (4) VisibleIDs push-down → only the listed id; empty slice → nothing.
	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, VisibleIDs: []string{string(bOther.ID)}})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, bOther.ID, rows[0].ID)

	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, VisibleIDs: []string{}})
	require.NoError(t, err)
	assert.Empty(t, rows, "empty VisibleIDs lists nothing")

	// (5) keyset pagination: page_size 1 → one row + a next token, then resume.
	page1, next, err := rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 1, ScopeType: "account", ScopeID: string(acc.ID)})
	require.NoError(t, err)
	require.Len(t, page1, 1)
	require.NotEmpty(t, next, "a second page must be signalled")
	page2, _, err := rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 1, ScopeType: "account", ScopeID: string(acc.ID), PageToken: next})
	require.NoError(t, err)
	require.Len(t, page2, 1)
	assert.NotEqual(t, page1[0].ID, page2[0].ID, "keyset advances to a distinct row")

	// (6) garbage page_token → InvalidArgument (repo backstop).
	_, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 10, PageToken: "%%%bad%%%"})
	require.Error(t, err)
}
