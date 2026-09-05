// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
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

	// (4) subject predicate → only that subject's binding. (There is deliberately
	// no visible-id push-down: read visibility is resolved per-object by the
	// use-case over the returned page — see internal/authzfilter.)
	rows, _, err = rd.AccessBindings().List(ctx, repoab.ListFilter{PageSize: 100, SubjectID: string(bOther.SubjectID)})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, bOther.ID, rows[0].ID)

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

// TestAB_IAM_1_32_UnifiedList_HidesRevoked — F11 × F10 parity. The soft-revoke
// (RevokeGuarded) RETAINS the row with status='REVOKED'; the unified List must hide
// it by default exactly like ListByAccount/ListByRole do, and surface it only under
// the explicit IncludeRevoked audit-retention read. Without the status predicate a
// revoked grant is returned next to live ones — and after an identical re-grant (the
// partial UNIQUE frees the slot on revoked_at) the SAME grant appears TWICE.
func TestAB_IAM_1_32_UnifiedList_HidesRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "abulrv")
	member := mustSeedUser(t, ctx, pool, "abulrvm")
	acc := seedAccount(t, ctx, repo, "acc-abulrv", owner)

	live := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc.ID),
	})
	gone := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
	})

	// Soft-revoke `gone` (row retained, status→REVOKED, revoked_at stamped).
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoked, err := w.AccessBindingsW().RevokeGuarded(ctx, gone.ID, domain.UserID(owner))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status)

	scope := repoab.ListFilter{PageSize: 100, ScopeType: "account", ScopeID: string(acc.ID)}

	// (1) default read hides the revoked row.
	rows := listAB(t, ctx, repo, scope)
	require.Len(t, rows, 1, "the soft-revoked binding must NOT be listed by default")
	assert.Equal(t, live.ID, rows[0].ID)

	// (2) explicit audit-retention read surfaces it, flagged REVOKED.
	inclFilter := scope
	inclFilter.IncludeRevoked = true
	rows = listAB(t, ctx, repo, inclFilter)
	require.Len(t, rows, 2, "IncludeRevoked surfaces the retained row")
	var sawRevoked bool
	for _, r := range rows {
		if r.ID == gone.ID {
			sawRevoked = true
			assert.Equal(t, domain.AccessBindingStatusRevoked, r.Status)
		}
	}
	assert.True(t, sawRevoked, "the retained row is returned under IncludeRevoked")

	// (3) re-grant of the IDENTICAL 5-tuple (the partial UNIQUE freed the slot on
	// revoked_at) → the default read must still show exactly ONE row for it.
	regrant := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
	})
	rows = listAB(t, ctx, repo, repoab.ListFilter{PageSize: 100, SubjectID: string(member)})
	require.Len(t, rows, 1, "a re-granted 5-tuple must not be duplicated by its revoked predecessor")
	assert.Equal(t, regrant.ID, rows[0].ID)
}

// listAB runs one List on a FRESH short-lived Reader (each assertion needs a
// snapshot that sees the previously committed writer-tx) and releases its pooled
// connection immediately — a Reader parked until t.Cleanup would outlive the
// test's `defer pool.Close()` and deadlock puddle's drain.
func listAB(t *testing.T, ctx context.Context, repo *kachopg.Repository, f repoab.ListFilter) []domain.AccessBinding {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err := rd.AccessBindings().List(ctx, f)
	require.NoError(t, err)
	return rows
}
