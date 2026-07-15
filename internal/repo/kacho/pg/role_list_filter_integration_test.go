// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// role_list_filter_integration_test.go — SQL-side behaviour of the scope-filtered
// RoleService.List read path.
//
//   - ListFilter.AccountID scopes the catalog to system + that Account's
//     custom roles; a foreign Account's custom role never appears (SQL WHERE,
//     not software post-filter).
//   - ListFilter.PageSize > 1000 → InvalidArgument (no silent clamp).
//   - ListFilter.VisibleIDs (FGA `viewer` id-set push-down) intersects at the
//     SQL layer so keyset (created_at,id) pagination stays correct over the
//     FILTERED set — no leaky/short pages. System roles bypass VisibleIDs (catalog
//     floor) so the per-object filter only constrains custom roles.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

// TestRole_List_185_AccountScope — accountId scope: system + own-account custom
// only; a foreign account's custom role is absent.
func TestRole_List_185_AccountScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "rl185a")
	accA := seedAccount(t, ctx, repo, "acc-rl185-a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "rl185b")
	accB := seedAccount(t, ctx, repo, "acc-rl185-b", ownerB)

	cA := seedCustomRole(t, ctx, repo, accA.ID, "rl185_a")
	cB := seedCustomRole(t, ctx, repo, accB.ID, "rl185_b")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.Roles().List(ctx, reporole.ListFilter{
		PageSize:  1000,
		AccountID: accA.ID,
	})
	require.NoError(t, err)
	byID := roleIDs(out)
	assert.Contains(t, byID, cA.ID, "own-account custom role visible")
	assert.NotContains(t, byID, cB.ID, "foreign-account custom role NEVER visible")
	sawSystem := false
	for _, r := range out {
		if r.IsSystem {
			sawSystem = true
		}
	}
	assert.True(t, sawSystem, "system roles always in scope (catalog floor)")
}

// TestRole_List_184_PageSizeRejectOverMax — page_size > 1000 → InvalidArgument
// at the repo List boundary (no silent clamp).
func TestRole_List_184_PageSizeRejectOverMax(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	_, _, err = rd.Roles().List(ctx, reporole.ListFilter{PageSize: 1001})
	require.Error(t, err, "page_size>1000 must error (no silent clamp)")
	// Repo-level contract: the iam sentinel ErrInvalidArg (the use-case/handler
	// maps it to gRPC INVALID_ARGUMENT via MapRepoErr; verified at unit level).
	require.ErrorIs(t, err, iamerr.ErrInvalidArg, "page_size>1000 → ErrInvalidArg sentinel")
	assert.Equal(t, codes.InvalidArgument, status.Code(shared.MapRepoErr(err)),
		"MapRepoErr surfaces INVALID_ARGUMENT to the gRPC boundary")
}

// TestRole_List_D46_VisibleIDsPaginationDense — with a VisibleIDs id-set
// (the FGA v_list push-down), keyset pagination is dense over the FILTERED set
// (system roles ∪ the granted custom ids), with no short/leaky pages.
func TestRole_List_D46_VisibleIDsPaginationDense(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rld46")
	acc := seedAccount(t, ctx, repo, "acc-rld46", owner)

	// 5 custom roles; only 3 are "visible" (granted). The other 2 must NEVER
	// appear nor cause short pages.
	cVisible := []domain.RoleID{}
	cHidden := []domain.RoleID{}
	for i := 0; i < 3; i++ {
		r := seedCustomRole(t, ctx, repo, acc.ID, "rld46_vis"+string(rune('a'+i)))
		cVisible = append(cVisible, r.ID)
	}
	for i := 0; i < 2; i++ {
		r := seedCustomRole(t, ctx, repo, acc.ID, "rld46_hid"+string(rune('a'+i)))
		cHidden = append(cHidden, r.ID)
	}

	visibleIDs := make([]string, 0, len(cVisible))
	for _, id := range cVisible {
		visibleIDs = append(visibleIDs, string(id))
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Full set with the visible filter: system roles + 3 visible custom.
	full, _, err := rd.Roles().List(ctx, reporole.ListFilter{
		PageSize:   1000,
		AccountID:  acc.ID,
		VisibleIDs: visibleIDs,
	})
	require.NoError(t, err)
	fullByID := roleIDs(full)
	for _, id := range cVisible {
		assert.Contains(t, fullByID, id, "granted custom role visible")
	}
	for _, id := range cHidden {
		assert.NotContains(t, fullByID, id, "ungranted custom role absent (no leak)")
	}

	// Keyset walk page_size=1: dense coverage of exactly the filtered set, no dups.
	seen := map[domain.RoleID]bool{}
	token := ""
	pages := 0
	for {
		page, next, perr := rd.Roles().List(ctx, reporole.ListFilter{
			PageSize:   1,
			AccountID:  acc.ID,
			VisibleIDs: visibleIDs,
			PageToken:  token,
		})
		require.NoError(t, perr)
		require.LessOrEqual(t, len(page), 1, "page_size=1 yields ≤1 element")
		for _, r := range page {
			require.False(t, seen[r.ID], "no duplicate across pages: %s", r.ID)
			require.True(t, fullByID[r.ID].ID != "" || r.IsSystem,
				"page only contains filtered-set members: %s", r.ID)
			seen[r.ID] = true
		}
		pages++
		if next == "" {
			break
		}
		token = next
		require.LessOrEqual(t, pages, len(full)+2, "must terminate")
	}
	assert.Equal(t, len(full), len(seen),
		"paged walk covers exactly the filtered set (dense) — no leaky/short pages")
	// no hidden custom role ever surfaced through pagination
	for _, id := range cHidden {
		assert.False(t, seen[id], "hidden custom role never paginated in (no leak)")
	}
}
