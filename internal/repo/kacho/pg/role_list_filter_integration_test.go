// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_list_filter_integration_test.go — SQL-side behaviour of the scope-filtered
// RoleService.List read path.
//
//   - ListFilter.AccountID scopes the catalog to system + that Account's
//     custom roles; a foreign Account's custom role never appears (SQL WHERE,
//     not software post-filter).
//   - ListFilter.PageSize > 1000 → InvalidArgument (no silent clamp).
//   - keyset (created_at,id) pagination is dense over the account-scoped
//     catalog — no duplicate and no skipped row across pages.
//
// There is deliberately NO visible-id push-down in ListFilter: read visibility
// is resolved PER-OBJECT by the use-case over the page this returns
// (internal/authzfilter). Собрать такой набор идентификаторов ЗАРАНЕЕ можно было
// только перечислением объектов, а оно снято с контракта (решение Р1) именно
// потому, что не имело продолжения: ответ обрезался серверным пределом, и сверх
// него ресурсы арендатора становились невидимы НАВСЕГДА при живых правах.
// Порядок «страница → проверка страницы» этого класса не имеет by construction.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	reporole "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/role"
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

// TestRole_List_D46_KeysetPaginationDense — a keyset walk covers the
// account-scoped catalog EXACTLY once: no duplicate across pages and no row
// skipped. This is what makes the use-case's per-object visibility filter safe
// to apply on top (a filtered page may come back short, but the WALK is still
// complete).
func TestRole_List_D46_KeysetPaginationDense(t *testing.T) {
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

	// 5 custom roles in the account — every one of them must be walked exactly once.
	custom := []domain.RoleID{}
	for i := 0; i < 5; i++ {
		r := seedCustomRole(t, ctx, repo, acc.ID, "rld46_c"+string(rune('a'+i)))
		custom = append(custom, r.ID)
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Full set for the account scope: system roles + this account's 5 custom.
	full, _, err := rd.Roles().List(ctx, reporole.ListFilter{
		PageSize:  1000,
		AccountID: acc.ID,
	})
	require.NoError(t, err)
	fullByID := roleIDs(full)
	for _, id := range custom {
		assert.Contains(t, fullByID, id, "account-scoped custom role present in the full set")
	}

	// Keyset walk page_size=1: dense coverage of exactly the filtered set, no dups.
	seen := map[domain.RoleID]bool{}
	token := ""
	pages := 0
	for {
		page, next, perr := rd.Roles().List(ctx, reporole.ListFilter{
			PageSize:  1,
			AccountID: acc.ID,
			PageToken: token,
		})
		require.NoError(t, perr)
		require.LessOrEqual(t, len(page), 1, "page_size=1 yields ≤1 element")
		for _, r := range page {
			require.False(t, seen[r.ID], "no duplicate across pages: %s", r.ID)
			require.True(t, fullByID[r.ID].ID != "" || r.IsSystem,
				"page only contains account-scoped members: %s", r.ID)
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
		"paged walk covers the account-scoped catalog exactly once (dense) — no skipped row")
	for _, id := range custom {
		assert.True(t, seen[id], "every account-scoped custom role is reachable by the keyset walk: %s", id)
	}
}
