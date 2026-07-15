// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_list_by_account_integration_test.go — integration tests for
// `Reader.ListByAccount` (KAC: admin sees all access_bindings inside their
// account, not only their own).
//
// Coverage:
//   - LBA-01: bindings directly on the account + bindings on every project of
//     the account are both returned (single query, ordered by created_at).
//   - LBA-02: filter by subject_type (only `user` / only `service_account`).
//   - LBA-03: include_revoked=false hides REVOKED rows; include_revoked=true
//     returns them too.
//   - LBA-04: keyset pagination — page_size=N returns next_page_token; second
//     page continues at the same cursor; total rows match no-pagination call.
//   - LBA-05: empty account (no bindings, no projects) → empty list, no token.
//   - LBA-06: account isolation — bindings on a different account are NOT
//     returned (account_id scope predicate works for both directly attached
//     and project-attached rows).
//
// The repo method is purely SQL; authorization (admin-only) lives in the
// use-case layer (see list_by_account_test.go).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestAB_LBA01_DirectAndProjectScopedBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lba01o")
	other := mustSeedUser(t, ctx, pool, "lba01x")
	acc := seedAccount(t, ctx, repo, "acc-lba01", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-lba01")

	// owner → admin on account
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(owner),
		RoleID:       seedSystemRoleIDIAMAdmin,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	// other → viewer on account (direct)
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(other),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	// other → viewer on project (project-attached)
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(other),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "project",
		ResourceID:   string(proj.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	rows, next, err := rd.AccessBindings().ListByAccount(ctx, acc.ID, repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 3, len(rows), "expected direct (2) + project-scoped (1) bindings")
	assert.Empty(t, next, "no next page expected")
}

func TestAB_LBA02_FilterBySubjectType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lba02o")
	acc := seedAccount(t, ctx, repo, "acc-lba02", owner)
	saID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))

	// Insert SA row into kacho_iam.service_accounts table so the soft-ref
	// matches reality (subject_id has no FK; the test seeds it for clarity).
	_, err = pool.Exec(ctx, `INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, created_at)
		VALUES ($1, $2, 'sa-lba02', '', now())`, string(saID), string(acc.ID))
	require.NoError(t, err)

	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc.ID),
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeServiceAccount, SubjectID: domain.SubjectID(saID),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	users, _, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 100, SubjectTypeFilter: "user"})
	require.NoError(t, err)
	assert.Equal(t, 1, len(users))
	assert.Equal(t, domain.SubjectTypeUser, users[0].SubjectType)

	sas, _, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 100, SubjectTypeFilter: "service_account"})
	require.NoError(t, err)
	assert.Equal(t, 1, len(sas))
	assert.Equal(t, domain.SubjectTypeServiceAccount, sas[0].SubjectType)
}

func TestAB_LBA03_IncludeRevokedFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lba03o")
	acc := seedAccount(t, ctx, repo, "acc-lba03", owner)

	active := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc.ID),
	})
	_ = active

	// Insert a REVOKED binding directly (cannot use the partial-UNIQUE active
	// path twice for the same 5-tuple).
	other := mustSeedUser(t, ctx, pool, "lba03x")
	_, err = pool.Exec(ctx, `INSERT INTO kacho_iam.access_bindings
		(id, subject_type, subject_id, role_id, resource_type, resource_id, status,
		 granted_by_user_id, revoked_at, revoked_by_user_id, created_at)
		VALUES ($1, 'user', $2, $3, 'account', $4, 'REVOKED', '', now(), $5, now())`,
		ids.NewID(domain.PrefixAccessBinding), string(other),
		seedSystemRoleIDIAMView, string(acc.ID), string(owner))
	require.NoError(t, err)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// default — hide revoked.
	rows, _, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 1, len(rows))
	assert.Equal(t, domain.AccessBindingStatusActive, rows[0].Status)

	// include_revoked=true → 2 rows.
	all, _, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 100, IncludeRevoked: true})
	require.NoError(t, err)
	assert.Equal(t, 2, len(all))
}

func TestAB_LBA04_KeysetPagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lba04o")
	acc := seedAccount(t, ctx, repo, "acc-lba04", owner)

	// Seed 5 bindings with 5 different users.
	for i := 0; i < 5; i++ {
		uid := mustSeedUser(t, ctx, pool, "lba04u"+string(rune('a'+i)))
		_ = insertAB(t, ctx, repo, domain.AccessBinding{
			SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
			RoleID: seedSystemRoleIDIAMView, ResourceType: "account", ResourceID: string(acc.ID),
		})
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// page_size=2 — first page returns 2 rows + token.
	page1, token, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, 2, len(page1))
	assert.NotEmpty(t, token, "next_page_token expected when more rows exist")

	// page 2.
	page2, token2, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 2, PageToken: token})
	require.NoError(t, err)
	assert.Equal(t, 2, len(page2))
	assert.NotEmpty(t, token2)

	// page 3 — last row, no further token.
	page3, token3, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 2, PageToken: token2})
	require.NoError(t, err)
	assert.Equal(t, 1, len(page3))
	assert.Empty(t, token3, "last page must not return a token")

	// IDs must be unique across pages.
	seen := map[domain.AccessBindingID]bool{}
	for _, b := range append(append(page1, page2...), page3...) {
		assert.False(t, seen[b.ID], "duplicate id %s across pages", b.ID)
		seen[b.ID] = true
	}
	assert.Equal(t, 5, len(seen))
}

func TestAB_LBA05_EmptyAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lba05o")
	acc := seedAccount(t, ctx, repo, "acc-lba05", owner)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	rows, next, err := rd.AccessBindings().ListByAccount(ctx, acc.ID,
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Empty(t, rows)
	assert.Empty(t, next)
}

func TestAB_LBA06_AccountIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner1 := mustSeedUser(t, ctx, pool, "lba06a")
	owner2 := mustSeedUser(t, ctx, pool, "lba06b")
	acc1 := seedAccount(t, ctx, repo, "acc-lba06a", owner1)
	acc2 := seedAccount(t, ctx, repo, "acc-lba06b", owner2)
	proj2 := seedProject(t, ctx, repo, acc2.ID, "proj-lba06b")

	// Binding in acc1.
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner1),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc1.ID),
	})
	// Binding in acc2 (direct + project).
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner2),
		RoleID: seedSystemRoleIDIAMAdmin, ResourceType: "account", ResourceID: string(acc2.ID),
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(owner2),
		RoleID: seedSystemRoleIDIAMView, ResourceType: "project", ResourceID: string(proj2.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// acc1 → 1 binding only (no leakage from acc2).
	rows1, _, err := rd.AccessBindings().ListByAccount(ctx, acc1.ID,
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 1, len(rows1))
	assert.Equal(t, string(acc1.ID), rows1[0].ResourceID)

	// acc2 → 2 bindings (direct + project).
	rows2, _, err := rd.AccessBindings().ListByAccount(ctx, acc2.ID,
		repoab.AccountPageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 2, len(rows2))
}
