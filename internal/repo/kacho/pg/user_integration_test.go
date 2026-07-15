// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// user_integration_test.go — integration tests UserRepo.
//
// Покрытие:
// - 15a: Upsert NEW (created=true).
// - 15b: Upsert EXISTING external_id → UPDATE email/display_name, created=false.
// - 16: GetByExternalID happy + NotFound.
// - 16b: GetByEmail happy + NotFound (case-insensitive).
// - 41a: Delete без refs → OK.
// - 41b: Delete с GroupMember → FailedPrecondition.
// - 41c: Delete с AccessBinding → FailedPrecondition.
// - 41d: Delete несущ. → NotFound.
// - 41e: Delete owner-of-Account → FailedPrecondition (FK accounts_owner_fk).

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// upsertUser-compatible helper: создает **дополнительного** user-row
// в **отдельном** Account, владельцем которого является SEPARATE admin-user.
// Это нужно, чтобы возвращаемый user НЕ был owner Account'а (иначе любая
// попытка Delete упирается в FK accounts.owner_user_id RESTRICT).
//
// Поток (одна TX с DEFERRABLE FK):
// 1. INSERT admin-user (owner of throwaway Account).
// 2. INSERT throwaway Account (owner_user_id = admin).
// 3. INSERT target user в тот же Account (но НЕ owner).
// 4. COMMIT — все FK консистентны.
func upsertUser(t *testing.T, ctx context.Context, repo *kachopg.Repository, externalID, email, name string) (domain.User, bool) {
	t.Helper()
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	adminID := domain.UserID(ids.NewID(domain.PrefixUser))
	targetID := domain.UserID(ids.NewID(domain.PrefixUser))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()

	// Admin first (will own the throwaway Account).
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           adminID,
		AccountID:    accID,
		ExternalID:   domain.ExternalSubject(fmt.Sprintf("admin-of-%s", externalID)),
		Email:        domain.Email(fmt.Sprintf("admin-of-%s", email)),
		DisplayName:  domain.DisplayName("Throwaway Admin"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "InsertActive admin")

	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          accID,
		Name:        domain.AccountName(fmt.Sprintf("acc-%s", strings.ToLower(string(accID[len(accID)-6:])))),
		OwnerUserID: adminID,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err, "Insert account")

	target, err := w.UsersW().InsertActive(ctx, domain.User{
		ID:           targetID,
		AccountID:    accID,
		ExternalID:   domain.ExternalSubject(externalID),
		Email:        domain.Email(email),
		DisplayName:  domain.DisplayName(name),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "InsertActive target")

	require.NoError(t, w.Commit(ctx))
	committed = true
	return target, true
}

// ── 15a: Upsert NEW (created=true) ──────────────────────────────────────────
func TestUser_15a_Upsert_New(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	u, created := upsertUser(t, ctx, repo, "zit-new-15a", "new15a@example.com", "New User 15a")
	assert.True(t, created, "first Upsert → created=true")
	assert.True(t, strings.HasPrefix(string(u.ID), "usr"))
	assert.Equal(t, domain.Email("new15a@example.com"), u.Email)
	assert.WithinDuration(t, time.Now(), u.CreatedAt, 30*time.Second)
}

// ── 15b: Upsert EXISTING (account_id, external_id) → created=false, profile updated.
// : UPSERT теперь per-Account; второй вызов должен указывать тот же
// AccountID, что и первый.
func TestUser_15b_Upsert_Existing_UpdatesProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	first, created1 := upsertUser(t, ctx, repo, "zit-15b", "old15b@example.com", "Old Name")
	require.True(t, created1)

	// Второй Upsert тот же (account_id, external_id), новый email/name.
	u2 := domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)), // ignored on conflict
		AccountID:    first.AccountID,
		ExternalID:   "zit-15b",
		Email:        "new15b@example.com",
		DisplayName:  "New Name",
		InviteStatus: domain.InviteStatusActive,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, created2, err := w.UsersW().Upsert(ctx, u2)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	assert.False(t, created2, "second Upsert → created=false")
	assert.Equal(t, first.ID, out.ID, "row id preserved (xmin's update doesn't change id)")
	assert.Equal(t, domain.Email("new15b@example.com"), out.Email)
	assert.Equal(t, domain.DisplayName("New Name"), out.DisplayName)
}

// ── 16: GetByExternalID ─────────────────────────────────────────────────────
func TestUser_16_GetByExternalID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	u, _ := upsertUser(t, ctx, repo, "ext-16", "u16@example.com", "U16")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Users().GetByExternalID(ctx, "ext-16")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	_, err = rd.Users().GetByExternalID(ctx, "nonexistent-ext")
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

// ── 16b: GetByEmail case-insensitive ────────────────────────────────────────
func TestUser_16b_GetByEmail_CaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	u, _ := upsertUser(t, ctx, repo, "ext-16b", "Mixed.Case@Example.COM", "Mc")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Users().GetByEmail(ctx, "mixed.case@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID, "lookup case-insensitive")
}

// ── 41a: Delete без refs → OK ───────────────────────────────────────────────
func TestUser_41a_Delete_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	u, _ := upsertUser(t, ctx, repo, "ext-41a", "u41a@example.com", "U41a")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.UsersW().Delete(ctx, u.ID))
	require.NoError(t, w.Commit(ctx))
}

// ── 41b: Delete с GroupMember → FailedPrecondition ─────────────────────────
func TestUser_41b_Delete_WithGroupMember(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Setup: User, Account, Group, GroupMember(User).
	u, _ := upsertUser(t, ctx, repo, "ext-41b", "u41b@example.com", "U41b")
	acc := seedAccount(t, ctx, repo, "acc-41b", u.ID)
	grpID := ids.NewID(domain.PrefixGroup)
	_, err = pool.Exec(ctx,
		`INSERT INTO groups (id, account_id, name) VALUES ($1, $2, $3)`,
		grpID, string(acc.ID), "g41b",
	)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO group_members (group_id, member_type, member_id) VALUES ($1, 'user', $2)`,
		grpID, string(u.ID),
	)
	require.NoError(t, err)

	// User cannot be deleted while in group + while owner of account.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, u.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)
}

// ── 41c: Delete с AccessBinding → FailedPrecondition ───────────────────────
func TestUser_41c_Delete_WithAccessBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	u, _ := upsertUser(t, ctx, repo, "ext-41c", "u41c@example.com", "U41c")
	// Bind на system-role (есть в seed)
	abID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id)
		VALUES ($1, 'user', $2, $3, 'account', 'acc0000000000000ghst')`,
		abID, string(u.ID), seedSystemRoleIDIAMView,
	)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, u.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)
	assert.Contains(t, err.Error(), "access bindings")
}

// ── 41d: Delete несущ. → NotFound ───────────────────────────────────────────
func TestUser_41d_Delete_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, "usr0000000000000ghst")
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

// ── 41e: Delete owner-of-Account → FailedPrecondition (FK accounts_owner_fk) ─
func TestUser_41e_Delete_OwnerOfAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// bootstrapAdmin создает user-row который является owner Account'а.
	// Удаление такого user'а должно завершиться FailedPrecondition — FK
	// accounts.owner_user_id RESTRICT не позволяет удалить owner-row пока
	// Account существует.
	userID, _ := bootstrapAdmin(t, ctx, repo, "e41e")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, userID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"owner of Account cannot be deleted while Account exists, got %v", err)
}

// ── ListAccountsForUser should include accounts where user is owner ─────────────────
// Verifies fix: when a user owns a SECOND account (created via
// Account.Create with ownerUserId = userID), ListAccountsForUser must return
// that second account even though the user's primary row has account_id pointing
// to their bootstrap account. Without the fix this test fails because the old
// query only checked `WHERE id = $1 AND invite_status = 'ACTIVE'` — which only
// returns the user's own bootstrap account, not explicitly created owned accounts.
func TestUser_ListAccountsForUser_IncludesOwnedAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Step 1: Bootstrap user — creates userID with bootstrap account (bootstrapAccID).
	userID, bootstrapAccID := bootstrapAdmin(t, ctx, repo, "bug4")

	// Step 2: Create a SECOND account with the same user as owner_user_id.
	// This simulates the setup.sh ensure_account flow: user calls
	// AccountService.Create with ownerUserId=userID → new account created in
	// accounts table, but NO new user row is inserted in users table for that
	// account. The user's primary row still has account_id = bootstrapAccID.
	secondAccID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          secondAccID,
		Name:        domain.AccountName("owned-second-" + string(secondAccID[len(secondAccID)-6:])),
		OwnerUserID: userID,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Step 3: ListAccountsForUser must return BOTH accounts.
	// Before the fix: only bootstrapAccID is returned (user's row account_id).
	// After the fix: both bootstrapAccID and secondAccID are returned.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	accs, err := rd.Users().ListAccountsForUser(ctx, userID)
	require.NoError(t, err)

	accSet := make(map[domain.AccountID]bool, len(accs))
	for _, a := range accs {
		accSet[a] = true
	}
	assert.True(t, accSet[bootstrapAccID],
		"bootstrap account (users.account_id) must be in result")
	assert.True(t, accSet[secondAccID],
		"explicitly owned account (accounts.owner_user_id) must be in result (BUG-4)")
}

// ── List smoke ──────────────────────────────────────────────────────────────
func TestUser_List_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	for i := 0; i < 3; i++ {
		_, _ = upsertUser(t, ctx, repo,
			fmt.Sprintf("ext-list-%d", i),
			fmt.Sprintf("list%d@example.com", i),
			"L",
		)
	}
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err := rd.Users().List(ctx, repouser.ListFilter{PageSize: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rows), 3)
}
