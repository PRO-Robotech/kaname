// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_invite_integration_test.go — integration tests для user-invite-flow.
//
// Покрытие:
// - InsertPending happy/idempotent.
// - InsertPending concurrent race.
// - ActivateInvite happy + not-found.
// - FindPendingByEmail: одна строка человека, членства в N аккаунтах.
// - FindActiveByExternalID.
// - GetByAccountEmail (idempotent invite).
// - InsertActive bootstrap-flow DEFERRABLE FK.
// - Глобальная уникальность почты: приглашение известной почты во второй
//   аккаунт (строка одна, членств много).
// - List filter by AccountID + AccountIDs (default-deny).
//
// Все тесты используют testcontainers Postgres (как и существующие в этом
// репо). Skip если `testing.Short()`.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	repouser "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/user"
)

// bootstrapAdmin — utility: bootstrap-флоу (user + own Account) через одну TX
// с DEFERRABLE FK. Возвращает (userID, accountID) admin'а.
func bootstrapAdmin(t *testing.T, ctx context.Context, repo *kachopg.Repository, suffix string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		ExternalID:   domain.ExternalSubject("ext-" + suffix + "-" + string(uid)),
		Email:        domain.Email(fmt.Sprintf("admin-%s@example.com", strings.ToLower(suffix))),
		DisplayName:  domain.DisplayName("Admin " + suffix),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          accID,
		Name:        domain.AccountName(fmt.Sprintf("acc-%s-%s", strings.ToLower(suffix), strings.ToLower(string(accID[len(accID)-6:])))),
		OwnerUserID: uid,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	committed = true
	return uid, accID
}

// ── InsertPending happy — новый PENDING-row ───────────────────────────
func TestUserInvite_S01_InsertPending_New(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "s01")

	// When Invite new email
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	out, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        domain.Email("newbie@example.com"),
		DisplayName:  domain.DisplayName("Newbie"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	assert.True(t, inserted, "first InsertPending → inserted=true")
	assert.Equal(t, uid, out.ID)
	assert.Equal(t, accID, out.AccountID)
	assert.Equal(t, domain.InviteStatusPending, out.InviteStatus)
	assert.Equal(t, domain.ExternalSubject(""), out.ExternalID)
	assert.Equal(t, adminID, out.InvitedBy)
}

// ── InsertPending idempotent — second invite to same email ────────────
func TestUserInvite_S03_InsertPending_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "s03")
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid1 := domain.UserID(ids.NewID(domain.PrefixUser))
	first, ins1, err := w.UsersW().InsertPending(ctx, domain.User{
		ID: uid1, AccountID: accID, Email: "dup@example.com",
		DisplayName: "Original", InviteStatus: domain.InviteStatusPending, InvitedBy: adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.True(t, ins1)

	// Second Invite to same email — should be idempotent
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid2 := domain.UserID(ids.NewID(domain.PrefixUser))
	second, ins2, err := w2.UsersW().InsertPending(ctx, domain.User{
		ID: uid2, AccountID: accID, Email: "DUP@example.com", // mixed case
		DisplayName: "DifferentName", InviteStatus: domain.InviteStatusPending, InvitedBy: adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	assert.False(t, ins2, "second InsertPending → inserted=false (idempotent)")
	assert.Equal(t, first.ID, second.ID, "same row returned")
	assert.Equal(t, domain.DisplayName("Original"), second.DisplayName,
		"display_name НЕ перезаписывается (DO NOTHING)")
}

// ── FindPendingByEmail — один человек, приглашённый в ДВА аккаунта ────
//
// Прежняя редакция звалась `..._CrossAccount` и утверждала ДВЕ строки, по одной
// на аккаунт: ключ почты был парным с аккаунтом, поэтому приглашение того же
// человека во второй аккаунт заводило ему вторую строку — второй идентификатор
// и второй набор прав, из которых действовал один.
//
// Ключ стал глобальным (`users_identity_email_uniq`, миграция
// 20260823050000_users_identity_uniqueness_goes_global), и такого состояния не
// бывает ни при каком вводе. Предпосылка прежнего утверждения неконструируема,
// поэтому проба переписана под новый наблюдаемый исход ТОГО ЖЕ пути, а не снята.
//
// Вопрос при этом не исчез, а разделился надвое — и проба задаёт оба:
//
//   - «сколько строк с этой почтой ждут входа» — отвечает читатель по почте:
//     ровно одна, сколько бы приглашений ни пришло;
//   - «в каких аккаунтах человек приглашён» — отвечает зеркало членств.
//
// Спросить только первое было бы хуже, чем не спрашивать: «одна строка»
// зеленеет и тогда, когда приглашение во второй аккаунт не доехало вовсе.
func TestUserInvite_S04_FindPendingByEmail_OneRowManyMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminAID, accA := bootstrapAdmin(t, ctx, repo, "s04A")
	adminBID, accB := bootstrapAdmin(t, ctx, repo, "s04B")

	const shared = domain.Email("shared@example.com")

	// invite — путь приглашения одной операцией; соединение возвращается в пул
	// на любом исходе, иначе отказ утверждения увёл бы за собой и закрытие пула.
	invite := func(acc domain.AccountID, admin domain.UserID, email domain.Email) domain.User {
		t.Helper()
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		committed := false
		defer func() {
			if !committed {
				_ = w.Rollback(ctx)
			}
		}()
		u, _, ierr := w.UsersW().InsertPending(ctx, domain.User{
			ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
			AccountID:    acc,
			Email:        email,
			DisplayName:  "Pending",
			InviteStatus: domain.InviteStatusPending,
			InvitedBy:    admin,
		})
		require.NoError(t, ierr)
		require.NoError(t, w.Commit(ctx))
		committed = true
		return u
	}

	person := invite(accA, adminAID, shared)
	again := invite(accB, adminBID, shared)
	require.Equal(t, person.ID, again.ID,
		"оба приглашения обязаны сойтись на ОДНОМ человеке — иначе всё, что ниже, "+
			"утверждает про две разные личности")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	rows, err := rd.Users().FindPendingByEmail(ctx, shared)
	require.NoError(t, err)
	// Отрицательный контроль читателя: он обязан РАЗЛИЧАТЬ почту, а не отдавать
	// всё подряд. Без этого «одна строка» ниже ничего не сообщает.
	none, err := rd.Users().FindPendingByEmail(ctx, domain.Email("nobody-s04@example.com"))
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(ctx))

	assert.Empty(t, none, "на неизвестную почту читатель обязан вернуть пусто")
	if assert.Len(t, rows, 1, "строка человека одна, сколько бы приглашений ни пришло") {
		assert.Equal(t, person.ID, rows[0].ID)
		assert.Equal(t, domain.InviteStatusPending, rows[0].InviteStatus)
		assert.Equal(t, domain.ExternalSubject(""), rows[0].ExternalID,
			"приглашённый внешнего субъекта не несёт — он появится на первом входе")
	}

	mems := membershipsOf(t, ctx, pool, person.ID)
	require.Len(t, mems, 2,
		"«в каких аккаунтах он приглашён» отвечает зеркало членств — их обязано стать два")
	state := map[string]string{}
	for _, m := range mems {
		state[m.AccountID] = m.State
	}
	assert.Equal(t, "PENDING", state[string(accA)],
		"членство в аккаунте A обязано ждать входа")
	assert.Equal(t, "PENDING", state[string(accB)],
		"членство в аккаунте B обязано ждать входа — приглашение не активирует человека")

	// ── положительный контроль: другой человек — своя строка и своё членство ─
	other := invite(accA, adminAID, domain.Email("other-s04@example.com"))
	assert.NotEqual(t, person.ID, other.ID,
		"другая почта обязана завести СВОЮ строку — иначе «одна строка» выше означало бы, "+
			"что писатель сводит в неё кого угодно")
	assert.Len(t, membershipsOf(t, ctx, pool, other.ID), 1)
}

// ── ActivateInvite — PENDING → ACTIVE happy ───────────────────────────
func TestUserInvite_S05_ActivateInvite_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "s05")
	// Pre-create PENDING
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "activate@example.com",
		DisplayName:  "Activated",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Activate
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, err := w2.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("kratos-sub-s05"),
		domain.DisplayName("Real Name"))
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	assert.Equal(t, pending.ID, activated.ID)
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
	assert.Equal(t, domain.ExternalSubject("kratos-sub-s05"), activated.ExternalID)
	assert.Equal(t, domain.DisplayName("Real Name"), activated.DisplayName)

	// FindActive should now find it
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, err := rd.Users().FindActiveByExternalID(ctx, "kratos-sub-s05")
	require.NoError(t, err)
	assert.Len(t, rows, 1)
	assert.Equal(t, pending.ID, rows[0].ID)
}

// ── ActivateInvite — already-ACTIVE row → ErrNotFound ────────────────
func TestUserInvite_S05b_ActivateInvite_NotPending_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// bootstrapAdmin создает ACTIVE-row сразу. Попытка ActivateInvite на нее
	// → 0 rows RETURNING → ErrNotFound (row уже не в PENDING-состоянии).
	adminID, _ := bootstrapAdmin(t, ctx, repo, "s05b")
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.UsersW().ActivateInvite(ctx, adminID,
		domain.ExternalSubject("new-sub"), domain.DisplayName("X"))
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"expected ErrNotFound (row not in PENDING state), got %v", err)
}

// ── InsertActive bootstrap — DEFERRABLE FK (user + account same TX) ───
func TestUserInvite_S06_Bootstrap_DeferrableFK(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Bootstrap flow: INSERT user → INSERT account → COMMIT
	// FK на account_id отложен; на COMMIT все проверяется консистентно.
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)

	// 1. INSERT user первым (FK на account отложен).
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           uid,
		AccountID:    accID, // ← forward reference
		ExternalID:   domain.ExternalSubject("bootstrap-sub-s06"),
		Email:        "bootstrap@example.com",
		DisplayName:  "Bootstrap User",
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "InsertActive: FK check deferred to COMMIT")

	// 2. INSERT account (owner_user_id = uid; FK тоже отложен).
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          accID,
		Name:        domain.AccountName("bootstrap-acc-s06"),
		OwnerUserID: uid,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err, "Insert account: FK check deferred")

	// 3. COMMIT — DEFERRABLE FK проверяется здесь.
	require.NoError(t, w.Commit(ctx), "COMMIT should succeed (both FK resolved)")

	// Verify state
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	u, err := rd.Users().Get(ctx, uid)
	require.NoError(t, err)
	assert.Equal(t, accID, u.AccountID)
	assert.Equal(t, domain.InviteStatusActive, u.InviteStatus)
}

// ── Bootstrap-TX negative: INSERT user без последующего account → COMMIT fails ──
func TestUserInvite_S30_Bootstrap_DeferrableFK_FailOnCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)

	// INSERT user с account_id = несуществующий accID; FK отложен.
	_, err = w.UsersW().InsertActive(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		ExternalID:   domain.ExternalSubject("orphan-sub-s30"),
		Email:        "orphan@example.com",
		DisplayName:  "Orphan",
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "INSERT itself does not fail (FK deferred)")

	// COMMIT должен упасть на FK-violation (account не существует).
	err = w.Commit(ctx)
	require.Error(t, err, "COMMIT must fail — account_id points to missing row")
	_ = w.Rollback(ctx)
}

// ── ConcurrentInvite — race-safe (UNIQUE на account_id + lower(email)) ──
func TestUserInvite_S11_ConcurrentInvite_RaceSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "s11")

	const N = 5
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []bool // inserted-flags
		gotIDs  []domain.UserID
		errs    []error
	)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			uid := domain.UserID(ids.NewID(domain.PrefixUser))
			out, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
				ID:           uid,
				AccountID:    accID,
				Email:        "race@example.com",
				DisplayName:  "Race",
				InviteStatus: domain.InviteStatusPending,
				InvitedBy:    adminID,
			})
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			if err := w.Commit(ctx); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, inserted)
			gotIDs = append(gotIDs, out.ID)
			mu.Unlock()
		}()
	}
	wg.Wait()

	// 0 ошибок (все TX успешны: одна INSERT'ит, остальные подцепляют existing).
	assert.Empty(t, errs, "no errors expected (all idempotent)")
	// Все вернули одну и ту же row.
	require.NotEmpty(t, gotIDs)
	for _, id := range gotIDs[1:] {
		assert.Equal(t, gotIDs[0], id, "all goroutines see same row id")
	}
	// Ровно 1 inserted=true (первый INSERT), остальные inserted=false.
	insertedCount := 0
	for _, b := range results {
		if b {
			insertedCount++
		}
	}
	assert.Equal(t, 1, insertedCount, "exactly one goroutine wrote new row")
}

// ── GetByAccountEmail — для idempotent invite use-case ────────────────
func TestUserInvite_S23_GetByAccountEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accA := bootstrapAdmin(t, ctx, repo, "s23A")
	_, accB := bootstrapAdmin(t, ctx, repo, "s23B")

	// Insert PENDING into accA only.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, _, err = w.UsersW().InsertPending(ctx, domain.User{
		ID: uid, AccountID: accA, Email: "scope@example.com",
		DisplayName: "Scoped", InviteStatus: domain.InviteStatusPending, InvitedBy: adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// In accA → found
	gotA, err := rd.Users().GetByAccountEmail(ctx, accA, "scope@example.com")
	require.NoError(t, err)
	assert.Equal(t, uid, gotA.ID)

	// In accB → NotFound (per-Account isolation)
	_, err = rd.Users().GetByAccountEmail(ctx, accB, "scope@example.com")
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "expected NotFound, got %v", err)
}

// ── List filter by AccountID + AccountIDs ─────────────────────────────
func TestUserInvite_S09_List_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "s09A")
	_, accB := bootstrapAdmin(t, ctx, repo, "s09B")

	// 2 PENDING в accA, 1 PENDING в accB.
	for i, p := range []struct {
		acc   domain.AccountID
		email string
	}{
		{accA, "a1@example.com"}, {accA, "a2@example.com"},
		{accB, "b1@example.com"},
	} {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID:        domain.UserID(ids.NewID(domain.PrefixUser)),
			AccountID: p.acc, Email: domain.Email(p.email),
			DisplayName:  domain.DisplayName(fmt.Sprintf("U%d", i)),
			InviteStatus: domain.InviteStatusPending, InvitedBy: adminA,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// accA filter: only accA users (2 invited + 1 admin = 3).
	rowsA, _, err := rd.Users().List(ctx, repouser.ListFilter{
		AccountID: accA, PageSize: 50,
	})
	require.NoError(t, err)
	assert.Len(t, rowsA, 3, "accA: 2 invited + 1 admin")

	// accB filter: 1 admin + 1 invited.
	rowsB, _, err := rd.Users().List(ctx, repouser.ListFilter{
		AccountID: accB, PageSize: 50,
	})
	require.NoError(t, err)
	assert.Len(t, rowsB, 2, "accB: 1 invited + 1 admin")

	// accA+accB AccountIDs filter: all.
	rowsAll, _, err := rd.Users().List(ctx, repouser.ListFilter{
		AccountIDs: []domain.AccountID{accA, accB}, PageSize: 50,
	})
	require.NoError(t, err)
	assert.Len(t, rowsAll, 5, "all 5 rows across both accounts")
}

// ── Почта опознаёт ЧЕЛОВЕКА, а не его строку в аккаунте ───────────────
//
// Прежняя редакция звалась `..._UniqueEmailPerAccount` и стерегла ровно
// обратное сегодняшнему: уникальность почты была ПАРНОЙ с аккаунтом, поэтому та
// же почта в другом аккаунте была законной ВТОРОЙ строкой — и проба этого
// требовала. Предпосылка снята миграцией
// 20260823050000_users_identity_uniqueness_goes_global: ключ `lower(email)`
// стал глобальным, и второй строки не бывает ни при каком вводе.
//
// Пер-аккаунтной границы больше нет — но уникальность не исчезла, она стала
// ШИРЕ, и её отказ обязан быть утверждён: иначе «снята прежняя граница»
// неотличимо от «снята всякая».
//
// Поэтому проба спрашивает обе половины одного предмета:
//
//   - путь приглашения (`InsertPending`, арбитрирующий почту) второй строки НЕ
//     ЗАВОДИТ: он находит человека и добавляет ему членство в названном
//     аккаунте;
//   - писатель первого появления (`InsertActive`), который почту НЕ
//     арбитрирует, упирается в САМ КЛЮЧ и получает отказ сентинелом.
//
// Каждое отрицание идёт в паре с положительным контролем: «вторая строка не
// заведена» истинно и тогда, когда писатель не заводит строк вовсе, а «ключ
// отверг» — и тогда, когда писатель отвергает любой ввод.
func TestUserInvite_S25_EmailIdentifiesThePersonGlobally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	adminID, accA := bootstrapAdmin(t, ctx, repo, "s25A")
	_, accB := bootstrapAdmin(t, ctx, repo, "s25B")

	const email = domain.Email("u@example.com")

	// ── первое появление: строка заводится ──────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	first, ins1, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:        domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID: accA, Email: email,
		DisplayName: "X", InviteStatus: domain.InviteStatusPending, InvitedBy: adminID,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.True(t, ins1, "ПРЕДПОСЫЛКА: неизвестная почта обязана завести строку")

	// ── та же почта во ВТОРОЙ аккаунт: тот же человек, второе членство ──────
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	second, ins2, err := w2.UsersW().InsertPending(ctx, domain.User{
		ID:        domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID: accB, Email: email,
		DisplayName: "Y", InviteStatus: domain.InviteStatusPending, InvitedBy: adminID,
	})
	require.NoError(t, err,
		"приглашение известной почты во второй аккаунт обязано ПРОЙТИ: отказ здесь означал бы, "+
			"что глобальный ключ сломал путь, ради которого он и вводился")
	require.NoError(t, w2.Commit(ctx))
	assert.False(t, ins2,
		"вторая строка заводиться не вправе — человек уже есть, и писатель обязан это различать")
	assert.Equal(t, first.ID, second.ID, "идентификатор человека один и тот же в обоих ответах")

	var rowsWithThatEmail int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.users WHERE lower(email) = lower($1)`,
		string(email)).Scan(&rowsWithThatEmail))
	assert.Equal(t, 1, rowsWithThatEmail, "строк с этой почтой обязана остаться ровно одна")

	mems := membershipsOf(t, ctx, pool, first.ID)
	require.Len(t, mems, 2,
		"принадлежность двум аккаунтам выражается ЧЛЕНСТВАМИ — без этого утверждения "+
			"«одна строка» зеленело бы и тогда, когда второе приглашение не доехало вовсе")
	assert.ElementsMatch(t, []string{string(accA), string(accB)},
		[]string{mems[0].AccountID, mems[1].AccountID},
		"членства обязаны вести в оба названных аккаунта, а не в один дважды")

	// ── сам ключ: писатель, почту НЕ арбитрирующий, получает отказ ──────────
	//
	// InsertPending выше в конфликт не упирается by construction — он его
	// арбитрирует. Значит утверждать через него, что ключ существует, нельзя:
	// он зеленел бы и на базе вовсе без ключа. Отказ спрашивается у того
	// писателя, для которого конфликт есть конфликт.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w3.UsersW().InsertActive(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accB,
		ExternalID:   domain.ExternalSubject("ext-s25-clash"),
		Email:        email,
		DisplayName:  "Clash",
		InviteStatus: domain.InviteStatusActive,
	})
	_ = w3.Rollback(ctx)
	require.Error(t, err,
		"вторая строка на ту же почту обязана быть отвергнута КЛЮЧОМ, а не принята молча")
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
		"отказ ключа обязан приезжать сентинелом ErrAlreadyExists, получено %v", err)
	assert.NotContains(t, err.Error(), "users_identity_email_uniq",
		"имя ограничения наружу не течёт (data-integrity.md §SQLSTATE-маппинг)")
	assert.NotContains(t, err.Error(), "duplicate key value",
		"сырой текст драйвера наружу не течёт")

	// ── положительный контроль к отказу ─────────────────────────────────────
	w4, err := repo.Writer(ctx)
	require.NoError(t, err)
	otherID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w4.UsersW().InsertActive(ctx, domain.User{
		ID:           otherID,
		AccountID:    accB,
		ExternalID:   domain.ExternalSubject("ext-s25-other"),
		Email:        domain.Email("other-s25@example.com"),
		DisplayName:  "Other",
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err,
		"тот же писатель на СВОБОДНОЙ почте обязан завести строку — иначе отказ выше "+
			"доказывал бы лишь то, что писатель сломан целиком")
	require.NoError(t, w4.Commit(ctx))
	assert.Len(t, membershipsOf(t, ctx, pool, otherID), 1,
		"у своего человека своё единственное членство")
}
