// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_setblocked_integration_test.go — писатель состояния членства против
// настоящего Postgres.
//
// Здесь проверяется то, что unit-фейк проверить не может по построению: что
// ОДИН стейтмент действительно различает три исхода, что предикат не даёт
// тронуть неподтверждённое приглашение (иначе прилетел бы не внятный отказ, а
// нарушение констрейнта из глубины драйвера), и что конкурирующие писатели
// оставляют строку в одном из запрошенных состояний, а не в третьем.
//
// Run: `go test ./internal/repo/kacho/pg/... -run UserSetInviteStatus`.
// Пропускается с -short.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// setInviteStatus прогоняет писателя в собственной writer-транзакции и коммитит.
func setInviteStatus(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	id domain.UserID, st domain.InviteStatus) (domain.User, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, serr := w.UsersW().SetInviteStatus(ctx, id, st)
	if serr != nil {
		_ = w.Rollback(ctx)
		return domain.User{}, serr
	}
	require.NoError(t, w.Commit(ctx))
	return out, nil
}

func readInviteStatus(t *testing.T, ctx context.Context, repo *kachopg.Repository, id domain.UserID) string {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	u, err := rd.Users().Get(ctx, id)
	require.NoError(t, err)
	return string(u.InviteStatus)
}

func newSetBlockedEnv(t *testing.T) (context.Context, *kachopg.Repository, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return ctx, kachopg.New(pool, nil), pool
}

// TestUserSetInviteStatus_RoundTripsBothDirections — состояние доезжает до
// колонки и читается обратно, в обе стороны. Односторонний контроль — тот, за
// которым оператор не потянется.
func TestUserSetInviteStatus_RoundTripsBothDirections(t *testing.T) {
	ctx, repo, pool := newSetBlockedEnv(t)
	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_setblk_rt", "rt@example.com", "ACTIVE")

	out, err := setInviteStatus(t, ctx, repo, uid, domain.InviteStatusBlocked)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusBlocked, out.InviteStatus,
		"писатель возвращает строку целиком, чтобы вызывающий назвал аккаунт в следе без второго чтения")
	assert.Equal(t, "BLOCKED", readInviteStatus(t, ctx, repo, uid))

	back, err := setInviteStatus(t, ctx, repo, uid, domain.InviteStatusActive)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusActive, back.InviteStatus)
	assert.Equal(t, "ACTIVE", readInviteStatus(t, ctx, repo, uid))
}

// TestUserSetInviteStatus_IsIdempotentByState — аргумент состояние, а не
// переход: повтор проходит и оставляет строку там же.
func TestUserSetInviteStatus_IsIdempotentByState(t *testing.T) {
	ctx, repo, pool := newSetBlockedEnv(t)
	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_setblk_idem", "idem@example.com", "BLOCKED")

	out, err := setInviteStatus(t, ctx, repo, uid, domain.InviteStatusBlocked)
	require.NoError(t, err, "повтор безопасного направления не может быть отказом")
	assert.Equal(t, domain.InviteStatusBlocked, out.InviteStatus)
	assert.Equal(t, "BLOCKED", readInviteStatus(t, ctx, repo, uid))
}

// TestUserSetInviteStatus_MissingRow_NotFound — строки нет → NotFound
// контракт-тоном. Это та половина различителя, которую предикат состояния
// схлопнул бы с «есть, но нельзя», если бы стейтмент не возвращал признак
// существования.
func TestUserSetInviteStatus_MissingRow_NotFound(t *testing.T) {
	ctx, repo, _ := newSetBlockedEnv(t)
	absent := domain.UserID(ids.NewID(domain.PrefixUser))

	_, err := setInviteStatus(t, ctx, repo, absent, domain.InviteStatusBlocked)
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrNotFound),
		"ожидался sentinel отсутствия, получено %v", err)
	assert.Contains(t, err.Error(), fmt.Sprintf("User %s not found", absent))
}

// TestUserSetInviteStatus_PendingRow_FailedPrecondition — и вторая половина:
// строка ЕСТЬ, но её состояние записи не допускает.
//
// Ответ обязан отличаться от предыдущего кейса. Схлопни их в один код — и
// администратор, которому сказали «нет такого пользователя» про существующее
// приглашение, пойдёт искать не там; а сказать про удалённую строку
// «не активна» значило бы утверждать про неё то, чего проверить уже нельзя.
func TestUserSetInviteStatus_PendingRow_FailedPrecondition(t *testing.T) {
	ctx, repo, pool := newSetBlockedEnv(t)
	// PENDING несёт пустой external_id — так требует
	// users_invite_status_consistency, и именно поэтому такую строку нельзя
	// перевести ни в ACTIVE, ни в BLOCKED.
	uid, _ := seedAccountAndUser(t, ctx, pool, "", "pending@example.com", "PENDING")

	for _, st := range []domain.InviteStatus{domain.InviteStatusBlocked, domain.InviteStatusActive} {
		t.Run(string(st), func(t *testing.T) {
			_, err := setInviteStatus(t, ctx, repo, uid, st)
			require.Error(t, err)
			assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition),
				"ожидалось предусловие, получено %v", err)
			assert.Contains(t, err.Error(), fmt.Sprintf("User %s is not active", uid))
			assert.Equal(t, "PENDING", readInviteStatus(t, ctx, repo, uid),
				"отказ, у которого остался эффект, — не отказ")
		})
	}
}

// TestUserSetInviteStatus_ConcurrentWritersLeaveARequestedState — конкурирующие
// писатели не оставляют строку в третьем состоянии.
//
// Инвариант выражен предикатом одного стейтмента, а не проверкой-до-записи,
// поэтому здесь проверяется именно то, что даёт БД: row-lock сериализует
// писателей, каждый видит уже обновлённую строку, и итог — одно из ЗАПРОШЕННЫХ
// состояний. Unit-тест этого поймать не может.
func TestUserSetInviteStatus_ConcurrentWritersLeaveARequestedState(t *testing.T) {
	ctx, repo, pool := newSetBlockedEnv(t)
	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_setblk_race", "race@example.com", "ACTIVE")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := domain.InviteStatusBlocked
			if i%2 == 1 {
				st = domain.InviteStatusActive
			}
			w, err := repo.Writer(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			if _, serr := w.UsersW().SetInviteStatus(ctx, uid, st); serr != nil {
				_ = w.Rollback(ctx)
				errs[i] = serr
				return
			}
			errs[i] = w.Commit(ctx)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		assert.NoError(t, err, "писатель %d: обе стороны идемпотентны, отказов быть не должно", i)
	}
	final := readInviteStatus(t, ctx, repo, uid)
	assert.Contains(t, []string{"ACTIVE", "BLOCKED"}, final,
		"итог обязан быть одним из запрошенных состояний, получено %q", final)
}

// TestUserSetInviteStatus_RejectsUnknownState — состояние приходит
// bind-параметром, поэтому мусор в нём не должен доезжать до CHECK базы: отказ
// обязан быть внятным аргументным, а не нарушением констрейнта из драйвера.
func TestUserSetInviteStatus_RejectsUnknownState(t *testing.T) {
	ctx, repo, pool := newSetBlockedEnv(t)
	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_setblk_bad", "bad@example.com", "ACTIVE")

	_, err := setInviteStatus(t, ctx, repo, uid, domain.InviteStatus("SUSPENDED"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrInvalidArg),
		"ожидался аргументный отказ, получено %v", err)
	assert.Equal(t, "ACTIVE", readInviteStatus(t, ctx, repo, uid))
}
