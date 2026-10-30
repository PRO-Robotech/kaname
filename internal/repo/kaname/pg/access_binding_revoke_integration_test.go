// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_revoke_integration_test.go — TDD integration-тесты для
// redesign-2026 F10 (`AccessBinding.:revoke` — мягкий отзыв, `Delete` — жёсткое
// удаление; IAM-1-28/29).
//
// Покрытие (testcontainers Postgres 16, реальные миграции + partial UNIQUE):
//   - TestAB_IAM_1_28_RevokeGuarded_SoftRevoke — CAS ACTIVE→REVOKED; строка ОСТАЁТСЯ
//     (Get всё ещё возвращает строку, НЕ NotFound), revoked_at/revoked_by проставлены
//     (хранение для аудита) — в отличие от жёсткого Delete (Get→NotFound).
//   - TestAB_IAM_1_28_RevokeGuarded_RefusesProtected — при deletion_protection=true
//     отказ FAILED_PRECONDITION (атомарный CAS `WHERE …AND deletion_protection=false`,
//     owner-binding не отзывается случайно, паритет с Delete).
//   - TestAB_IAM_1_28_RevokeGuarded_NotFound — отсутствующий binding → NotFound.
//   - TestAB_IAM_1_28_RevokeGuarded_TerminalRevoked — повторный revoke уже-REVOKED
//     → FAILED_PRECONDITION (REVOKED терминален; идемпотентность grant-lifecycle).
//   - TestAB_IAM_1_29_ReGrantAfterRevoke_Race — concurrent-race на partial-UNIQUE
//     re-grant (data-integrity §5): N goroutine Insert идентичного (subject,role,
//     scope) при ACTIVE → ровно 1 winner, остальные ALREADY_EXISTS; после :revoke
//     winner'а → новый идентичный Create проходит как НОВАЯ ACTIVE-строка (revoked
//     строка освобождает slot partial UNIQUE `WHERE revoked_at IS NULL`).
//   - TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS — N горутин зовут RevokeGuarded
//     ОДНОГО ACTIVE binding → ровно один success, остальные FAILED_PRECONDITION
//     (row-lock сериализует; проигравшие видят строку уже REVOKED). Под -race.
//
// Запуск: `go test ./internal/repo/kaname/pg/... -race`. Уборщик контейнеров
// testcontainers (ryuk) НЕ выключается: `Terminate` исполняется лишь при штатном
// завершении, а обрыв по `-timeout`, сигнал или падение процесса оставили бы Postgres
// жить без владельца. Выключение уборщика законно только в конвейере на эфемерном
// исполнителе (`.github/workflows/ci.yml`, шаг «контейнерные пробы»), который
// исчезает целиком вместе с поднятым.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// insertActiveBinding — помощник: вставляет и фиксирует одну ACTIVE-выдачу с данным
// id и пятёркой полей, как обвязка проб deletion_protection.
func insertActiveBinding(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	id domain.AccessBindingID, uid domain.UserID, accID string, protected bool) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
		DeletionProtection: protected,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
}

func TestAB_IAM_1_28_RevokeGuarded_SoftRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-soft")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-soft", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

	// Мягкий отзыв.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoked, err := w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status,
		"RevokeGuarded returns the row transitioned to REVOKED")
	require.NotNil(t, revoked.RevokedAt, "revoked_at must be stamped")
	require.NotNil(t, revoked.RevokedByUserID, "revoked_by_user_id must be retained (audit)")
	assert.Equal(t, uid, *revoked.RevokedByUserID)

	// Строка ОСТАЁТСЯ — Get её возвращает (в отличие от жёсткого Delete → NotFound).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, gerr, "soft-revoke retains the row — Get must still succeed")
	assert.Equal(t, domain.AccessBindingStatusRevoked, got.Status)
	require.NotNil(t, got.RevokedAt)
}

func TestAB_IAM_1_28_RevokeGuarded_RefusesProtected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-prot")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-prot", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), true) // защищена

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"RevokeGuarded on protected binding → FailedPrecondition, got %v", err)

	// Строка обязана пережить отвергнутый отзыв (по-прежнему ACTIVE).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, gerr := rd.AccessBindings().Get(ctx, id)
	_ = rd.Rollback(ctx)
	require.NoError(t, gerr)
	assert.Equal(t, domain.AccessBindingStatusActive, got.Status, "protected binding stays ACTIVE")
}

func TestAB_IAM_1_28_RevokeGuarded_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), "usr-nobody")
	_ = w.Rollback(ctx)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"RevokeGuarded missing → NotFound, got %v", err)
}

func TestAB_IAM_1_28_RevokeGuarded_TerminalRevoked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-term")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-term", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

	// Первый отзыв побеждает.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Второй отзыв уже REVOKED (терминальной) строки → FailedPrecondition.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w2.AccessBindingsW().RevokeGuarded(ctx, id, uid)
	_ = w2.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"re-revoke of REVOKED (terminal) → FailedPrecondition, got %v", err)
}

// TestAB_IAM_1_29_ReGrantAfterRevoke_Race — гонка на частичном UNIQUE действующих
// выдач (data-integrity §5). N горутин разом вставляют ОДНУ И ТУ ЖЕ пятёрку (id
// разные) → ровно ОДНА становится ACTIVE, остальные получают ALREADY_EXISTS. После
// :revoke победителя такая же повторная выдача — НОВАЯ ACTIVE-строка (у REVOKED-строки
// стоит revoked_at, и место частичного UNIQUE освобождается).
func TestAB_IAM_1_29_ReGrantAfterRevoke_Race(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-race")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-race", uid)
	accID := string(acc.ID)

	// ── Фаза 1: конкурентные одинаковые Create → ровно один победитель ─────
	const goroutines = 8
	type res struct {
		id  domain.AccessBindingID
		err error
	}
	out := make(chan res, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
			ready.Done()
			<-startGate
			gw, werr := repo.Writer(ctx)
			if werr != nil {
				out <- res{id, werr}
				return
			}
			_, ierr := bindingset.Insert(ctx, gw.AccessBindingsW(), domain.AccessBinding{
				ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
				RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
			})
			if ierr != nil {
				_ = gw.Rollback(ctx)
				out <- res{id, ierr}
				return
			}
			out <- res{id, gw.Commit(ctx)}
		}()
	}
	ready.Wait()
	close(startGate)

	var winner domain.AccessBindingID
	successes, already, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		r := <-out
		switch {
		case r.err == nil:
			successes++
			winner = r.id
		case stderrors.Is(r.err, iamerr.ErrAlreadyExists):
			already++
		default:
			other++
			t.Logf("unexpected race error: %v", r.err)
		}
	}
	require.Equal(t, 1, successes, "exactly one identical Create wins the active-grant UNIQUE")
	assert.Equal(t, goroutines-1, already, "losers get ALREADY_EXISTS (partial UNIQUE)")
	assert.Equal(t, 0, other, "no unexpected errors / panics")

	// ── Фаза 2: отзыв победителя ──────────────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, winner, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// ── Фаза 3: такая же повторная выдача — теперь НОВАЯ ACTIVE-строка ────
	regrantID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	regranted, err := bindingset.Insert(ctx, w2.AccessBindingsW(), domain.AccessBinding{
		ID: regrantID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: "rol000000000sysviewer", ResourceType: "account", ResourceID: accID,
	})
	require.NoError(t, err, "re-grant after revoke must succeed — revoked row frees the slot")
	require.NoError(t, w2.Commit(ctx))
	assert.NotEqual(t, winner, regranted.ID, "re-grant is a distinct new ACTIVE binding id")
	assert.Equal(t, domain.AccessBindingStatusActive, regranted.Status)
}

// TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS — N горутин зовут RevokeGuarded на ОДНОЙ
// ACTIVE-выдаче → ровно один успех, остальные FailedPrecondition (блокировка строки
// одним оператором UPDATE … WHERE status='ACTIVE' сериализует; проигравшие видят её уже
// REVOKED). Двух победителей не бывает, паники не бывает. Идёт под -race.
func TestAB_IAM_1_28_RevokeGuarded_ConcurrentCAS(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-28-cas")
	acc := seedAccount(t, ctx, repo, "acc-iam1-28-cas", uid)
	id := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	insertActiveBinding(t, ctx, repo, id, uid, string(acc.ID), false)

	const goroutines = 8
	results := make(chan error, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			ready.Done()
			<-startGate
			gw, werr := repo.Writer(ctx)
			if werr != nil {
				results <- werr
				return
			}
			_, rerr := gw.AccessBindingsW().RevokeGuarded(ctx, id, uid)
			if rerr != nil {
				_ = gw.Rollback(ctx)
				results <- rerr
				return
			}
			results <- gw.Commit(ctx)
		}()
	}
	ready.Wait()
	close(startGate)

	successes, failedPre, other := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		switch err := <-results; {
		case err == nil:
			successes++
		case stderrors.Is(err, iamerr.ErrFailedPrecondition):
			failedPre++
		default:
			other++
			t.Logf("unexpected race error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one RevokeGuarded wins")
	assert.Equal(t, goroutines-1, failedPre, "losers see the row already REVOKED → FailedPrecondition")
	assert.Equal(t, 0, other, "no unexpected errors / panics")
}
