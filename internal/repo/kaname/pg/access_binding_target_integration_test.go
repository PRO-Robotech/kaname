// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_target_integration_test.go — redesign-2026 F8 (IAM-1-21/29):
// частичный UNIQUE действующих выдач теперь включает `target_digest`, поэтому:
//
//   - два конкурентных ОДИНАКОВЫХ Create (тот же субъект, роль, область И цель) →
//     ровно один победитель, остальные ALREADY_EXISTS (отпечаток — колонка ключа;
//     WHERE revoked_at IS NULL НЕ МЕНЯЛСЯ и не ослаблен до status='ACTIVE');
//   - после RevokeGuarded победителя такая же повторная выдача — НОВАЯ ACTIVE-строка
//     (отозванная строка освобождает место);
//   - две РАЗНЫЕ цели (тот же субъект, роль, область) СОСУЩЕСТВУЮТ — новое измерение
//     F8 — потому что их отпечатки различны.
//
// Идёт под -race. Запуск: `go test ./internal/repo/kaname/pg/... -race -timeout 30m -p 1`.
// Уборщик контейнеров testcontainers (ryuk) НЕ выключается: `Terminate` исполняется
// лишь при штатном завершении, а обрыв по `-timeout`, сигнал или падение процесса
// оставили бы Postgres жить без владельца. Выключение уборщика законно только в
// конвейере на эфемерном исполнителе (`.github/workflows/ci.yml`, шаг «контейнерные
// пробы»), который исчезает целиком вместе с поднятым.

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

// insertBindingWithTarget вставляет и фиксирует одну ACTIVE-выдачу с данной целью
// на пятёрке полей (uid, аккаунт).
func insertBindingWithTarget(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	id domain.AccessBindingID, uid domain.UserID, accID string, tgt domain.AccessTarget) (domain.AccessBinding, error) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, ierr := bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID: id, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: accID,
		Target: tgt,
	})
	if ierr != nil {
		_ = w.Rollback(ctx)
		return domain.AccessBinding{}, ierr
	}
	return out, w.Commit(ctx)
}

// TestAB_IAM_1_29_ReGrantWithTarget_Race — конкурентные одинаковые выдачи с
// пообъектной целью сталкиваются на расширенном UNIQUE действующих выдач (субъект,
// роль, область, target_digest); после отзыва такая же повторная выдача — НОВАЯ
// ACTIVE-строка.
func TestAB_IAM_1_29_ReGrantWithTarget_Race(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-tgt-race")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-tgt-race", uid)
	accID := string(acc.ID)

	tgt := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-race1"}}}

	// ── Фаза 1: конкурентные одинаковые Create (та же цель) → один победитель ─
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
			_, ierr := insertBindingWithTarget(t, ctx, repo, id, uid, accID, tgt)
			out <- res{id, ierr}
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
	require.Equal(t, 1, successes, "exactly one identical (subject,role,scope,target) Create wins")
	assert.Equal(t, goroutines-1, already, "losers get ALREADY_EXISTS (partial UNIQUE incl. target_digest)")
	assert.Equal(t, 0, other, "no unexpected errors / panics")

	// ── Фаза 2: отзыв победителя ──────────────────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().RevokeGuarded(ctx, winner, uid)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// ── Фаза 3: такая же повторная выдача — НОВАЯ ACTIVE-строка ───────────
	regrantID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	regranted, err := insertBindingWithTarget(t, ctx, repo, regrantID, uid, accID, tgt)
	require.NoError(t, err, "re-grant after revoke must succeed — revoked row frees the slot")
	assert.NotEqual(t, winner, regranted.ID, "re-grant is a distinct new ACTIVE binding id")
	assert.Equal(t, domain.AccessBindingStatusActive, regranted.Status)
	// цель проходит туда и обратно через колонку базы.
	require.Len(t, regranted.Target.Resources, 1)
	assert.Equal(t, "compute.instance", regranted.Target.Resources[0].Type)
	assert.Equal(t, "ins-race1", regranted.Target.Resources[0].ID)
}

// TestAB_IAM_1_29_DistinctTargets_Coexist — НОВОЕ измерение F8: тот же субъект,
// роль и область с РАЗНЫМИ целями НЕ сталкиваются (отпечатки различны), а выдача
// allInScope на весь якорь — ещё одно отдельное место ("all").
func TestAB_IAM_1_29_DistinctTargets_Coexist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (needs Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "iam1-29-tgt-coexist")
	acc := seedAccount(t, ctx, repo, "acc-iam1-29-tgt-coexist", uid)
	accID := string(acc.ID)

	// пообъектная ins-1, пообъектная ins-2 и allInScope на весь якорь — три разных
	// target_digest → три сосуществующие ACTIVE-строки.
	_, e1 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-1"}}})
	require.NoError(t, e1)

	_, e2 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-2"}}})
	require.NoError(t, e2, "a DISTINCT per-object target must NOT collide with ins-1")

	_, e3 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{AllInScope: true})
	require.NoError(t, e3, "the whole-anchor allInScope grant is a distinct slot ('all')")

	// а ДУБЛЬ ins-1 сталкивается.
	_, e4 := insertBindingWithTarget(t, ctx, repo,
		domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), uid, accID,
		domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "ins-1"}}})
	require.Error(t, e4)
	assert.True(t, stderrors.Is(e4, iamerr.ErrAlreadyExists), "identical target collides (ALREADY_EXISTS)")
}
