// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_object_pass_lock_order_world_integration_test.go — снятие
// регистрации объекта и полный проход материализации по этому объекту берут
// замки в одном порядке (PRO-Robotech/kaname#974).
//
// # Предмет
//
// Снятие регистрации запирает выдачи, чья цель называет ключ, и роли, чьи
// правила называют его в `resourceNames`; проход по объекту запирает выдачи
// веера и их роли. Когда у сторон разный порядок родов — снятие пишет строку
// снятия общего факта раньше, чем берёт роль, а проход берёт роль раньше, чем
// пишет тот же факт, — возникает кольцо ожидания: Postgres снимает одну из
// сторон отказом взаимной блокировки (SQLSTATE 40P01). Корректность держится
// откатом и повтором, но работа делается дважды, а отказ уезжает вызывающему.
//
// # Фикстура кольца
//
// Ключ K, человек usr-D и ДВЕ выдачи с одним фактом `v_get` на K:
//   - B1 — роль чтения реестров, цель «только K», материализована: факт есть,
//     его держит реестр выпущенного B1;
//   - B2 — роль R2, правило которой называет K в `resourceNames`, область —
//     проект; не материализована: у неё нет члена на K, и проход по объекту
//     впервые пишет ей член и тот же факт.
//
// Снятие отзывает B1 (её цель — только K) и вычёркивает K из правил R2; проход
// по объекту сверяет обе выдачи. Кольцо замыкается, когда проход сверяет B2
// РАНЬШЕ B1 — порядок веера задаёт id, поэтому фикстура перебирает ключи, пока
// id B2 не окажется меньше id B1 (`orderedRingFixture`).
//
// # Что утверждается
//
// Проба с удержанием (`TestUnregisterVsObjectPass_HeldPassNoDeadlock`) держит
// проход на первой записи члена B2 — выдачи и роли он уже прочитал — и в эту
// паузу снимает регистрацию. Отпускание прохода не даёт отказа ни одной
// стороне. Конкурентная проба (`TestUnregisterVsObjectPass_ConcurrentNoDeadlock`)
// запускает обе стороны одновременно `uoRaceIterations` раз подряд без
// удержания: отказов 40P01 ноль. Исход каждого повтора сверяется с исходом
// последовательного выполнения (`TestUnregisterVsObjectPass_SequentialTwin` —
// законный близнец той же фикстуры): B1 отозвана по снятию, R2 не называет K,
// у B2 нет члена на K, прямого факта usr-D на K нет, решение отказывает.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// uoRaceIterations — число повторов конкурентной пробы.
const uoRaceIterations = 20

// ringFixture — одна фикстура кольца на своём ключе.
type ringFixture struct {
	key    string
	b1, b2 string        // b1 — цель «только K»; b2 — роль R2 с именем K
	r2     domain.RoleID // роль, правило которой называет K
}

// ringFixtureOn — фикстура кольца на ключе `key` (см. шапку). Положительный
// контроль: факт usr-D на K есть до гонки, у B2 нет члена на K.
func (w *urxWorld) ringFixtureOn(key string) ringFixture {
	w.t.Helper()
	w.registerRegistry(key)
	b1 := w.grantTo(w.usrD, w.rolRegGet, urTarget(key), false, "974: выдача B1 на K")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, key, true, "974 контроль фикстуры: B1 материализована в v_get на K")
	r2 := w.seedRole("uo_names_"+key, domain.Rules{namesRule(key)})
	b2 := w.unmaterializedGrant(r2, ndAllInScope(), "974: выдача B2 роли с именем K")
	require.Zerof(w.t, w.membersOn(b2, key), "974 контроль фикстуры: у B2 уже есть член на %s", key)
	require.NotZerof(w.t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "974 контроль фикстуры: факта usr-D на %s нет", key)
	return ringFixture{key: key, b1: b1, b2: b2, r2: r2}
}

// orderedRingFixture — фикстура кольца, в которой проход по объекту сверяет B2
// раньше B1 (id B2 меньше id B1). id случайны, поэтому перебираются ключи.
func (w *urxWorld) orderedRingFixture(base int) ringFixture {
	w.t.Helper()
	for i := 0; i < 20; i++ {
		fx := w.ringFixtureOn(raceKey(base, i))
		if fx.b2 < fx.b1 {
			return fx
		}
	}
	w.t.Fatal("ПРЕДПОСЫЛКА 974: за 20 ключей id B2 ни разу не оказался меньше id B1")
	return ringFixture{}
}

// judgeRingOutcome — исход последовательного выполнения (шапка, «Что утверждается»).
func (w *urxWorld) judgeRingOutcome(fx ringFixture, why string) {
	w.t.Helper()
	b1 := w.get(fx.b1)
	assert.Equalf(w.t, iamv1.AccessBinding_REVOKED, b1.GetStatus(), "%s: B1 на снятый %s не отозвана", why, fx.key)
	assert.Equalf(w.t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b1.GetRevocationReason(),
		"%s: причина отзыва B1", why)
	names, ok := w.roleNames(fx.r2)
	require.Truef(w.t, ok, "%s: роли R2 нет", why)
	assert.NotContainsf(w.t, names, fx.key, "%s: R2 называет снятый %s", why, fx.key)
	assert.Zerof(w.t, w.membersOn(fx.b2, fx.key), "%s: член B2 на снятом %s", why, fx.key)
	assert.Zerof(w.t, w.factsOf(w.usr(w.usrD), pcrRegType, fx.key), "%s: прямой факт usr-D на снятом %s", why, fx.key)
	assert.Falsef(w.t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, fx.key), "%s: usr-D читает снятый %s", why, fx.key)
}

// isDeadlockRefusal — отказ взаимной блокировки: сырой 40P01 прохода либо его
// отображение у снятия (класс «конфликт параллельной правки», ErrAborted).
func isDeadlockRefusal(err error) bool {
	if err == nil {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
		return true
	}
	return errors.Is(err, iamerr.ErrAborted) || strings.Contains(err.Error(), "40P01")
}

// objectPassHold — исполнитель транзакций реконсайлера, держащий полный проход
// по объекту на первой записи члена выдачи `binding`.
type objectPassHold struct {
	reconcile.TxRunner
	binding  domain.AccessBindingID
	p        pause
	mu       sync.Mutex
	finished chan struct{}
}

func (h *objectPassHold) arm(binding string) (reached, finished <-chan struct{}, release func()) {
	h.mu.Lock()
	h.binding = domain.AccessBindingID(binding)
	h.finished = make(chan struct{})
	finished = h.finished
	h.mu.Unlock()
	reached, release = h.p.arm()
	return reached, finished, release
}

func (h *objectPassHold) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	h.mu.Lock()
	finished, binding := h.finished, h.binding
	h.finished = nil
	h.mu.Unlock()
	if finished == nil {
		return h.TxRunner.WithTx(ctx, fn)
	}
	defer close(finished)
	return h.TxRunner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &memberHoldStore{ReconcileStore: s, binding: binding, p: &h.p})
	})
}

type memberHoldStore struct {
	reconcile.ReconcileStore
	binding domain.AccessBindingID
	p       *pause
}

func (s *memberHoldStore) UpsertMember(ctx context.Context, m domain.TargetMember) error {
	if m.BindingID == s.binding {
		s.p.hit()
	}
	return s.ReconcileStore.UpsertMember(ctx, m)
}

// awaitStalledOrDone — ждёт, пока снятие либо встанет на замке (в базе мира есть
// обслуживающий процесс, которого держит другой), либо закончится. В отличие от
// awaitBlockedOrDone исход закончившегося снятия возвращается, а не утверждается:
// отказ здесь — предмет пробы, а не сбой фикстуры.
func awaitStalledOrDone(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error) (blocked bool, err error) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return false, err
		default:
		}
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity
			  WHERE datname = current_database() AND wait_event_type = 'Lock'
			    AND cardinality(pg_blocking_pids(pid)) > 0`).Scan(&n))
		if n > 0 {
			return true, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("снятие ни встало на замке, ни закончилось за 20 с")
	return false, nil
}

// TestUnregisterVsObjectPass_HeldPassNoDeadlock — проход по объекту прочитал
// выдачи и роли и стоит на первой записи члена B2; снятие регистрации идёт в эту
// паузу. После отпускания обе стороны завершаются без отказа, исход — тот же,
// что при последовательном выполнении.
func TestUnregisterVsObjectPass_HeldPassNoDeadlock(t *testing.T) {
	w := newURXWorld(t)
	fx := w.orderedRingFixture(9000)
	hold := &objectPassHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	rec := reconcile.New(hold, nil, catalog.Fixed{F: w.facts})
	reached, finished, release := hold.arm(fx.b2)
	pass := make(chan error, 1)
	go func() { pass <- rec.ReconcileObject(w.ctx, pcrRegTgt, fx.key) }()

	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("974: проход по объекту не дошёл до записи члена B2")
	}
	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, fx.key) }()
	blocked, unregErr := awaitStalledOrDone(t, w.ctx, w.pool, done)
	release()
	passErr := <-pass
	<-finished
	if blocked {
		unregErr = <-done
	}
	t.Logf("974 удержание: снятие встало на замке: %v; отказ снятия: %v; отказ прохода: %v", blocked, unregErr, passErr)

	assert.Falsef(t, isDeadlockRefusal(unregErr), "974: снятие регистрации получило отказ взаимной блокировки: %v", unregErr)
	assert.Falsef(t, isDeadlockRefusal(passErr), "974: проход по объекту получил отказ взаимной блокировки: %v", passErr)
	require.NoError(t, unregErr, "974: снятие регистрации")
	require.NoError(t, passErr, "974: проход по объекту")
	w.judgeRingOutcome(fx, "974 удержание")
}

// TestUnregisterVsObjectPass_SequentialTwin — законный близнец: та же фикстура,
// проход по объекту закончился до снятия.
func TestUnregisterVsObjectPass_SequentialTwin(t *testing.T) {
	w := newURXWorld(t)
	fx := w.orderedRingFixture(9100)
	require.NoError(t, w.rec.ReconcileObject(w.ctx, pcrRegTgt, fx.key), "974 близнец: проход по объекту")
	require.NotZero(t, w.membersOn(fx.b2, fx.key), "974 близнец контроль: проход записал член B2 на K")
	w.withdraw(w.ctx, fx.key)
	w.judgeRingOutcome(fx, "974 близнец")
}

// TestUnregisterVsObjectPass_ConcurrentNoDeadlock — снятие регистрации и проход
// по тому же объекту одновременно, `uoRaceIterations` раз подряд, каждый повтор
// на своём ключе: отказов взаимной блокировки ноль, исход каждого повтора — как у
// последовательного выполнения.
func TestUnregisterVsObjectPass_ConcurrentNoDeadlock(t *testing.T) {
	w := newURXWorld(t)
	var deadlocks int
	for i := 0; i < uoRaceIterations; i++ {
		fx := w.ringFixtureOn(raceKey(9200, i))
		var wg sync.WaitGroup
		var passErr, unregErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; passErr = w.rec.ReconcileObject(w.ctx, pcrRegTgt, fx.key) }()
		go func() { defer wg.Done(); <-start; unregErr = w.withdrawErr(w.ctx, fx.key) }()
		close(start)
		wg.Wait()
		for _, e := range []error{passErr, unregErr} {
			if isDeadlockRefusal(e) {
				deadlocks++
				t.Errorf("974 #%d (%s): отказ взаимной блокировки: %v", i, fx.key, e)
			}
		}
		if unregErr != nil {
			require.NoErrorf(t, w.withdrawErr(w.ctx, fx.key), "974 #%d: повтор снятия после отказа", i)
		}
		w.judgeRingOutcome(fx, fmt.Sprintf("974 #%d", i))
	}
	t.Logf("974: повторов %d · отказов 40P01 %d", uoRaceIterations, deadlocks)
	assert.Zero(t, deadlocks, "974: отказы взаимной блокировки")
}
