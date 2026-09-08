// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_lockfree_integration_test.go — окно материализации создания НЕ
// ЗАНИМАЕТ ОЧЕРЕДЬ за фоновым полным проходом того же биндинга.
//
// ЧТО ЭТО ЗА СВОЙСТВО И ПОЧЕМУ ОНО ОТДЕЛЬНОЕ. Соседний файл уже утверждает, что N
// форвардов ОДНОГО биндинга идут параллельно друг другу (SHARE ∥ SHARE), и что
// форвард с полным проходом не роняют друг друга в 40P01. Ни то, ни другое не
// говорит про ОЖИДАНИЕ: пока полный проход держит EXCLUSIVE-advisory, форвард
// стоит в очереди, и оба прежних утверждения остаются зелёными — они смотрят на
// исход, а не на срок. Между тем срок здесь и есть предмет: форвард существует
// ровно затем, чтобы созданный ресурс был виден создателю раньше клиентского
// бюджета чтения-своих-записей.
//
// ЗАМЕР, ИЗ КОТОРОГО ПРОБА ВЫВЕДЕНА (тёплый 12-ядерный стенд, волна vpc+compute+nlb,
// выборка pg_stat_activity раз в 5 с): 99 наблюдений бэкенда, ждущего
// `pg_advisory_xact_lock_shared` — это и есть форвард пути создания — среднее
// ожидание 0.88 с, максимум 4.6 с; ещё 40 наблюдений ждали EXCLUSIVE. На ранере
// вчетверо меньшей мощности те же ожидания растягиваются за клиентские бюджеты, и
// создатель получает отказ на СВОЙ свежий ресурс.
//
// ФОРМА ПРОБЫ. Полный проход эмулируется ЕГО ЖЕ кодом — первыми двумя стейтментами
// писательской транзакции (`AcquireBindingLock` + `LoadBinding`), а не рукописным
// SQL: если режимы блокировок в продукте изменятся, проба поедет за ними, а не
// останется описывать прошлое. Держатель не отпускает транзакцию, пока форвард не
// ответил, поэтому «успел» здесь означает «не ждал», а не «дождался».
//
// Парный положительный контроль (иначе отрицание зеленело бы на сломанном): тот же
// форвард БЕЗ держателя обязан материализовать объект — то есть проба умеет
// отличить «не ждёт» от «ничего не делает».

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// forwardLockFreeBudget — сколько форварду даётся на проход, пока полный проход
// держит биндинг. Щедро относительно здорового прохода (единицы-десятки
// миллисекунд на пустой базе) и заведомо меньше срока держателя ниже, поэтому
// исчерпание бюджета означает ровно очередь, а не медленную машину.
const forwardLockFreeBudget = 3 * time.Second

// forwardLockFreeHold — сколько держатель заведомо не отпускает биндинг. Больше
// бюджета форварда, иначе проба могла бы «пройти» просто потому, что держатель
// успел закончиться сам.
const forwardLockFreeHold = 8 * time.Second

func TestReconcileForward_07_DoesNotQueueBehindInFlightFullPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "fwd7")
	rec, adapter := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "fwd7role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "iHeld", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iFree", string(fx.prj), string(fx.accID), nil, now)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: без держателя форвард материализует объект ──────
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "iFree"))
	subj := "user:" + string(fx.member)
	require.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:iFree"),
		"контроль: форвард без держателя обязан материализовать объект — иначе проба ниже "+
			"утверждала бы «не ждёт» о проходе, который ничего не делает")

	// ── ДЕРЖАТЕЛЬ: полный проход в полёте на ТОМ ЖЕ биндинге ───────────────────
	held := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
			// Ровно первые два стейтмента писательской транзакции полного прохода.
			if err := s.AcquireBindingLock(ctx, bid); err != nil {
				return err
			}
			if _, _, err := s.LoadBinding(ctx, bid); err != nil {
				return err
			}
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	defer func() { close(release); wg.Wait() }()

	// ── УТВЕРЖДЕНИЕ: форвард проходит, НЕ дожидаясь держателя ─────────────────
	fctx, cancel := context.WithTimeout(ctx, forwardLockFreeBudget)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rec.ReconcileObjectForward(fctx, "compute.instance", "iHeld") }()

	select {
	case err := <-done:
		require.NoError(t, err, "форвард обязан пройти при живом полном проходе того же биндинга")
	case <-time.After(forwardLockFreeBudget + time.Second):
		t.Fatalf("форвард пути создания встал в очередь за фоновым полным проходом "+
			"(бюджет %s исчерпан): окно видимости своего свежего ресурса определяется "+
			"не работой форварда, а сроком чужой транзакции", forwardLockFreeBudget)
	}

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iHeld")
	require.True(t, ok, "объект материализован, а не просто «не упал»")
	assert.Equal(t, domain.VerificationActive, st)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bid, subj, "v_update", "compute_instance:iHeld"),
		"пер-объектный грант создателя виден сразу, не по завершении чужого прохода")

	_ = forwardLockFreeHold // держатель живёт до defer-release, который позже бюджета
}
