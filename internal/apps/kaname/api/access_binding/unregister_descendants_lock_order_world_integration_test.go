// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_descendants_lock_order_world_integration_test.go — снятие родителя
// вместе с потомками берёт замки в порядке kaname#975 (PRO-Robotech/kaname#1019).
//
// # Предмет
//
// Снятие регистрации родителя снимает и его потомков (kaname#1002). Порядок родов
// у снятия и у прохода материализации обязан быть один: выдачи, роли, строки
// зеркала, факты. Прежде снятие запирало выдачи родителя, писало его факты и лишь
// потом, уже у каждого потомка, снимало строку зеркала и запирало выдачи потомка.
// Проход по потомку запирает выдачи своего веера одним оператором в порядке id —
// и когда в его веере выдача потомка стоит раньше выдачи, названной родителем,
// стороны сходятся в кольцо: снятие держит выдачу родителя и ждёт выдачу
// потомка, проход держит выдачу потомка и ждёт выдачу родителя. Postgres снимает
// одну сторону отказом 40P01.
//
// # Фикстура кольца
//
// Реестр P, под ним репозиторий P/app, человек usr-D и ДВЕ выдачи, обе
// материализованы на P/app одним общим фактом `v_get`:
//   - B1 — роль чтения репозиториев, цель «только P/app» (называет потомка);
//   - BX — роль с вложенным правилом над репозиториями, цель «только P» (называет
//     родителя; её член на P/app выведен вложенным правилом).
//
// Проход по P/app сверяет обе (обе — в веере объекта). Кольцо замыкается, когда
// id B1 меньше id BX: проход берёт B1 первой. id случайны, поэтому фикстура
// перебирает ключи (`orderedDescendantRing`).
//
// # Что утверждается
//
// Проба с удержанием (`…_HeldUnregisterNoDeadlock`) останавливает снятие перед
// первой записью (замки выдач и ролей взяты), в эту паузу запускает проход по P/app и ждёт, пока он
// встанет на замке; затем снятие отпускается. Ни одна сторона не получает отказа,
// исход — как у последовательного выполнения. Конкурентная проба
// (`…_ConcurrentNoDeadlock`) запускает обе стороны одновременно `dlRaceIterations`
// раз подряд без удержания: отказов 40P01 ноль. Законный близнец
// (`…_SequentialTwin`) — та же фикстура без гонки: родитель и потомок сняты, обе
// выдачи отозваны, прямого факта нет, а проход по живому объекту соседнего реестра
// пишет его член, как прежде.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// dlRaceIterations — число повторов конкурентной пробы.
const dlRaceIterations = 20

// dlRepoTgt — тип репозитория словарём каталога (цель прохода по объекту).
const dlRepoTgt = "registry.repositories"

// descendantRing — одна фикстура кольца на своём реестре.
type descendantRing struct {
	parent, child string // реестр P и репозиторий P/app
	b1, bx        string // b1 называет потомка; bx — родителя (вложенное правило)
}

// descendantRingWorld — мир П3-У (вложенные правила) с ролями фикстуры кольца.
type descendantRingWorld struct {
	*cascadeWorld
	roleRepo, roleNested domain.RoleID
}

func newDescendantRingWorld(t *testing.T) *descendantRingWorld {
	t.Helper()
	w := &descendantRingWorld{cascadeWorld: &cascadeWorld{urxWorld: newP3UWorld(t)}}
	w.roleRepo = w.seedRole("dl_repo_get",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	w.roleNested = w.seedRole("dl_nested", pcrWithChild(pcrRepositoriesRule()))
	return w
}

// ringOn — фикстура кольца на реестре `parent` (см. шапку). Положительный
// контроль: обе выдачи материализованы на P/app, общий факт usr-D стоит.
func (w *descendantRingWorld) ringOn(parent string) descendantRing {
	w.t.Helper()
	w.registerRegistry(parent)
	w.registerRepository(parent, "app")
	child := parent + "/app"
	b1 := w.grantTo(w.usrD, w.roleRepo, repoTarget(child), false, "1019: выдача B1 на потомка")
	bx := w.grantTo(w.usrD, w.roleNested, urTarget(parent), false, "1019: выдача BX на родителя")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRepoType, child, true, "1019 контроль фикстуры: usr-D не читает потомка")
	// Члены выдач пишет проход материализации после создания выдачи; ответ о
	// доступе выше даёт уже одна B1, поэтому член BX ждётся отдельно.
	w.pollMember(b1, child, "1019 контроль фикстуры: у B1 нет члена на "+child)
	w.pollMember(bx, child, "1019 контроль фикстуры: у BX нет члена на "+child+" (вложенное правило)")
	require.NotZerof(w.t, w.factsOf(w.usr(w.usrD), pcrRepoType, child), "1019 контроль фикстуры: общего факта usr-D на %s нет", child)
	return descendantRing{parent: parent, child: child, b1: b1, bx: bx}
}

// pollMember — ждёт член выдачи `binding` на объекте `objectID` не дольше 15 с.
func (w *descendantRingWorld) pollMember(binding, objectID, why string) {
	w.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for w.membersOn(binding, objectID) == 0 {
		if time.Now().After(deadline) {
			w.t.Fatal(why)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// orderedDescendantRing — фикстура, в которой проход по потомку берёт B1 раньше
// BX (id B1 меньше id BX). id случайны, поэтому перебираются реестры.
func (w *descendantRingWorld) orderedDescendantRing(base int) descendantRing {
	w.t.Helper()
	for i := 0; i < 20; i++ {
		fx := w.ringOn(raceKey(base, i))
		if fx.b1 < fx.bx {
			return fx
		}
	}
	w.t.Fatal("ПРЕДПОСЫЛКА 1019: за 20 реестров id B1 ни разу не оказался меньше id BX")
	return descendantRing{}
}

// judgeDescendantRing — исход последовательного выполнения: родитель и потомок
// сняты, обе выдачи отозваны снятием, прямого факта usr-D на потомке нет.
func (w *descendantRingWorld) judgeDescendantRing(fx descendantRing, why string) {
	w.t.Helper()
	assert.Falsef(w.t, w.registered(pcrRegType, fx.parent), "%s: регистрация родителя %s осталась", why, fx.parent)
	assert.Falsef(w.t, w.registered(pcrRepoType, fx.child), "%s: регистрация потомка %s осталась", why, fx.child)
	for name, id := range map[string]string{"B1": fx.b1, "BX": fx.bx} {
		b := w.get(id)
		assert.Equalf(w.t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "%s: %s не отозвана", why, name)
		assert.Equalf(w.t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(),
			"%s: причина отзыва %s", why, name)
	}
	assert.Zerof(w.t, w.factsOf(w.usr(w.usrD), pcrRepoType, fx.child), "%s: прямой факт usr-D на снятом %s", why, fx.child)
	assert.Falsef(w.t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, fx.child), "%s: usr-D читает снятого потомка %s", why, fx.child)
}

// withdrawWith — снятие регистрации реестра `id` данным use-case своей версией.
func (w *urxWorld) withdrawWith(ctx context.Context, uc *internaliam.RegisterResourceUseCase, id string) error {
	w.verMu.Lock()
	ver := w.nextVersion()
	w.verMu.Unlock()
	return uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project",
		Object: pcrRegType + ":" + id, SourceVersion: ver,
	})
}

// mirrorHold — порт зеркала снятия с двумя точками удержания; каждая срабатывает
// один раз, по заряду:
//   - beforeDelete — снятие стоит перед удалением строки зеркала родителя, то
//     есть перед первой записью транзакции: замки выдач и ролей уже взяты;
//   - afterDescendants — снятие прочитало перечень потомков и ещё не сняло ни
//     одного из них.
//
// Точки удержания стоят на порте зеркала, а не на порте отзыва: порядок вызовов
// зеркала у снятия до правки и после неё один (удаление строки родителя — первая
// запись, чтение потомков — до снятия первого потомка), поэтому одна и та же проба
// исполняется на обеих ревизиях.
type mirrorHold struct {
	*kanamepg.ResourceMirrorEmitter
	beforeDelete, afterDescendants pause
}

func (h *mirrorHold) DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) (bool, error) {
	h.beforeDelete.hit()
	return h.ResourceMirrorEmitter.DeleteTx(ctx, tx, objectType, objectID, tombstone)
}

func (h *mirrorHold) DescendantsTx(ctx context.Context, tx service.Tx, parentType, parentID string) ([]service.RegisteredDescendant, error) {
	out, err := h.ResourceMirrorEmitter.DescendantsTx(ctx, tx, parentType, parentID)
	if err == nil {
		h.afterDescendants.hit()
	}
	return out, err
}

// heldRegister — use-case снятия мира поверх удерживающего порта зеркала.
func (w *urxWorld) heldRegister() (*internaliam.RegisterResourceUseCase, *mirrorHold) {
	hold := &mirrorHold{ResourceMirrorEmitter: kanamepg.NewResourceMirrorEmitter()}
	return internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		hold,
		kanamepg.NewPoolTxBeginner(w.pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	), hold
}

// TestUnregisterDescendantsVsObjectPass_HeldUnregisterNoDeadlock — снятие P
// взяло замки выдач и ролей и стоит перед первой записью; проход по потомку P/app
// идёт в эту паузу и встаёт на замке. После отпускания обе стороны завершаются без
// отказа, исход — тот же, что при последовательном выполнении.
func TestUnregisterDescendantsVsObjectPass_HeldUnregisterNoDeadlock(t *testing.T) {
	w := newDescendantRingWorld(t)
	fx := w.orderedDescendantRing(19000)
	uc, hold := w.heldRegister()
	reached, release := hold.beforeDelete.arm()
	done := make(chan error, 1)
	go func() { done <- w.withdrawWith(w.ctx, uc, fx.parent) }()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("1019: снятие закончилось, не дойдя до удержания: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("1019: снятие не дошло до первой записи")
	}
	pass := make(chan error, 1)
	go func() { pass <- w.rec.ReconcileObject(w.ctx, dlRepoTgt, fx.child) }()
	blocked, passErr := awaitStalledOrDone(t, w.ctx, w.pool, pass)
	release()
	unregErr := <-done
	if blocked {
		passErr = <-pass
	}
	t.Logf("1019 удержание: проход встал на замке: %v; отказ снятия: %v; отказ прохода: %v", blocked, unregErr, passErr)

	assert.Falsef(t, isDeadlockRefusal(unregErr), "1019: снятие родителя получило отказ взаимной блокировки: %v", unregErr)
	assert.Falsef(t, isDeadlockRefusal(passErr), "1019: проход по потомку получил отказ взаимной блокировки: %v", passErr)
	require.NoError(t, unregErr, "1019: снятие родителя")
	require.NoError(t, passErr, "1019: проход по потомку")
	w.judgeDescendantRing(fx, "1019 удержание")
}

// TestUnregisterDescendantsVsObjectPass_SequentialTwin — законный близнец: та же
// фикстура, проход по потомку закончился до снятия родителя. Проход по живому
// объекту соседнего реестра снятием не затронут.
func TestUnregisterDescendantsVsObjectPass_SequentialTwin(t *testing.T) {
	w := newDescendantRingWorld(t)
	fx := w.orderedDescendantRing(19100)
	live := w.ringOn(raceKey(19150, 0))

	require.NoError(t, w.rec.ReconcileObject(w.ctx, dlRepoTgt, fx.child), "1019 близнец: проход по потомку")
	require.NoError(t, w.withdrawErr(w.ctx, fx.parent), "1019 близнец: снятие родителя")

	w.judgeDescendantRing(fx, "1019 близнец")
	require.NoError(t, w.rec.ReconcileObject(w.ctx, dlRepoTgt, live.child), "1019 близнец: проход по живому объекту")
	assert.Truef(t, w.registered(pcrRepoType, live.child), "1019 близнец: регистрация живого %s снята", live.child)
	for name, id := range map[string]string{"B1": live.b1, "BX": live.bx} {
		assert.Equalf(t, iamv1.AccessBinding_ACTIVE, w.get(id).GetStatus(), "1019 близнец: %s живого объекта не ACTIVE", name)
		assert.NotZerof(t, w.membersOn(id, live.child), "1019 близнец: член %s на живом %s снят", name, live.child)
	}
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, live.child), "1019 близнец: usr-D не читает живой объект")
}

// TestUnregisterDescendantsVsObjectPass_ConcurrentNoDeadlock — снятие родителя и
// проход по потомку одновременно, `dlRaceIterations` раз подряд, каждый повтор на
// своём реестре: отказов взаимной блокировки ноль, обе стороны успешны, исход —
// как у последовательного выполнения.
func TestUnregisterDescendantsVsObjectPass_ConcurrentNoDeadlock(t *testing.T) {
	w := newDescendantRingWorld(t)
	var deadlocks, failures int
	for i := 0; i < dlRaceIterations; i++ {
		fx := w.orderedDescendantRing(19200 + i*20)
		var wg sync.WaitGroup
		var passErr, unregErr error
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; passErr = w.rec.ReconcileObject(w.ctx, dlRepoTgt, fx.child) }()
		go func() { defer wg.Done(); <-start; unregErr = w.withdrawErr(w.ctx, fx.parent) }()
		close(start)
		wg.Wait()
		for side, e := range map[string]error{"проход": passErr, "снятие": unregErr} {
			if isDeadlockRefusal(e) {
				deadlocks++
				t.Errorf("1019 #%d (%s), %s: отказ взаимной блокировки: %v", i, fx.parent, side, e)
			} else if e != nil {
				failures++
				t.Errorf("1019 #%d (%s), %s: отказ: %v", i, fx.parent, side, e)
			}
		}
		if unregErr != nil {
			require.NoErrorf(t, w.withdrawErr(w.ctx, fx.parent), "1019 #%d: повтор снятия после отказа", i)
		}
		w.judgeDescendantRing(fx, fmt.Sprintf("1019 #%d", i))
	}
	t.Logf("1019: повторов %d · отказов 40P01 %d · прочих отказов %d", dlRaceIterations, deadlocks, failures)
	assert.Zero(t, deadlocks, "1019: отказы взаимной блокировки")
	assert.Zero(t, failures, "1019: прочие отказы сторон")
}
