// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// register_resource_detached_forward_test.go — пост-коммитный форвард переживает
// отмену ВЫЗЫВАЮЩЕГО.
//
// ПРЕДМЕТ. RegisterResource зовут кросс-сервисные синхронные регистраторы
// (services/<svc>/internal/clients/iam_sync_registrar.go), и у них per-call deadline
// 5 с. Форвард исполнялся на КОНТЕКСТЕ ЗАПРОСА, поэтому истечение этого дедлайна
// отменяло не только ответ вызывающему, но и саму материализацию: под конкуренцией
// замер дал 121 отказ forward с `context canceled`, и невидимыми оставались РОВНО
// отменённые объекты (p95 окна 82.6 с при клиентском бюджете чтения-своих-записей
// 12.5 с; 106 из 300 первых чтений создателем — отказ).
//
// ПОЧЕМУ ОТВЯЗКА ЗАКОННА. Форвард — УСКОРИТЕЛЬ, а не источник истины: всё, что он
// материализует, уже закоммичено в writer-tx вызывающего (owner-tuple, строка
// зеркала, событие реконсайла), и at-least-once дренаж с реконсайлером сходятся к
// тому же состоянию. Отвязка меняет, КОГДА работа наблюдается, а не ВЫПОЛНЯЕТСЯ ли
// она — ровно то же обоснование, что записано в shared/postcommit.go.
//
// ЧТО ЭТО НЕ ЕСТЬ. Это НЕ барьер на видимость (ban #9): `Operation.done` у
// вызывающего по-прежнему не ждёт материализации, а сам Register остаётся
// нефатальным к отказу форварда — VBC-15 продолжает это утверждать.
//
// ГРАНИЦА. Отвязывается ОТМЕНА, но не время: у форварда собственный конечный бюджет,
// иначе повисший на блокировке проход держал бы горутину всю жизнь процесса
// (architecture.md — per-call deadline на каждом внешнем вызове).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dfRecon — реконсайлер, который ДОКЛАДЫВАЕТ о состоянии полученного контекста:
// отменён ли он и остался ли у него дедлайн. Именно эти два факта и составляют
// предмет пробы, поэтому они снимаются внутри самого прохода, а не снаружи.
type dfRecon struct {
	sawCanceled bool
	sawDeadline bool
	deadlineIn  time.Duration
	calls       int
}

func (r *dfRecon) ReconcileObjectForward(ctx context.Context, _, _ string) error {
	r.calls++
	r.sawCanceled = ctx.Err() != nil
	if dl, ok := ctx.Deadline(); ok {
		r.sawDeadline = true
		r.deadlineIn = time.Until(dl)
	}
	return nil
}

func (r *dfRecon) ReconcileObjectForwardNoStale(ctx context.Context, t, id string) error {
	return r.ReconcileObjectForward(ctx, t, id)
}

// TestRegisterResource_ForwardSurvivesCallerCancellation — вызывающий отменил запрос
// (истёк его per-call deadline), а материализация обязана состояться.
//
// КРАСНАЯ, пока форвард исполняется на контексте запроса: он получает уже отменённый
// ctx и падает `context canceled`, то есть объект остаётся невидимым своему создателю
// до асинхронного дренажа.
func TestRegisterResource_ForwardSurvivesCallerCancellation(t *testing.T) {
	rec := &dfRecon{}
	txb := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb, seededCatalogTypes{}).WithObjectReconciler(rec, nil)

	// Ровно та ситуация, что на стенде: дедлайн вызывающего истёк к моменту, когда
	// writer-tx уже закоммичен и очередь дошла до пост-коммитного прохода.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := uc.Register(ctx, &regReq{subject: "user:usr_creator", relation: "v_get", object: "vpc_network:vpcn_detached"})

	require.NoError(t, err, "отказ форварда не фатален — этого VBC-15 и требует")
	require.True(t, txb.tx.committed, "writer-tx коммитится независимо от отмены")

	require.Equal(t, 1, rec.calls, "пост-коммитный проход обязан состояться ровно один раз")
	assert.False(t, rec.sawCanceled,
		"форвард получил ОТМЕНЁННЫЙ контекст вызывающего — материализация не состоится, "+
			"и создатель не увидит свой свежий объект до асинхронного дренажа")
	assert.True(t, rec.sawDeadline,
		"у отвязанного прохода обязан остаться СВОЙ конечный бюджет: без него повисший "+
			"на блокировке проход держал бы горутину всю жизнь процесса")
}

// TestRegisterResource_DetachedForwardKeepsItsOwnBudget — отвязка снимает ОТМЕНУ,
// а не время. Положительный контроль к предыдущей пробе: если бюджет когда-нибудь
// уберут «чтобы наверняка досчиталось», эта проба покраснеет.
func TestRegisterResource_DetachedForwardKeepsItsOwnBudget(t *testing.T) {
	rec := &dfRecon{}
	txb2 := &smTxBeginner{}
	uc := NewRegisterResourceUseCase(smEmitter{}, mirrorAdapter{}, txb2, seededCatalogTypes{}).WithObjectReconciler(rec, nil)

	// Вызывающий жив и щедр — проба смотрит не на его отмену, а на то, что бюджет
	// прохода СОБСТВЕННЫЙ, а не унаследованный.
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()

	err := uc.Register(ctx, &regReq{subject: "user:usr_creator", relation: "v_get", object: "vpc_network:vpcn_budget"})
	require.NoError(t, err)

	require.Equal(t, 1, rec.calls)
	require.True(t, rec.sawDeadline, "проход обязан нести конечный бюджет")
	// Порог заведомо ниже щедрости вызывающего (час) и заведомо выше здорового
	// прохода (миллисекунды — низкие секунды). Сравнение с самим часом предмета НЕ
	// различает: унаследованный час минус миллисекунды тоже меньше часа, и первая
	// редакция этой пробы на том и зеленела, ничего не проверяя.
	assert.Less(t, rec.deadlineIn, 10*time.Minute,
		"бюджет прохода унаследован от вызывающего — тогда щедрый вызывающий даёт "+
			"проходу право висеть сколь угодно долго")
}
