// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// bootstrap_reconciler_observability_test.go — «неисполнимый посев ВИДЕН, а не
// тих» (KAN-W5-06 приёмки KAN-WIRE-1, предмет ПР-7).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Согласователь посева объявлен незавершающим ПО КОНТРАКТУ: он повторяет
// попытку бессрочно и подъём не задерживает. На стенде, где посев исполниться
// не может — адрес почты назван, а строки личности не будет никогда, — он
// печатает `Debug` и больше ничего. Уровень `Debug` при рабочем `Info` не
// печатается ВОВСЕ, поэтому «доступ не выдан ни разу за всю жизнь стенда»
// снаружи неотличимо от «выдан на первой же попытке».
//
// Цена этой неразличимости названа приёмкой: доступ кластерного администратора
// — доступ ТОГО ЕДИНСТВЕННОГО, кто мог бы починить остальное.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЮТ ПРОБЫ, И ПОЧЕМУ ЧИСЛИТЕЛЬ СЧИТАЕТСЯ ВМЕСТЕ СО ЗНАМЕНАТЕЛЕМ
//
// Счётчик одних отказов не отличает «отказов не было» от «согласователя не было
// вовсе»: и там и там ноль. Поэтому наблюдатель получает исход КАЖДОЙ попытки —
// и удачной, и неудачной, — а «выдано» существует как полоса с самого старта, а
// не появляется вместе с первой выдачей.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingObserver — наблюдатель попыток, считающий исходы по полосам.
type recordingObserver struct {
	mu       sync.Mutex
	outcomes map[string]int
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{outcomes: map[string]int{}}
}

func (o *recordingObserver) IncBootstrapAdminAttempt(outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcomes[outcome]++
}

func (o *recordingObserver) count(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

func (o *recordingObserver) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, v := range o.outcomes {
		n += v
	}
	return n
}

// TestBootstrapReconcilerUnreachableSeedIsCounted — НЕСУЩАЯ отрицательная
// проба: посев, который не исполнится никогда, обязан быть виден счётчиком.
//
// Отличие от положительного близнеца ниже — ОДИН факт: исполнитель никогда не
// возвращает закоммиченную выдачу.
func TestBootstrapReconcilerUnreachableSeedIsCounted(t *testing.T) {
	obs := newRecordingObserver()
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		// Строки личности не будет никогда — посев неисполним.
		return BootstrapAdminResult{Skipped: true, SkipReason: "user not registered"}, nil
	}

	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{
		Interval: time.Millisecond,
		Observer: obs,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, rec.Run(ctx))

	assert.Zero(t, obs.count(BootstrapOutcomeGranted),
		"выдач не было — полоса «выдано» обязана остаться нулевой")
	assert.GreaterOrEqual(t, obs.count(BootstrapOutcomeNotRegistered), 2,
		"каждая попытка обязана дойти до наблюдателя: без знаменателя ноль выдач "+
			"неотличим от «согласователь не работал»")
}

// TestBootstrapReconcilerGrantIsCounted — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ.
//
// Без него отрицание выше зеленело бы на наблюдателе, который не считает ничего.
func TestBootstrapReconcilerGrantIsCounted(t *testing.T) {
	obs := newRecordingObserver()
	calls := 0
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		calls++
		if calls < 2 {
			return BootstrapAdminResult{Skipped: true, SkipReason: "user not registered"}, nil
		}
		return BootstrapAdminResult{Skipped: false, GrantID: "cag_x", UserID: "usr_boot"}, nil
	}

	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{
		Interval: time.Millisecond,
		Observer: obs,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, rec.Run(ctx))

	assert.Equal(t, 1, obs.count(BootstrapOutcomeGranted),
		"закоммиченная выдача обязана быть названа ровно один раз")
	assert.Equal(t, 1, obs.count(BootstrapOutcomeNotRegistered),
		"попытка, предшествовавшая выдаче, обязана быть названа своей полосой")
}

// TestBootstrapReconcilerDisabledSeedIsNamed — посев ВЫКЛЮЧЕН, и это отдельное
// состояние, а не тишина.
//
// Отличие от неисполнимого посева — ОДИН факт: причина пропуска терминальная.
// Различать обязательно: «адрес не задан» чинит оператор настройкой, а
// «личность не появилась» — регистрацией администратора, и это разные места.
func TestBootstrapReconcilerDisabledSeedIsNamed(t *testing.T) {
	obs := newRecordingObserver()
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		return BootstrapAdminResult{Skipped: true, SkipReason: "email empty"}, nil
	}

	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{
		Interval: time.Millisecond,
		Observer: obs,
	})
	require.NoError(t, rec.Run(context.Background()))

	assert.Equal(t, 1, obs.count(BootstrapOutcomeDisabled))
	assert.Zero(t, obs.count(BootstrapOutcomeGranted))
	assert.Equal(t, 1, obs.total(), "терминальный пропуск завершает петлю первой же попыткой")
}

// TestBootstrapReconcilerFailureIsCounted — отказ базы отличим от пропуска.
//
// Отличие от неисполнимого посева — ОДИН факт: исполнитель вернул ошибку, а не
// пропуск. Слив их в одну полосу оставил бы оператора без ответа на вопрос
// «стенд сломан или условие не создано».
func TestBootstrapReconcilerFailureIsCounted(t *testing.T) {
	obs := newRecordingObserver()
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		return BootstrapAdminResult{}, assert.AnError
	}

	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{
		Interval: time.Millisecond,
		Observer: obs,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	require.NoError(t, rec.Run(ctx))

	assert.GreaterOrEqual(t, obs.count(BootstrapOutcomeFailed), 2)
	assert.Zero(t, obs.count(BootstrapOutcomeGranted))
	assert.Zero(t, obs.count(BootstrapOutcomeNotRegistered),
		"отказ базы не вправе печататься полосой пропуска")
}

// TestBootstrapReconcilerWithoutObserverStillRuns — наблюдатель необязателен.
//
// Продукт обязан подниматься и там, где реестр метрик не собран: отсутствие
// наблюдателя не вправе ронять посев.
func TestBootstrapReconcilerWithoutObserverStillRuns(t *testing.T) {
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		return BootstrapAdminResult{Skipped: false, GrantID: "cag_x"}, nil
	}
	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	require.NoError(t, rec.Run(context.Background()))
}

// TestBootstrapSkipReasonsAllHaveAnOutcomeBand — отображение причины пропуска в
// полосу счётчика ПОЛНО относительно объявленного набора причин.
//
// Без этой пробы новая причина уехала бы в тишину: `observe` корзины «прочее»
// не имеет намеренно, поэтому неотображённая причина просто не считается — и
// «ноль попыток этой полосы» стало бы неотличимо от «полосы не существует».
func TestBootstrapSkipReasonsAllHaveAnOutcomeBand(t *testing.T) {
	require.NotEmpty(t, AllBootstrapSkipReasons,
		"перечень причин пуст — проба беспредметна и её молчание ничего не значит")

	bands := map[string]bool{}
	for _, o := range BootstrapOutcomes {
		bands[o] = true
	}

	for _, reason := range AllBootstrapSkipReasons {
		outcome, known := skipReasonOutcome[reason]
		assert.Truef(t, known,
			"причина пропуска %q объявлена без полосы счётчика: попытка с ней "+
				"не будет посчитана НИ В ОДНОЙ полосе", reason)
		assert.Truef(t, bands[outcome],
			"причина %q отображена в полосу %q, которой нет в перечне полос: "+
				"ряд, заводимый заранее, её не заведёт", reason, outcome)
	}

	// Обратная сторона: отображение не вправе называть причин, которых нет.
	// Запись, которой нечего отображать, пережила бы свой предмет молча.
	declared := map[BootstrapSkipReason]bool{}
	for _, r := range AllBootstrapSkipReasons {
		declared[r] = true
	}
	for reason := range skipReasonOutcome {
		assert.Truef(t, declared[reason],
			"отображение называет причину %q, которой нет в объявленном наборе", reason)
	}

	t.Logf("осмотрено причин пропуска: %d; полос счётчика: %d",
		len(AllBootstrapSkipReasons), len(BootstrapOutcomes))
}
