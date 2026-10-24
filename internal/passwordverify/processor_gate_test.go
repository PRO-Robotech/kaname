// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// processor_gate_test.go — одновременных ВЫЧИСЛЕНИЙ не больше, чем процессоров
// у процесса (kaname#882).
//
// Ёмкость — предел допуска по памяти: столько проверок вправе идти разом.
// Вычисление argon2id упирается в процессор, и сверх числа процессоров
// одновременные вычисления только делят его: все кончаются вместе и позже
// всех, и каждое следующее за проверкой действие (оператор базы с собственным
// сроком) начинается у всех разом на занятом процессоре. Вычисления сверх
// процессоров ждут места в порядке прихода и кончаются по одному.
package passwordverify_test

import (
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// TestProcessorSlots_AreTheSmallerOfCapacityAndProcessors — мест вычисления
// столько, сколько процессоров, но не больше ёмкости.
func TestProcessorSlots_AreTheSmallerOfCapacityAndProcessors(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	require.Equal(t, 1, newVerifier(t, 4, newRecordingObserver()).ProcessorSlots(), "один процессор — одно место вычисления")

	runtime.GOMAXPROCS(8)
	require.Equal(t, 4, newVerifier(t, 4, newRecordingObserver()).ProcessorSlots(), "ёмкость меньше процессоров — мест столько, сколько ёмкость")
	require.Equal(t, 8, newVerifier(t, 16, newRecordingObserver()).ProcessorSlots(), "ёмкость больше процессоров — мест столько, сколько процессоров")
}

// TestVerify_ComputationsBeyondTheProcessorsFinishOneByOne — на одном процессоре
// шесть одновременных проверок кончаются по одной: первая — около одной
// стоимости, последняя — около шести. Деля процессор, они кончались бы почти
// вместе. Порог — первая не позже 0,35 последней: при очереди отношение около
// 1/6, при делёжке не ниже 0,49 (замер до правки: шесть прогонов из шести
// красные). Класс — параллельность 4, как у класса службы: вычисление
// расходится на четыре горутины, и планировщик делит процессор между ними.
func TestVerify_ComputationsBeyondTheProcessorsFinishOneByOne(t *testing.T) {
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	v := newVerifier(t, 6, newRecordingObserver())
	stored := verifierOf(t, argon2idValue(t, rightPassword, 65536, 1, 4, 32))
	// Прогрев: первое вычисление процесса платит ещё и за первое касание
	// памяти, и без прогрева первое окончание стояло бы дальше от остальных.
	require.Equal(t, passwordverify.OutcomeMatched, verify(t, v, stored, rightPassword).Outcome, "прогрев")

	const n = 6
	start := make(chan struct{})
	finished := make([]time.Duration, n)
	var wg sync.WaitGroup
	t0 := time.Now()
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res := verify(t, v, stored, rightPassword)
			finished[i] = time.Since(t0)
			if res.Outcome != passwordverify.OutcomeMatched {
				t.Errorf("проверка %d: исход %s, ожидался «совпал»", i, res.Outcome)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	slices.Sort(finished)
	t.Logf("окончания шести одновременных проверок на одном процессоре: %v", finished)
	require.Lessf(t, float64(finished[0]), 0.35*float64(finished[n-1]),
		"первая проверка кончилась в %v при последней в %v: вычисления делили процессор и кончились вместе", finished[0], finished[n-1])
}
