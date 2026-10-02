// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// window_budget_test.go — память окна П3 ограничена, и предел не отнимает
// отказа у ключа на пределе (kaname#315, возврат ревью безопасности круга 1:
// ключ таблицы — адрес источника, и вызывающий, меняющий адрес на каждом
// запросе, растил её без предела).
//
// Близнецы идут парами: превышение предела памяти — красное до правки, ключ на
// пределе и свежий источник после потока — отказ сохраняется.
package failurewindow_test

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/failurewindow"
)

const (
	budgetLimit  = 50
	budgetWindow = 15 * time.Minute
	budget       = 256
)

func newBudgetWindow(t *testing.T, c *clock, limit, budget int) *failurewindow.Window {
	t.Helper()
	w, err := failurewindow.NewWithBudget(limit, budgetWindow, c.Now, budget)
	require.NoError(t, err)
	return w
}

// flood — по одному отказу с n разных источников на одном показании часов:
// вызывающий, меняющий адрес на каждом запросе.
func flood(w *failurewindow.Window, prefix string, n int) {
	for i := 0; i < n; i++ {
		w.Record(fmt.Sprintf("%s-%d", prefix, i))
	}
}

// Поток источников, каждый с одним отказом, не растит таблицу за предел: ни
// отказов, ни ключей в ней не больше предела.
func TestWindowStoredFailuresStayWithinTheBudgetUnderAFloodOfSources(t *testing.T) {
	c := &clock{now: t0}
	w := newBudgetWindow(t, c, budgetLimit, budget)

	flood(w, "rotating", 10*budget)

	require.LessOrEqual(t, w.Stored(), budget, "отказов в таблице больше предела памяти")
	require.LessOrEqual(t, w.Keys(), budget, "ключей в таблице больше предела памяти")
}

// Близнец: ключ на пределе поток переживает — его отказ сохраняется с тем же
// сроком, что без потока (KN-PACE-18 на единице: 840 с).
func TestWindowKeepsTheRefusalOfAKeyAtTheLimitThroughAFlood(t *testing.T) {
	c := &clock{now: t0}
	w := newBudgetWindow(t, c, budgetLimit, budget)
	recordAt(c, w, "P", t0, budgetLimit)

	c.Set(t0.Add(50 * time.Second))
	flood(w, "rotating", 10*budget)

	c.Set(t0.Add(60 * time.Second))
	retry, ok := w.Admit("P")
	require.False(t, ok, "поток чужих источников снял отказ с ключа на пределе")
	require.Equal(t, 840*time.Second, retry)
}

// Близнец: после потока свежий источник по-прежнему засчитывается и на
// пределе не допущен — предел памяти не выключает ось для новых ключей, пока
// в таблице есть кого забыть.
func TestWindowStillCountsAFreshSourceAfterAFlood(t *testing.T) {
	c := &clock{now: t0}
	w := newBudgetWindow(t, c, budgetLimit, budget)
	flood(w, "rotating", 10*budget)

	recordAt(c, w, "Q", t0.Add(time.Second), budgetLimit)

	c.Set(t0.Add(60 * time.Second))
	retry, ok := w.Admit("Q")
	require.False(t, ok, "свежий источник после потока не засчитан")
	require.Equal(t, 841*time.Second, retry)
}

// Таблица, занятая одними ключами на пределе, не вытесняет ни одного из них
// ради нового ключа и за предел памяти не растёт.
func TestWindowSaturatedByKeysAtTheLimitEvictsNoneOfThem(t *testing.T) {
	c := &clock{now: t0}
	w := newBudgetWindow(t, c, budgetLimit, 2*budgetLimit)
	recordAt(c, w, "P1", t0, budgetLimit)
	recordAt(c, w, "P2", t0, budgetLimit)

	c.Set(t0.Add(50 * time.Second))
	w.Record("R")

	require.LessOrEqual(t, w.Stored(), 2*budgetLimit, "отказов в таблице больше предела памяти")
	for _, key := range []string{"P1", "P2"} {
		c.Set(t0.Add(60 * time.Second))
		retry, ok := w.Admit(key)
		require.False(t, ok, "ключ %s на пределе вытеснен", key)
		require.Equal(t, 840*time.Second, retry, "срок ключа %s", key)
	}
}

// Отказы, вышедшие из окна, возвращают свою память: ключ, у которого из
// пятидесяти в окне остался один, не держит места под пятьдесят.
func TestWindowFailuresThatLeftReleaseTheirMemory(t *testing.T) {
	c := &clock{now: t0}
	w := newBudgetWindow(t, c, budgetLimit, budget*budgetLimit)
	for i := 0; i < 20; i++ {
		recordAt(c, w, fmt.Sprintf("src-%d", i), t0, budgetLimit)
	}

	c.Set(t0.Add(budgetWindow + 48*time.Second))
	for i := 0; i < 20; i++ {
		_, ok := w.Admit(fmt.Sprintf("src-%d", i))
		require.True(t, ok)
	}

	require.Equal(t, 20, w.Stored(), "у каждого ключа в окне остался один отказ")
	require.LessOrEqual(t, w.Reserved(), 2*w.Stored(), "вышедшие отказы держат своё место")
}

// Часы читаются под замком окна: иначе два одновременных отказа одного ключа
// ложатся в таблицу не по порядку, и срок считается от не того отказа.
//
// Первый отказ читает часы (t0+2 с) и стоит на показании, пока второй не
// закончит свою запись либо не выйдет срок ожидания. Часы, прочитанные вне
// замка, дают второму прочитать t0+3 с и записать его раньше первого. Под
// замком второй ждёт первого, и отказы ложатся по порядку.
func TestWindowReadsItsClockUnderItsLock(t *testing.T) {
	var calls atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	now := func() time.Time {
		k := calls.Add(1)
		if k == 2 {
			close(entered)
			<-release
		}
		return t0.Add(time.Duration(k) * time.Second)
	}
	w, err := failurewindow.New(2, budgetWindow, now)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); w.Record("P") }()
	<-entered

	secondDone := make(chan struct{})
	wg.Add(1)
	go func() { defer wg.Done(); w.Record("P"); close(secondDone) }()
	select {
	case <-secondDone:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	wg.Wait()

	// Отказы — t0+2 с и t0+3 с; Admit читает t0+4 с. Срок — до выхода
	// старейшего: t0+2 с + окно − (t0+4 с).
	retry, ok := w.Admit("P")
	require.False(t, ok)
	require.Equal(t, budgetWindow-2*time.Second, retry, "отказы легли в таблицу не по порядку")
}

// Окно продукта построено с пределом [failurewindow.MaxStoredFailures], и
// память полной таблицы им ограничена: на ключах — адресах IPv6 в 39 знаков, по
// одному отказу (самый дорогой отказ), байт на хранимый отказ не больше 256.
// Замер ведётся на пределе 1<<16 и переносится на предел продукта умножением:
// цена отказа от размера таблицы не зависит.
func TestWindowMemoryAtTheBudgetStaysBounded(t *testing.T) {
	product, err := failurewindow.New(budgetLimit, budgetWindow, time.Now)
	require.NoError(t, err)
	require.Equal(t, failurewindow.MaxStoredFailures, product.Budget())

	const n = 1 << 16
	c := &clock{now: t0}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	w := newBudgetWindow(t, c, budgetLimit, n)
	for i := 0; i < 2*n; i++ {
		w.Record(fmt.Sprintf("2001:0db8:0000:0000:0000:0000:%04x:%04x", i>>16, i&0xffff))
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	stored := w.Stored()
	require.Equal(t, n, stored, "поток вдвое больше предела заполняет таблицу ровно до предела")
	perFailure := float64(after.HeapAlloc-before.HeapAlloc) / float64(stored)
	t.Logf("байт на хранимый отказ: %.0f; полная таблица продукта: %.0f МиБ",
		perFailure, perFailure*float64(failurewindow.MaxStoredFailures)/(1<<20))
	require.LessOrEqual(t, perFailure, 256.0, "цена хранимого отказа выше расчётной")
	runtime.KeepAlive(w)
}

// Предел оси выше предела памяти — отказ построения, а не ось, которой ни один
// ключ не достигнет. Близнец — предел, равный пределу памяти: построение
// проходит.
func TestWindowRefusesALimitAboveTheBudget(t *testing.T) {
	c := &clock{now: t0}
	_, err := failurewindow.NewWithBudget(budget+1, budgetWindow, c.Now, budget)
	require.ErrorContains(t, err, "below the per-key limit")

	_, err = failurewindow.NewWithBudget(budget, budgetWindow, c.Now, budget)
	require.NoError(t, err)
}
