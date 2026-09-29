// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// window_test.go — окно засчитанных отказов на источник (ось П3 приёмки
// ceremony-pace-is-named-by-number.md, kaname#315).
//
// Проба судит единицу на управляемых часах: всякое «одновременно» значит «на
// одном показании часов», а «через 15 минут» — сдвиг показания, а не ожидание.
package failurewindow_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/failurewindow"
)

// clock — управляемые часы пробы.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

var t0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

func newWindow(t *testing.T, c *clock) *failurewindow.Window {
	t.Helper()
	w, err := failurewindow.New(50, 15*time.Minute, c.Now)
	require.NoError(t, err)
	return w
}

// recordAt — n засчитанных отказов источника в моменты start, start+1s, ….
func recordAt(c *clock, w *failurewindow.Window, key string, start time.Time, n int) {
	for i := 0; i < n; i++ {
		c.Set(start.Add(time.Duration(i) * time.Second))
		w.Record(key)
	}
}

// KN-PACE-18 на единице: пятьдесят отказов — в t0+60 с источник не допущен, и
// срок — до выхода старейшего из окна: t0+900 − (t0+60) = 840 с.
func TestWindowRefusesAtTheLimitAndNamesTheOldestExit(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 50)

	c.Set(t0.Add(60 * time.Second))
	retry, ok := w.Admit("P")
	require.False(t, ok, "пятьдесят отказов в окне — предел; источник обязан быть не допущен")
	require.Equal(t, 840*time.Second, retry)
}

// KN-PACE-19 на единице: сорок девять — ещё допущен.
func TestWindowAdmitsBelowTheLimit(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 49)

	c.Set(t0.Add(60 * time.Second))
	_, ok := w.Admit("P")
	require.True(t, ok, "сорок девять отказов — ниже предела")
}

// KN-PACE-18b на единице: счёт за пределом (51) — срок до момента, когда
// останется предел минус один: выйдут отказы из t0 и t0+1 с, t0+901 − t0+60.
func TestWindowAboveTheLimitNamesTheExitThatLeavesLimitMinusOne(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 49)
	c.Set(t0.Add(49 * time.Second))
	w.Record("P")
	w.Record("P")

	c.Set(t0.Add(60 * time.Second))
	retry, ok := w.Admit("P")
	require.False(t, ok)
	require.Equal(t, 841*time.Second, retry)
}

// KN-PACE-20 на единице: окно скользит, и отказ ровно длины окна от него
// уже вышел.
func TestWindowSlidesAndAFailureExactlyOneWindowOldIsOut(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 50)

	c.Set(t0.Add(900*time.Second - time.Nanosecond))
	_, ok := w.Admit("P")
	require.False(t, ok, "за наносекунду до конца окна отказ из t0 ещё в нём")

	c.Set(t0.Add(900 * time.Second))
	_, ok = w.Admit("P")
	require.True(t, ok, "ровно через длину окна отказ из t0 из окна вышел: в нём 49")
}

// KN-PACE-21 на единице: ключи считаются порознь.
func TestWindowKeysAreCountedSeparately(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 50)

	c.Set(t0.Add(60 * time.Second))
	_, ok := w.Admit("Q")
	require.True(t, ok, "отказы P не трогают Q")
}

// Срок округлением не бывает нулём: отказ, до выхода которого осталась доля
// секунды, называет не меньше чем долю, а не ноль.
func TestWindowRetryIsNeverZero(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	recordAt(c, w, "P", t0, 50)

	c.Set(t0.Add(900*time.Second - time.Millisecond))
	retry, ok := w.Admit("P")
	require.False(t, ok)
	require.Positive(t, retry)
}

// Память ограничена отказами в окне: ключи, чьи отказы все вышли, убираются.
func TestWindowForgetsKeysWhoseFailuresAllLeft(t *testing.T) {
	c := &clock{now: t0}
	w := newWindow(t, c)
	for i := 0; i < 200; i++ {
		w.Record(fmt.Sprintf("src-%d", i))
	}
	require.Equal(t, 200, w.Keys())

	c.Set(t0.Add(15 * time.Minute))
	w.Record("fresh")
	require.Equal(t, 1, w.Keys(), "отказы старше окна не держат своих ключей")
}

// Незаданная величина — отказ построения, а не «без ограничения».
func TestWindowRefusesUndeclaredValues(t *testing.T) {
	c := &clock{now: t0}
	_, err := failurewindow.New(0, time.Minute, c.Now)
	require.Error(t, err)
	_, err = failurewindow.New(1, 0, c.Now)
	require.Error(t, err)
	_, err = failurewindow.New(1, time.Minute, nil)
	require.Error(t, err)
}
