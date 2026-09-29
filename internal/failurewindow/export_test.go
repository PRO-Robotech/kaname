// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package failurewindow

import "time"

// NewWithBudget — окно с пределом хранимых отказов, заданным пробой: предел
// продукта ([MaxStoredFailures]) проба наполняла бы дольше, чем судит.
// Построение — тот же newWindow, что у [New].
func NewWithBudget(limit int, window time.Duration, now func() time.Time, budget int) (*Window, error) {
	return newWindow(limit, window, now, budget)
}

// Budget — предел хранимых отказов, с которым окно построено.
func (w *Window) Budget() int { return w.budget }

// Keys — число ключей в таблице.
func (w *Window) Keys() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.keys)
}

// Stored — засчитанных отказов в таблице, счётом по самой таблице, а не по
// учёту окна: проба судит память, а не счётчик.
func (w *Window) Stored() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, at := range w.keys {
		n += len(at)
	}
	return n
}

// Reserved — мест под моменты отказов, занятых таблицей: сумма ёмкостей.
func (w *Window) Reserved() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, at := range w.keys {
		n += cap(at)
	}
	return n
}
