// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package failurewindow — окно засчитанных отказов на ключ: ось П3 поверхности
// выдачи, «неудавшихся доказательств клиента за окно на источник» (приёмка
// ceremony-pace-is-named-by-number.md, Р5; kaname#315).
//
// # Решается при входе, растёт по исходу
//
// [Window.Admit] судит ключ по счёту, набранному к моменту входа запроса, и
// ничего не списывает; [Window.Record] засчитывает отказ, когда он наступил.
// Разнести вопрос и запись здесь законно, а не гонка: засчитывается ИСХОД, и
// до исхода его не знает никто. Цена названа приёмкой (Р3): отвергаемые
// предъявления, допущенные одновременно при счёте ниже предела, выводят счёт за
// предел — не дальше числа одновременно допущенных, то есть потолка П1, — и срок
// ожидания это учитывает.
//
// # Окно скользит, срок — до «предел минус один»
//
// Отказ в окне, пока с него прошло меньше длины окна; ровно через длину окна он
// из окна выходит. Не допущенному ключу называется срок до момента, когда в окне
// останется предел минус один отказ, — тогда следующий запрос будет допущен.
//
// # Память ограничена отказами в окне
//
// У ключа хранятся моменты его отказов в окне, по возрастанию. Ключ, чьи отказы
// все вышли, неотличим от незаведённого и убирается: проходом по росту таблицы
// либо по прошествии окна с прошлого прохода. Отказов у ключа не больше предела
// плюс число одновременно допущенных; ключей — не больше, чем источников,
// отказавших за последнее окно.
//
// # Величины — на процесс
//
// Окно живёт в памяти процесса: за балансировщиком из N реплик источнику
// достаётся до N пределов. Величина объявляется в расчёте на реплику.
package failurewindow

import (
	"fmt"
	"sync"
	"time"
)

// minSweepSize — размер таблицы, ниже которого проход уборки по росту не идёт.
const minSweepSize = 64

// Window — окно отказов по ключу.
type Window struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	now    func() time.Time
	keys   map[string][]time.Time

	// sweepAt — размер таблицы, при котором идёт следующий проход по росту.
	sweepAt int
	// sweptAt — момент последнего прохода.
	sweptAt time.Time
}

// New собирает окно. Незаданная величина — ОТКАЗ ПОСТРОЕНИЯ: ноль означал бы
// «без ограничения», а величина, подставленная построением, стражу старта не
// видна.
func New(limit int, window time.Duration, now func() time.Time) (*Window, error) {
	switch {
	case limit <= 0:
		return nil, fmt.Errorf("failurewindow: failures per key must be declared as a positive number (got %d)", limit)
	case window <= 0:
		return nil, fmt.Errorf("failurewindow: window must be declared as a positive duration (got %s)", window)
	case now == nil:
		return nil, fmt.Errorf("failurewindow: clock is required (time source is an input, not the environment)")
	}
	return &Window{limit: limit, window: window, now: now, keys: make(map[string][]time.Time),
		sweepAt: minSweepSize, sweptAt: now()}, nil
}

// Admit отвечает, допущен ли ключ по счёту, набранному к этому моменту.
//
// ok=false — в окне не меньше предела; retryAfter — через сколько в окне
// останется предел минус один отказ. Срок положителен всегда.
func (w *Window) Admit(key string) (retryAfter time.Duration, ok bool) {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()

	w.maybeSweepLocked(now)
	at := w.pruneLocked(key, now)
	if len(at) < w.limit {
		return 0, true
	}
	// Допуск наступит, когда выйдут len−limit+1 старейших; последний из них —
	// at[len−limit].
	retryAfter = at[len(at)-w.limit].Add(w.window).Sub(now)
	if retryAfter <= 0 {
		retryAfter = time.Nanosecond
	}
	return retryAfter, false
}

// Record засчитывает отказ ключа в текущий момент.
func (w *Window) Record(key string) {
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()

	w.maybeSweepLocked(now)
	at := w.pruneLocked(key, now)
	w.keys[key] = append(at, now)
}

// Keys — число ключей в таблице. Для проб памяти.
func (w *Window) Keys() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.keys)
}

// pruneLocked снимает у ключа отказы, вышедшие из окна, и возвращает оставшиеся.
func (w *Window) pruneLocked(key string, now time.Time) []time.Time {
	at := w.keys[key]
	i := 0
	for i < len(at) && now.Sub(at[i]) >= w.window {
		i++
	}
	if i == len(at) {
		delete(w.keys, key)
		return nil
	}
	if i > 0 {
		at = append(at[:0], at[i:]...)
		w.keys[key] = at
	}
	return at
}

// maybeSweepLocked убирает ключи, чьи отказы все вышли, когда таблица удвоилась
// с прошлого прохода либо прошло окно.
func (w *Window) maybeSweepLocked(now time.Time) {
	grown := len(w.keys) >= w.sweepAt
	aged := now.Sub(w.sweptAt) >= w.window && len(w.keys) > 0
	if !grown && !aged {
		return
	}
	for k := range w.keys {
		w.pruneLocked(k, now)
	}
	w.sweptAt = now
	w.sweepAt = max(minSweepSize, 2*len(w.keys))
}
