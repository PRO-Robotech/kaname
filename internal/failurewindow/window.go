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
// # Память ограничена пределом, и ключ на пределе её не теряет
//
// У ключа хранятся моменты его отказов в окне, по возрастанию, и не больше
// предела: допуск и срок решает отказ, предел-й с конца, а старейшие сверх него
// не решают ничего. Поэтому счёт за пределом (Р3) хранится пределом, и срок у
// него тот же, что у полного счёта.
//
// Ключ, чьи отказы все вышли, неотличим от незаведённого и убирается: проходом
// по росту таблицы либо по прошествии окна с прошлого прохода. Отказы, вышедшие
// из окна, возвращают и своё место под моменты.
//
// Ключ — адрес источника, и вызывающий, меняющий адрес, заводит ключ на каждый
// запрос. Поэтому засчитанных отказов в таблице, по всем ключам вместе, не
// больше [MaxStoredFailures]. Новому отказу, которому места нет, место
// освобождает ключ НИЖЕ предела: он забывается целиком, и его счёт начинается
// заново. Ключ НА пределе не забывается никогда — его отказ и срок переживают
// любой поток чужих источников. Ключ, отдающий место, ищется осмотром не больше
// [evictionProbes] ключей; когда среди осмотренных нет ключа ниже предела —
// таблица занята ключами на пределе, — новый отказ не засчитывается, пока место
// не освободит окно.
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

	// budget — предел засчитанных отказов в таблице, по всем ключам вместе;
	// stored — сколько их в ней сейчас.
	budget int
	stored int

	// sweepAt — размер таблицы, при котором идёт следующий проход по росту.
	sweepAt int
	// sweptAt — момент последнего прохода.
	sweptAt time.Time
}

// New собирает окно. Незаданная величина — ОТКАЗ ПОСТРОЕНИЯ: ноль означал бы
// «без ограничения», а величина, подставленная построением, стражу старта не
// видна.
func New(limit int, window time.Duration, now func() time.Time) (*Window, error) {
	return newWindow(limit, window, now, MaxStoredFailures)
}

// MaxStoredFailures — предел засчитанных отказов в таблице, по всем ключам
// вместе.
//
// Предел стоит на отказах, а не на ключах: место ключа растёт с числом его
// отказов, потолок которого — объявленный оператором предел оси, и предел на
// ключи оставил бы память функцией чужого числа. У всякого ключа в таблице есть
// хотя бы один отказ, поэтому ключей не больше этого числа.
//
// Дороже всего отказ стоит у ключа с одним отказом. Замер на ключах — адресах
// IPv6 в 39 знаков, по одному отказу (TestWindowMemoryAtTheBudgetStaysBounded,
// go1.26): около 170 байт на отказ, то есть около 42 МиБ на таблицу, полную до
// предела. Это шестая часть резерва сверх проверок пароля, который страж старта
// требует у боевого профиля чарта (256 МиБ из 1280Mi, INSTALL.md).
//
// Предел оси выше этого числа — отказ построения: ни один ключ не достиг бы
// своего предела, и ось молча не действовала бы.
const MaxStoredFailures = 1 << 18

// evictionProbes — сколько ключей таблицы осматривается в поисках места под
// новый отказ. Ключи на пределе места не отдают; осмотр ограничен, чтобы
// таблица, занятая ими, не делала каждую запись проходом по всей себе.
const evictionProbes = 16

func newWindow(limit int, window time.Duration, now func() time.Time, budget int) (*Window, error) {
	switch {
	case limit <= 0:
		return nil, fmt.Errorf("failurewindow: failures per key must be declared as a positive number (got %d)", limit)
	case window <= 0:
		return nil, fmt.Errorf("failurewindow: window must be declared as a positive duration (got %s)", window)
	case now == nil:
		return nil, fmt.Errorf("failurewindow: clock is required (time source is an input, not the environment)")
	case budget < limit:
		return nil, fmt.Errorf("failurewindow: stored failures budget %d is below the per-key limit %d: no key could reach the limit", budget, limit)
	}
	return &Window{limit: limit, window: window, now: now, keys: make(map[string][]time.Time),
		budget: budget, sweepAt: minSweepSize, sweptAt: now()}, nil
}

// Admit отвечает, допущен ли ключ по счёту, набранному к этому моменту.
//
// ok=false — в окне не меньше предела; retryAfter — через сколько в окне
// останется предел минус один отказ. Срок положителен всегда.
func (w *Window) Admit(key string) (retryAfter time.Duration, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// Часы читаются под замком: показание и запись по нему — одна операция, и
	// моменты ложатся в таблицу по возрастанию.
	now := w.now()

	w.maybeSweepLocked(now)
	at := w.pruneLocked(key, now)
	if len(at) < w.limit {
		return 0, true
	}
	// Допуск наступит, когда в окне останется предел минус один: выйдет отказ,
	// предел-й с конца, — at[len−limit].
	retryAfter = at[len(at)-w.limit].Add(w.window).Sub(now)
	if retryAfter <= 0 {
		retryAfter = time.Nanosecond
	}
	return retryAfter, false
}

// Record засчитывает отказ ключа в текущий момент.
func (w *Window) Record(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()

	w.maybeSweepLocked(now)
	at := w.pruneLocked(key, now)
	if len(at) >= w.limit {
		// Ключ на пределе: новый отказ вытесняет старейший этого же ключа, и
		// места в таблице не прибавляется.
		drop := len(at) - (w.limit - 1)
		copy(at, at[drop:])
		at = at[:w.limit-1]
		w.stored -= drop
	} else if w.stored >= w.budget && !w.makeRoomLocked(key, now) {
		return
	}
	w.keys[key] = append(at, now)
	w.stored++
}

// makeRoomLocked освобождает место под один отказ ключа except: снимает у
// осмотренных ключей вышедшие отказы и забывает ключ ниже предела. Ключ на
// пределе места не отдаёт. false — места нет.
func (w *Window) makeRoomLocked(except string, now time.Time) bool {
	probes := 0
	for k := range w.keys {
		if w.stored < w.budget || probes == evictionProbes {
			break
		}
		if k == except {
			continue
		}
		probes++
		if at := w.pruneLocked(k, now); len(at) != 0 && len(at) < w.limit {
			w.stored -= len(at)
			delete(w.keys, k)
		}
	}
	return w.stored < w.budget
}

// pruneLocked снимает у ключа отказы, вышедшие из окна, и возвращает оставшиеся.
func (w *Window) pruneLocked(key string, now time.Time) []time.Time {
	at := w.keys[key]
	i := 0
	for i < len(at) && now.Sub(at[i]) >= w.window {
		i++
	}
	if i == 0 {
		return at
	}
	w.stored -= i
	if i == len(at) {
		delete(w.keys, key)
		return nil
	}
	if rest := at[i:]; cap(at) > 2*len(rest) {
		// Вышедшие отказы возвращают своё место: ключ, у которого из многих
		// в окне остался один, не держит места под многих.
		at = append([]time.Time(nil), rest...)
	} else {
		at = append(at[:0], rest...)
	}
	w.keys[key] = at
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
