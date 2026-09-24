// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package exchangepace — ось темпа «обменов в секунду на идентификатор клиента»
// у поверхности выдачи (kaname#315).
//
// # Бронь, а не «спросить» и «списать»
//
// Решение и его следствие — ОДНА операция: [Pace.Reserve] сам списывает обмен и
// сам отвечает, остался ли он. Отдельного вопроса «есть ли темп» на пути
// решения нет: разнесённые, вопрос и списание пропускают параллельные запросы
// сверх темпа, и потолок становится «темп × параллелизм».
//
// Списанное возвращается вызывающим, когда обмен НЕ состоялся (отвергнут до
// принятия предъявления). Так темп клиента тратят только принятые предъявления:
// предъявитель без ключа клиента, назвавший чужой идентификатор, держит бронь
// лишь пока его проверяют, и чужой темп не расходует.
//
// # Ведро и его запас
//
// У каждого ключа — ведро ёмкостью в одну секунду объявленного темпа,
// пополняемое непрерывно. Запас сверх секунды не копится: клиент, молчавший
// час, не получает права на всплеск за этот час.
//
// # Память ограничена числом обменивавшихся, а не числом заявленных
//
// Ключ ведра — ЗАЯВЛЕННЫЙ идентификатор, и заявить можно любой. Поэтому ведро,
// вернувшееся к полному, удаляется: полное ведро неотличимо от отсутствующего.
// Возвращённая бронь (отвергнутый обмен) оставляет полное ведро — и строки не
// оставляет. Удержанная бронь пополняется за горизонт в одну секунду; проход
// уборки идёт, когда таблица удвоилась с прошлого прохода либо горизонт
// прошёл, поэтому в таблице живут только обменивавшиеся за последний горизонт.
//
// # Величина — на процесс
//
// Ведро живёт в памяти процесса. Несколько реплик за балансировщиком дают
// клиенту до «темп × число реплик»: величина объявляется в расчёте на реплику,
// и это сказано в описании ручки.
package exchangepace

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// minSweepSize — размер таблицы, ниже которого проход уборки по росту не
// идёт: на малой таблице он дороже того, что сберегает.
const minSweepSize = 64

// Pace — темп обменов по ключу.
type Pace struct {
	mu       sync.Mutex
	perSec   float64
	capacity float64
	horizon  time.Duration
	now      func() time.Time
	buckets  map[string]*bucket

	// sweepAt — размер таблицы, при котором идёт следующий проход по росту.
	sweepAt int
	// sweptAt — момент последнего прохода.
	sweptAt time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

// New собирает темп. Незаданная величина — ОТКАЗ ПОСТРОЕНИЯ: ноль означал бы
// «без ограничения», а темп, подставленный построением, стражу старта не
// различить с объявленным.
func New(perSec int, now func() time.Time) (*Pace, error) {
	if perSec <= 0 {
		return nil, fmt.Errorf("exchangepace: exchanges per second per client must be declared as a positive number (got %d)", perSec)
	}
	if now == nil {
		return nil, fmt.Errorf("exchangepace: clock is required (time source is an input, not the environment)")
	}
	rate := float64(perSec)
	return &Pace{
		perSec:   rate,
		capacity: rate,
		horizon:  time.Second,
		now:      now,
		buckets:  make(map[string]*bucket),
		sweepAt:  minSweepSize,
		sweptAt:  now(),
	}, nil
}

// Reserve списывает один обмен по ключу.
//
// ok=false — темп исчерпан; retryAfter — время до одного целого обмена, и
// refund в этом случае nil: возвращать нечего. ok=true — обмен списан; refund
// возвращает его, если обмен не состоялся. Повторный вызов refund холост.
func (p *Pace) Reserve(key string) (refund func(), retryAfter time.Duration, ok bool) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()

	p.maybeSweepLocked(now)
	b := p.buckets[key]
	if b == nil {
		b = &bucket{tokens: p.capacity, at: now}
		p.buckets[key] = b
	} else {
		p.refillLocked(b, now)
	}
	if b.tokens < 1 {
		return nil, p.waitFor(1 - b.tokens), false
	}
	b.tokens--

	var once sync.Once
	return func() { once.Do(func() { p.refund(key) }) }, 0, true
}

// refund возвращает один обмен, не выше ёмкости; полное ведро удаляется.
func (p *Pace) refund(key string) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.buckets[key]
	if b == nil {
		// Ведро уже убрано как полное: возвращать некуда, и темп от этого не
		// расширяется — полное ведро и есть наибольший запас.
		return
	}
	p.refillLocked(b, now)
	b.tokens = math.Min(p.capacity, b.tokens+1)
	if b.tokens >= p.capacity {
		delete(p.buckets, key)
	}
}

// refillLocked пополняет ведро временем, прошедшим с последнего касания.
func (p *Pace) refillLocked(b *bucket, now time.Time) {
	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.tokens = math.Min(p.capacity, b.tokens+elapsed.Seconds()*p.perSec)
		b.at = now
	}
}

// maybeSweepLocked убирает полные вёдра, когда таблица удвоилась с прошлого
// прохода либо прошёл горизонт пополнения.
func (p *Pace) maybeSweepLocked(now time.Time) {
	grown := len(p.buckets) >= p.sweepAt
	aged := now.Sub(p.sweptAt) >= p.horizon && len(p.buckets) > 0
	if !grown && !aged {
		return
	}
	for k, b := range p.buckets {
		p.refillLocked(b, now)
		if b.tokens >= p.capacity {
			delete(p.buckets, k)
		}
	}
	p.sweptAt = now
	p.sweepAt = max(minSweepSize, 2*len(p.buckets))
}

// waitFor — время, за которое пополнится deficit обменов.
func (p *Pace) waitFor(deficit float64) time.Duration {
	return time.Duration(math.Ceil(deficit / p.perSec * float64(time.Second)))
}
