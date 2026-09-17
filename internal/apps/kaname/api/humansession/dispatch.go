// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// dispatch.go — работа ВНЕ пути ответа (Ф5 Р2): постановка письма
// восстановления не удерживает ответ вызывающему, иначе разница работы двух
// полос — «адрес есть» и «адреса нет» — читалась бы секундомером как оракул
// существования адреса (Ф1-26, Ф1-51).
//
// # Что диспетчер обещает и чего нет
//
// Обещает: работа исполнится в контексте, ОТВЯЗАННОМ от контекста запроса
// (ответ ушёл — работа не отменяется), под своим пределом времени; остановка
// дожидается начатого. Не обещает долговечности до записи: процесс, умерший
// между ответом и записью, письма не поставит — человек повторит запрос, а
// строки без предмета не остаётся (Ф5-09: намерение атомарно с кодом).
//
// Синхронная форма — для проб и для измерения того, что асинхронная выносит за
// измеряемый участок (проба Ф5-20…22).

import (
	"context"
	"sync"
	"time"
)

// Dispatcher — порт: исполнить работу так, как велит посадка.
type Dispatcher interface {
	// Dispatch ставит работу. reqCtx — контекст запроса; работа получает СВОЙ
	// контекст и от отмены запроса не зависит.
	Dispatch(reqCtx context.Context, work func(ctx context.Context))
}

// SyncDispatcher исполняет работу на месте, контекстом вызывающего. Для проб и
// для замера стоимости: в посадке `own` это была бы та самая постановка на пути
// ответа, которую Р2 запрещает.
type SyncDispatcher struct{}

// Dispatch — см. порт.
func (SyncDispatcher) Dispatch(reqCtx context.Context, work func(ctx context.Context)) { work(reqCtx) }

// GoDispatcher исполняет работу горутиной под своим пределом времени и считает
// начатое, чтобы остановка дождалась её.
type GoDispatcher struct {
	timeout time.Duration
	mu      sync.Mutex
	wg      sync.WaitGroup
	stopped bool
}

// NewGoDispatcher — диспетчер с пределом времени на одну работу.
func NewGoDispatcher(timeout time.Duration) *GoDispatcher {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &GoDispatcher{timeout: timeout}
}

// Dispatch — см. порт. После остановки работа исполняется на месте, синхронно:
// принятая ответом постановка не может быть потеряна молча, а горутину
// остановленный диспетчер уже не дождался бы.
func (d *GoDispatcher) Dispatch(_ context.Context, work func(ctx context.Context)) {
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		defer cancel()
		work(ctx)
	}
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		run()
		return
	}
	d.wg.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.wg.Done()
		run()
	}()
}

// Wait останавливает приём и дожидается начатого.
func (d *GoDispatcher) Wait() {
	d.mu.Lock()
	d.stopped = true
	d.mu.Unlock()
	d.wg.Wait()
}
