// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// root_shutdown_test.go — предикат снятия kacho#2506, пункты 1 и 2.
//
// Утверждается НАБЛЮДАЕМОЕ поведение корня: возвращается ли задача-ожидатель по
// гашению, начатому КРАХОМ, и отдаёт ли `errgroup.Group` ошибку краха вместо
// того чтобы висеть. Проба вида «ожидатель позвал Trigger» осталась бы зелёной
// при ожидании на сигнальном контексте — то есть при ровно том дефекте, ради
// которого механизм и заведён.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

// awaitReturns — исполняет ожидателя и говорит, вернулся ли он за срок.
func awaitReturns(rs *rootShutdown, within time.Duration) bool {
	done := make(chan struct{})
	go func() { rs.Await(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// ПУНКТ 1: ожидатель возвращается по гашению БЕЗ сигнала.
func TestIAM2506_WaiterReturnsOnCrashInitiatedShutdownWithoutASignal(t *testing.T) {
	signalCtx, cancelSignal := context.WithCancel(context.Background())
	defer cancelSignal() // сигнал НЕ подаётся: его отсутствие и есть предмет

	var teardowns atomic.Int32
	rs := newRootShutdown(signalCtx, func() { teardowns.Add(1) })

	go func() {
		time.Sleep(20 * time.Millisecond)
		rs.Trigger() // КРАХ слушателя, а не сигнал
	}()

	if !awaitReturns(rs, 2*time.Second) {
		t.Fatalf("задача-ожидатель НЕ вернулась по гашению, начатому крахом. " +
			"`runServe` оканчивается на `group.Wait()`, который ждёт ВСЕ задачи, — " +
			"значит процесс не вышел бы вовсе и код возврата краха не был бы отдан " +
			"никогда")
	}
	if got := teardowns.Load(); got != 1 {
		t.Errorf("снятие из ротации исполнено %d раз(а) вместо одного — гашение не идемпотентно", got)
	}
}

// ПУНКТ 1, вторая сторона: сигнал по-прежнему гасит. Положительный контроль —
// без него проба выше зеленела бы на контексте, отменяемом чем угодно.
func TestIAM2506_WaiterStillReturnsOnASignal(t *testing.T) {
	signalCtx, cancelSignal := context.WithCancel(context.Background())
	rs := newRootShutdown(signalCtx, nil)

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancelSignal() // сигнал среды
	}()
	if !awaitReturns(rs, 2*time.Second) {
		t.Fatalf("ожидатель не вернулся по сигналу — гашение сломано во второй причине")
	}
}

// Контроль в третью сторону: пока не случилось НИ ОДНОЙ причины, ожидатель
// обязан ждать. Без этого «вернулся» ничего не доказывает.
func TestIAM2506_WaiterWaitsWhileNeitherCauseHappened(t *testing.T) {
	rs := newRootShutdown(context.Background(), nil)
	if awaitReturns(rs, 150*time.Millisecond) {
		t.Fatalf("ожидатель вернулся без единой причины гашения — тогда обе пробы " +
			"выше зелены by construction")
	}
	rs.Stop()
}

// ПУНКТ 2: корень возвращает ошибку КРАХА, а не блокируется.
//
// Собирается та же форма запуска, которой пользуется `runServe`: группа задач,
// среди них падающий слушатель, долгоживущий дренаж и ожидатель. До починки
// ожидатель висел на сигнальном контексте, `Wait()` не возвращался, и ошибка
// краха не доезжала до вызывающего никогда.
func TestIAM2506_GroupReturnsTheCrashErrorInsteadOfBlocking(t *testing.T) {
	crash := errors.New("public grpc server: listener closed")

	signalCtx, cancelSignal := context.WithCancel(context.Background())
	defer cancelSignal() // сигнала НЕ будет

	var stopped atomic.Int32
	rs := newRootShutdown(signalCtx, func() { stopped.Add(1) })

	var group errgroup.Group
	// Слушатель падает — это причина гашения.
	group.Go(func() error {
		time.Sleep(10 * time.Millisecond)
		rs.Trigger()
		return crash
	})
	// Долгоживущий дренаж: возвращается по КОРНЕВОМУ контексту.
	group.Go(func() error {
		<-rs.Context().Done()
		return nil
	})
	// Задача-ожидатель.
	group.Go(func() error { rs.Await(); return nil })

	done := make(chan error, 1)
	go func() { done <- group.Wait() }()

	select {
	case err := <-done:
		if !errors.Is(err, crash) {
			t.Fatalf("группа вернула %v, а ожидалась ошибка краха", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("группа НЕ вернула управления при крахе слушателя: процесс остался бы " +
			"с погашенными серверами и живыми задачами, пока кто-нибудь не пришлёт " +
			"сигнал, — то есть до истечения внешнего окна")
	}
	if got := stopped.Load(); got != 1 {
		t.Errorf("снятие из ротации исполнено %d раз(а) вместо одного", got)
	}
}

// Долгоживущая задача, взявшая СИГНАЛЬНЫЙ контекст, — тот самый дефект. Проба
// закрепляет ЦЕНУ ошибки, чтобы гейт ниже не выглядел педантизмом.
func TestIAM2506_ATaskOnTheSignalContextHoldsTheGroupOnACrash(t *testing.T) {
	signalCtx, cancelSignal := context.WithCancel(context.Background())
	defer cancelSignal()
	rs := newRootShutdown(signalCtx, nil)

	var group errgroup.Group
	group.Go(func() error {
		rs.Trigger()
		return errors.New("crash")
	})
	// ДЕФЕКТ: задача ждёт сигнальный контекст, а не корневой.
	group.Go(func() error { <-signalCtx.Done(); return nil })

	done := make(chan error, 1)
	go func() { done <- group.Wait() }()
	select {
	case <-done:
		t.Fatalf("группа вернулась, хотя задача ждёт сигнальный контекст, а сигнала " +
			"не было, — предпосылка гейта неверна, и тогда он стережёт несуществующее")
	case <-time.After(300 * time.Millisecond):
		// Так и есть: висит. Это и есть цена, которую закрывает корневой контекст.
	}
	cancelSignal()
	<-done
}
