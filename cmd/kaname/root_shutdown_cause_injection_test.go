// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// root_shutdown_cause_injection_test.go — доказательство, что гейт
// `TestIAM2506_NoRootTaskWaitsOnTheSignalContextAlone` способен упасть И
// способен смолчать.
//
// Пара «красное до · зелёное после» снята и на ЖИВОМ дереве: до починки
// перепись читалась «замыканий-задач 16 · на корневом контексте 0 · на
// сигнальном 12», после — «16 · 12 · 0». Здесь то же свойство закреплено
// воспроизводимо, на синтетике.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма, отличающаяся
// РОВНО ОДНИМ фактом: каким контекстом пользуется задача.

import (
	"os"
	"path/filepath"
	"testing"
)

// injRootOK — ЗАКОННОЕ устройство: корень гашения производен от сигнального,
// задачи берут его контекст.
const injRootOK = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	rootShutdown := newRootShutdown(ctx, func() {})
	defer rootShutdown.Stop()
	taskCtx := rootShutdown.Context()
	tasks := []func() error{
		func() error { rootShutdown.Await(); return nil },
		func() error { return drain(taskCtx) },
	}
	return run(tasks)
}
`

// injTaskOnSignalCtx — ДЕФЕКТ: задача взяла СИГНАЛЬНЫЙ контекст. Ровно один
// факт против близнеца выше.
const injTaskOnSignalCtx = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	rootShutdown := newRootShutdown(ctx, func() {})
	defer rootShutdown.Stop()
	taskCtx := rootShutdown.Context()
	tasks := []func() error{
		func() error { rootShutdown.Await(); return nil },
		func() error { return drain(ctx) },
		func() error { return drain(taskCtx) },
	}
	return run(tasks)
}
`

// injNoRootAtAll — ДЕФЕКТ дня заведения: корня гашения нет вовсе, задачи висят
// на сигнальном контексте.
const injNoRootAtAll = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	tasks := []func() error{
		func() error { <-ctx.Done(); return nil },
	}
	return run(tasks)
}
`

// injRootNotDerived — ДЕФЕКТ второй стороны: корень отменяем, но НЕ производен
// от сигнального. Тогда починка одной причины ломает вторую: сигнал перестаёт
// гасить фоновые задачи.
const injRootNotDerived = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	rootShutdown := newRootShutdown(context.Background(), func() {})
	taskCtx := rootShutdown.Context()
	tasks := []func() error{
		func() error { return drain(taskCtx) },
	}
	_ = ctx
	return run(tasks)
}
`

// injNamedResultTask — ГРАНИЦА: вторая законная форма записи задачи. Гейт
// обязан её ВИДЕТЬ, иначе всё, записанное так, уходит из наблюдения молча.
const injNamedResultTask = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	rootShutdown := newRootShutdown(ctx, func() {})
	taskCtx := rootShutdown.Context()
	tasks := []func() error{
		func() (err error) { return drain(ctx) },
		func() (err error) { return drain(taskCtx) },
	}
	return run(tasks)
}
`

// injNotATask — ЗАКОННЫЙ БЛИЗНЕЦ границы: замыкание с доводом задачей корня не
// является (это обработчик, а не фоновая работа), и гейт обязан о нём молчать.
const injNotATask = `package main

import (
	"context"
	"os/signal"
)

func runServe() error {
	ctx, cancel := signal.NotifyContext(context.Background(), 15)
	defer cancel()
	rootShutdown := newRootShutdown(ctx, func() {})
	taskCtx := rootShutdown.Context()
	handle := func(c context.Context) error { return drain(ctx) }
	tasks := []func() error{
		func() error { return drain(taskCtx) },
	}
	_ = handle
	return run(tasks)
}
`

func writeCauseTree(t *testing.T, body string) (root string, files []string) {
	t.Helper()
	root = t.TempDir()
	path := filepath.Join(root, "serve.go")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	return root, []string{path}
}

func causeCensusOf(t *testing.T, body string) ([]rootTaskSite, shutdownCauseCensus) {
	t.Helper()
	root, files := writeCauseTree(t, body)
	sites, census, err := scanShutdownCauses(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return sites, census
}

func TestIAM2506_InjectionRedsTheTaskOnTheSignalContextAndKeepsQuietOnTheRootOne(t *testing.T) {
	sites, census := causeCensusOf(t, injRootOK)
	if len(sites) != 0 || census.OnSignal != 0 {
		t.Fatalf("законное устройство дало находки: %+v · %s", sites, census.Summary())
	}
	if census.Tasks != 2 || census.OnRoot != 2 {
		t.Fatalf("перепись законного устройства неверна: %s", census.Summary())
	}

	sites, census = causeCensusOf(t, injTaskOnSignalCtx)
	if len(sites) != 1 {
		t.Fatalf("находок ожидалась РОВНО одна, получено %d: %+v — либо гейт не видит "+
			"дефекта, либо роняет заодно законного близнеца", len(sites), sites)
	}
	if census.Tasks != 3 || census.OnRoot != 2 || census.OnSignal != 1 {
		t.Errorf("перепись обязана назвать ТРИ числа и различить их: %s", census.Summary())
	}
}

func TestIAM2506_InjectionRedsTheRootThatDoesNotExist(t *testing.T) {
	_, census := causeCensusOf(t, injNoRootAtAll)
	if census.RootCtx != "" {
		t.Fatalf("корень гашения опознан там, где его нет (%q) — гейт зелен на "+
			"дефекте дня заведения", census.RootCtx)
	}
	if census.OnSignal != 1 {
		t.Errorf("задача на сигнальном контексте не насчитана: %s", census.Summary())
	}
}

func TestIAM2506_InjectionRedsTheRootThatIsNotDerivedFromTheSignal(t *testing.T) {
	_, census := causeCensusOf(t, injRootNotDerived)
	if census.RootCtx == "" {
		t.Fatalf("корень гашения не опознан: %s", census.Summary())
	}
	if census.RootDerived {
		t.Fatalf("корень, заведённый от `context.Background()`, назван производным от " +
			"сигнального — тогда гейт не заметил бы, что сигнал перестал гасить задачи")
	}
}

func TestIAM2506_InjectionSeesBothFormsOfTheTaskSignature(t *testing.T) {
	sites, census := causeCensusOf(t, injNamedResultTask)
	if census.Tasks != 2 {
		t.Fatalf("замыканий-задач насчитано %d вместо 2 — форма `func() (err error)` "+
			"ушла бы из наблюдения молча: не красное и не зелёное, а МОЛЧАНИЕ: %s",
			census.Tasks, census.Summary())
	}
	if len(sites) != 1 {
		t.Errorf("находок %d вместо одной: %+v", len(sites), sites)
	}
}

func TestIAM2506_InjectionKeepsQuietOnAClosureThatIsNotARootTask(t *testing.T) {
	sites, census := causeCensusOf(t, injNotATask)
	if census.Tasks != 1 {
		t.Fatalf("замыкание С ДОВОДОМ засчитано задачей корня (задач %d) — гейт краснел "+
			"бы на обработчиках, и его отключили бы первым: %s", census.Tasks, census.Summary())
	}
	if len(sites) != 0 {
		t.Errorf("находки на законном близнеце: %+v", sites)
	}
}

func TestIAM2506_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	sites, census, err := scanShutdownCauses(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if census.Parsed != 0 || census.Tasks != 0 || len(sites) != 0 {
		t.Fatalf("пустой состав дал непустую перепись: %s", census.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", census.Summary())
}
