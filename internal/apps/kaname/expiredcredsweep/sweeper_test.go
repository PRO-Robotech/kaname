// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sweeper_test.go — перепись прогона и разъезд реплик (задача #1264).

package expiredcredsweep_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"
)

// fakeStore — дублёр долговечной половины.
//
// Он отдаёт то, что ему велели, и НИЧЕГО не додумывает: дублёр, отвечающий «всё
// хорошо» на входе, где настоящий отказывает, делает невидимым ровно тот дефект,
// ради которого его подставляют.
type fakeStore struct {
	mu     sync.Mutex
	calls  int
	result expiredcredsweep.Result
	err    error
}

func (f *fakeStore) ReclaimExpiredCredentials(context.Context, expiredcredsweep.Spec) (expiredcredsweep.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result, f.err
}

func (f *fakeStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// recordingObserver — ряды величин.
type recordingObserver struct {
	mu   sync.Mutex
	rows []string
}

func (o *recordingObserver) SweepObserved(outcome string, found, reclaimed int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rows = append(o.rows, outcome)
	_ = found
	_ = reclaimed
}

func (o *recordingObserver) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.rows...)
}

func newLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func spec() expiredcredsweep.Spec {
	return expiredcredsweep.Spec{MinDelay: 21 * time.Minute, Grace: 24 * time.Hour, BatchSize: 200}
}

// CRED-RCL-13 — перепись печатает ДВА числа, и пустой прогон НЕ МОЛЧИТ.
//
// «Снято 0» само по себе не отличает «нечего снимать» от «нашёл и не снял», а
// молчание не отличает ни того, ни другого от «уборщик мёртв».
func TestCredRcl13_CensusPrintsBothNumbersAndAnEmptyPassIsNotSilent(t *testing.T) {
	log, buf := newLogger()
	store := &fakeStore{result: expiredcredsweep.Result{ByKind: map[string]int{}}}
	sw := expiredcredsweep.New(store, spec(), time.Hour, log)

	res := sw.SweepOnce(context.Background())

	if res.Found != 0 || res.Reclaimed != 0 {
		t.Fatalf("пустой прогон: найдено %d, снято %d", res.Found, res.Reclaimed)
	}
	out := buf.String()
	for _, want := range []string{"found=0", "reclaimed=0"} {
		if !strings.Contains(out, want) {
			t.Fatalf("перепись обязана печатать %q даже на пустом прогоне; напечатано:\n%s", want, out)
		}
	}
}

// CRED-RCL-13 (вторая половина) — «нашёл и НЕ снял» отличимо от «нечего снимать».
func TestCredRcl13_FoundWithoutReclaimedIsVisible(t *testing.T) {
	log, buf := newLogger()
	store := &fakeStore{result: expiredcredsweep.Result{Found: 7, Reclaimed: 0, ByKind: map[string]int{}}}
	s := spec()
	s.DryRun = true
	sw := expiredcredsweep.New(store, s, time.Hour, log)

	sw.SweepOnce(context.Background())

	out := buf.String()
	if !strings.Contains(out, "found=7") || !strings.Contains(out, "reclaimed=0") {
		t.Fatalf("прогон обязан назвать ОБА числа; напечатано:\n%s", out)
	}
	if !strings.Contains(out, "outcome=dry-run") {
		t.Fatalf("показ без снятия обязан называть себя, иначе он неотличим от мёртвого уборщика:\n%s", out)
	}
}

// CRED-RCL-13 (третья половина) — ОТКАЗ не печатается как успех.
//
// Прогон, не дошедший до предмета, — свой исход, и «снято 0» на нём означает
// «не смотрели», а не «нечего снимать».
func TestCredRcl13_AFailedPassIsNotReportedAsCleanliness(t *testing.T) {
	log, buf := newLogger()
	store := &fakeStore{err: errors.New("хранилище недоступно")}
	obs := &recordingObserver{}
	sw := expiredcredsweep.New(store, spec(), time.Hour, log).WithObserver(obs)

	sw.SweepOnce(context.Background())

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Fatalf("отказ обязан быть громким; напечатано:\n%s", out)
	}
	if got := obs.snapshot(); len(got) != 1 || got[0] != "failed" {
		t.Fatalf("ряд величин обязан нести исход «failed», получено %v", got)
	}
}

// CRED-RCL-20 — ряд прогонов растёт, и по нему видно, что петля ЖИВА.
//
// Журналом «петля мертва» не выражается: мёртвая петля не печатает ничего, а
// отсутствие строки правилом тревоги не выражается.
func TestCredRcl20_EveryPassAdvancesTheOutcomeSeries(t *testing.T) {
	log, _ := newLogger()
	store := &fakeStore{result: expiredcredsweep.Result{Found: 1, Reclaimed: 1, ByKind: map[string]int{}}}
	obs := &recordingObserver{}
	sw := expiredcredsweep.New(store, spec(), time.Hour, log).WithObserver(obs)

	for i := 0; i < 3; i++ {
		sw.SweepOnce(context.Background())
	}
	got := obs.snapshot()
	if len(got) != 3 {
		t.Fatalf("ряд обязан вырасти на число прогонов, получено %d: %v", len(got), got)
	}
	for _, o := range got {
		if o != "ok" {
			t.Fatalf("исход прогона обязан быть из закрытого набора, получено %q", o)
		}
	}
}

// CRED-RCL-30 — первый прогон РАЗВОДИТСЯ по репликам.
//
// Требование «первый прогон сразу при старте» при перекате даёт N одновременных
// обходов таблицы с максимальным долгом: поднимаются все реплики. Утверждаются
// ОБЕ стороны: разъезд запрошен И обход всё же происходит.
func TestCredRcl30_FirstPassIsJitteredYetStillHappens(t *testing.T) {
	log, _ := newLogger()
	store := &fakeStore{result: expiredcredsweep.Result{ByKind: map[string]int{}}}

	var askedFor time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	sw := expiredcredsweep.New(store, spec(), time.Hour, log).
		WithJitter(func(cap time.Duration) time.Duration {
			askedFor = cap
			return time.Millisecond // детерминизм входа: величина задана пробой
		}).
		WithTicker(func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} })

	done := make(chan struct{})
	go func() { sw.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for store.callCount() == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("первый прогон не состоялся: разъезд обязан ЗАДЕРЖАТЬ обход, а не отменить его")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	<-done

	if askedFor <= 0 {
		t.Fatalf("разъезд обязан быть запрошен с положительным потолком, получено %v", askedFor)
	}
	if askedFor > time.Hour {
		t.Fatalf("потолок разъезда обязан быть ограничен, получено %v", askedFor)
	}
}
