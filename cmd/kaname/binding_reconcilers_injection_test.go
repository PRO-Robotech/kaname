// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_reconcilers_injection_test.go — доказательство способности гейта
// дерева `TestEveryBindingReconcilerIsBuiltWithALane` упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — построение воркера обхода в том виде, в
// каком оно лежало в `serve.go` на `kaname@f0c8a1a5` (kaname#157): прямой
// `reconcile.New` внутри `runServe`, без приёмника размера. Судимый узел
// (построение под псевдонимом по умолчанию) дословен. Законные близнецы — те
// же формы записи там, где они законны.
package main

import (
	"strings"
	"testing"
)

// sweepDefectSrc — дефект дословно: воркер обхода строит свой экземпляр мимо
// сборщика полосы.
const sweepDefectSrc = `package main

import (
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func runServe(cfg config.Config) error {
	reconcileAdapter := kanamepg.NewReconcileAdapter(pool, catalogSnapshot)
	reconcileEngine := reconcile.New(reconcileAdapter,
		logger.With(slog.String("component", "rsab_reconciler")), catalogSnapshot)
	return run(reconcileEngine)
}
`

// lanesFixedSrc — он же после правки, вместе со сборщиками полос.
const lanesFixedSrc = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func newRequestBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source, reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, logger, cat).WithSizeRecorder(reg.BindingMaterializationRecorder().RequestLane())
}

func newSweepBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source, reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, logger, cat).WithSizeRecorder(reg.BindingMaterializationRecorder().SweepLane())
}

func runServe(cfg config.Config) error {
	reconcileEngine := newSweepBindingReconciler(reconcileAdapter, logger, catalogSnapshot, metricsReg)
	return run(reconcileEngine)
}

func buildServices() *services {
	rsabReconciler := newRequestBindingReconciler(adapter, logger, catalogSource, metricsReg)
	return &services{bindingReconciler: rsabReconciler}
}
`

// lanesSwappedSrc — сборщики есть, но обход провязан сборщиком ПУТИ ЗАПРОСА:
// его материализации пишутся в чужую полосу, а сборщик обхода не зовёт никто.
const lanesSwappedSrc = `package main

import (
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func newRequestBindingReconciler(tx reconcileapp.TxRunner, reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, nil, nil).WithSizeRecorder(reg.BindingMaterializationRecorder().RequestLane())
}

func newSweepBindingReconciler(tx reconcileapp.TxRunner, reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, nil, nil).WithSizeRecorder(reg.BindingMaterializationRecorder().SweepLane())
}

func runServe() error {
	return run(newRequestBindingReconciler(adapter, metricsReg))
}

func buildServices() *services {
	return &services{bindingReconciler: newRequestBindingReconciler(adapter, metricsReg)}
}
`

// sweepRenamedAliasSrc — тот же дефект под ДРУГИМ псевдонимом импорта.
const sweepRenamedAliasSrc = `package main

import (
	rsab "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

func runServe(cfg config.Config) error {
	return run(rsab.New(adapter, logger, catalogSnapshot))
}
`

// sweepProseSrc — имя построения в КОММЕНТАРИИ и СТРОКЕ, вызова нет.
const sweepProseSrc = `package main

import (
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
)

// Здесь reconcile.New НЕ зовётся: экземпляр собирает сборщик полосы.
const why = "reconcile.New мимо сборщика — материализации вне полосы"

func runServe(engine *reconcile.Reconciler) error {
	return run(engine, why)
}
`

func readAll(t *testing.T, srcs ...string) []reconcilerTreeReading {
	t.Helper()
	var out []reconcilerTreeReading
	for i, src := range srcs {
		r, err := readReconcilerTree("inject_"+string(rune('a'+i))+".go", []byte(src))
		if err != nil {
			t.Fatalf("разбор инъекции %d: %v", i, err)
		}
		if r.Calls == 0 {
			t.Fatalf("перепись инъекции %d пуста — разбор ничего не прочитал", i)
		}
		out = append(out, r)
	}
	return out
}

func requireFinding(t *testing.T, findings []string, fragment string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f, fragment) {
			return
		}
	}
	t.Fatalf("находки с %q нет; находки:\n%s", fragment, strings.Join(findings, "\n"))
}

// TestReconcilerTreeGateRedsOnTheSweepWorkerDefect — инъекция настоящим дефектом
// поверх исправленного сборщика: построение мимо сборщика названо координатой.
func TestReconcilerTreeGateRedsOnTheSweepWorkerDefect(t *testing.T) {
	findings := reconcilerTreeVerdict(readAll(t, lanesFixedSrc, sweepDefectSrc))
	requireFinding(t, findings, "МИМО сборщика полосы — inject_b.go:9 (runServe)")
	if len(findings) != 1 {
		t.Fatalf("красное пришло не только от предмета инъекции: %v", findings)
	}
}

// TestReconcilerTreeGateRedsWithoutBuilders — дефект как он лежал на базе:
// сборщиков нет вовсе, и гейт обязан сказать это, а не промолчать.
func TestReconcilerTreeGateRedsWithoutBuilders(t *testing.T) {
	findings := reconcilerTreeVerdict(readAll(t, sweepDefectSrc))
	requireFinding(t, findings, "МИМО сборщика полосы")
	requireFinding(t, findings, "сборщик newSweepBindingReconciler строит реконсайлер 0 раз")
	requireFinding(t, findings, "у сборщика newSweepBindingReconciler нет вызывающего")
}

// TestReconcilerTreeGateRedsOnASwappedLane — обход провязан сборщиком пути запроса.
func TestReconcilerTreeGateRedsOnASwappedLane(t *testing.T) {
	findings := reconcilerTreeVerdict(readAll(t, lanesSwappedSrc))
	requireFinding(t, findings, "у сборщика newSweepBindingReconciler нет вызывающего")
	if len(findings) != 1 {
		t.Fatalf("красное пришло не только от предмета инъекции: %v", findings)
	}
}

// TestReconcilerTreeGateRedsUnderARenamedAlias — псевдоним читается из импорта.
func TestReconcilerTreeGateRedsUnderARenamedAlias(t *testing.T) {
	findings := reconcilerTreeVerdict(readAll(t, lanesFixedSrc, sweepRenamedAliasSrc))
	requireFinding(t, findings, "МИМО сборщика полосы — inject_b.go:8 (runServe)")
}

// TestReconcilerTreeGateStaysSilentOnLegalTwins — исправленное дерево и проза.
func TestReconcilerTreeGateStaysSilentOnLegalTwins(t *testing.T) {
	if findings := reconcilerTreeVerdict(readAll(t, lanesFixedSrc)); len(findings) != 0 {
		t.Fatalf("исправленное дерево объявлено дефектным: %v", findings)
	}
	if findings := reconcilerTreeVerdict(readAll(t, lanesFixedSrc, sweepProseSrc)); len(findings) != 0 {
		t.Fatalf("гейт судит подстроку, а не узел разбора — краснеет на собственном объяснении: %v", findings)
	}
}
