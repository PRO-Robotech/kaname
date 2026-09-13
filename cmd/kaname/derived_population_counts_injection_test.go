// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// derived_population_counts_injection_test.go — доказательство, что гейт
// `TestIAM2480_DerivedPopulationCounts` способен упасть И способен смолчать.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма записи,
// отличающаяся РОВНО ОДНИМ фактом.

import (
	"os"
	"path/filepath"
	"testing"
)

// injPopulationsAgree — ЗАКОННЫЙ БЛИЗНЕЦ: построено столько же, сколько
// обслуживается.
const injPopulationsAgree = `package main

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	httpSurfaces := []SurfaceDescriptor{hooks, metrics}
	readinessCheckers := []Checker{{}, {}, {}}
	_ = outboxmetrics.NewCollector()
	return serve(httpSurfaces, readinessCheckers)
}
`

// injSurfaceBuiltButNotServed — ДЕФЕКТ: поверхность построена и в срез подъёма
// не попала. Ровно один факт против близнеца.
const injSurfaceBuiltButNotServed = `package main

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	jwks := iamHTTPSurface(Surface{})
	httpSurfaces := []SurfaceDescriptor{hooks, metrics}
	readinessCheckers := []Checker{{}, {}, {}}
	_ = outboxmetrics.NewCollector()
	_ = jwks
	return serve(httpSurfaces, readinessCheckers)
}
`

// injNoSurfacesAtAll — отказ РАЗБОРА: распознаватель не нашёл ни одной
// поверхности. Ноль здесь не пустая популяция, а мёртвый распознаватель.
const injNoSurfacesAtAll = `package main

func runServe() error {
	return nil
}
`

// injScannerIsAMethodOfAnother — ГРАНИЦА: одноимённый конструктор ЧУЖОГО пакета
// сканером очереди не является, и гейт обязан о нём молчать.
const injScannerIsAMethodOfAnother = `package main

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	httpSurfaces := []SurfaceDescriptor{hooks}
	readinessCheckers := []Checker{{}}
	_ = outboxmetrics.NewCollector()
	_ = somethingelse.NewCollector()
	return serve(httpSurfaces, readinessCheckers)
}
`

func populationsOf(t *testing.T, body string) populationCensus {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "serve.go")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	c, err := countRootPopulations([]string{path})
	if err != nil {
		t.Fatalf("%v", err)
	}
	return c
}

func TestIAM2480_InjectionRedsTheSurfaceNobodyServesAndKeepsQuietWhenTheyAgree(t *testing.T) {
	twin := populationsOf(t, injPopulationsAgree)
	if twin.SurfacesBuilt != 2 || twin.SurfacesServed != 2 {
		t.Fatalf("законный близнец сосчитан неверно: %s", twin.Summary())
	}
	if twin.QueueScanners != 1 || twin.ReadinessCheckers != 3 {
		t.Fatalf("соседние популяции сосчитаны неверно: %s", twin.Summary())
	}

	defect := populationsOf(t, injSurfaceBuiltButNotServed)
	if defect.SurfacesBuilt == defect.SurfacesServed {
		t.Fatalf("построено %d, обслуживается %d — расхождение НЕ увидено, и тогда "+
			"поверхность, которую никто не поднимает, проехала бы молча",
			defect.SurfacesBuilt, defect.SurfacesServed)
	}
	if defect.SurfacesBuilt != 3 || defect.SurfacesServed != 2 {
		t.Errorf("инъекция уронила заодно соседа: %s", defect.Summary())
	}
}

func TestIAM2480_InjectionRedsTheDeadRecognizer(t *testing.T) {
	c := populationsOf(t, injNoSurfacesAtAll)
	if c.SurfacesBuilt != 0 || c.SurfacesServed != 0 {
		t.Fatalf("распознаватель нашёл поверхности там, где их нет: %s", c.Summary())
	}
	// Живой гейт на такой переписи зовёт Fatalf: ноль означает отказ разбора, а
	// не пустую популяцию. Здесь проверена ПРЕДПОСЫЛКА отказа, а не его текст.
}

func TestIAM2480_InjectionKeepsQuietOnTheSameNameFromAnotherPackage(t *testing.T) {
	c := populationsOf(t, injScannerIsAMethodOfAnother)
	if c.QueueScanners != 1 {
		t.Fatalf("сканеров насчитано %d вместо 1: одноимённый конструктор ЧУЖОГО "+
			"пакета засчитан сканером очереди, и число стало бы неверным вверх", c.QueueScanners)
	}
}

func TestIAM2480_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	c, err := countRootPopulations(nil)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if c.Parsed != 0 || c.SurfacesBuilt != 0 {
		t.Fatalf("пустой состав дал непустую перепись: %s", c.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", c.Summary())
}
