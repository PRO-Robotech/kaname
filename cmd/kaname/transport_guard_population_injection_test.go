// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// transport_guard_population_injection_test.go — доказательство, что гейт
// `TestIAM2641_EveryNonGRPCSurfaceIsJudgedByATransportGuard` способен упасть И
// способен смолчать.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма записи,
// отличающаяся РОВНО ОДНИМ фактом.

import (
	"os"
	"path/filepath"
	"testing"
)

// injGuardsAgree — ЗАКОННЫЙ БЛИЗНЕЦ: сколько поверхностей построено, столько и
// судится перечнем.
const injGuardsAgree = `package main

func iamHTTPEdges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{name: "hooks"},
		{name: "metrics"},
	}
}

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	return serve(hooks, metrics)
}
`

// injSurfaceNobodyJudges — ДЕФЕКТ: поверхностей три, перечень знает две. Ровно
// один факт против близнеца — заведена седьмая поверхность.
const injSurfaceNobodyJudges = `package main

func iamHTTPEdges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{name: "hooks"},
		{name: "metrics"},
	}
}

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	fresh := iamHTTPSurface(Surface{})
	return serve(hooks, metrics, fresh)
}
`

// injEdgeWithoutSurface — ДЕФЕКТ С ДРУГОЙ СТОРОНЫ: перечень судит ребро, под
// которым корень поверхности не поднимает.
const injEdgeWithoutSurface = `package main

func iamHTTPEdges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{name: "hooks"},
		{name: "metrics"},
		{name: "призрак"},
	}
}

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	return serve(hooks, metrics)
}
`

// injLedgerCoversTheThird — ЗАКОННЫЙ БЛИЗНЕЦ ведомости: третью поверхность
// судит ОБЪЯВЛЕННЫЙ отдельный страж, и гейт обязан смолчать.
const injLedgerCoversTheThird = `package main

func iamHTTPEdges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{name: "hooks"},
		{name: "metrics"},
	}
}

func requireSeparateTLS(productionMode bool, addr string) error {
	return nil
}

func runServe() error {
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	token := iamHTTPSurface(Surface{})
	return serve(hooks, metrics, token)
}
`

// injLedgerGuardOnlyInProse — ГРАНИЦА, ради которой разбор идёт по УЗЛУ: имя
// стража стоит в комментарии и в строке, а ОБЪЯВЛЕНИЯ его нет. Один факт против
// близнеца выше — снято `func`.
const injLedgerGuardOnlyInProse = `package main

// Здесь объясняется, почему requireSeparateTLS — отдельный страж.
func iamHTTPEdges() []httpEdgeTLS {
	return []httpEdgeTLS{
		{name: "hooks"},
		{name: "metrics"},
	}
}

func runServe() error {
	log("requireSeparateTLS судит докерную полосу")
	hooks := iamHTTPSurface(Surface{})
	metrics := iamHTTPSurface(Surface{})
	token := iamHTTPSurface(Surface{})
	return serve(hooks, metrics, token)
}
`

// injLedger — ведомость инъекции: одна запись, страж назван именем.
var injLedger = []separatelyGuardedSurface{{
	Surface: "докерная полоса",
	Guard:   "requireSeparateTLS",
	Why:     "синтетика инъекции",
}}

func guardsOf(t *testing.T, body string, ledger []separatelyGuardedSurface) transportGuardCensus {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "serve.go")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("положить синтетику: %v", err)
	}
	c, err := countTransportGuardPopulations([]string{path}, ledger)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return c
}

func TestIAM2641_InjectionRedsTheSurfaceNoGuardJudgesAndKeepsQuietWhenTheyAgree(t *testing.T) {
	twin := guardsOf(t, injGuardsAgree, nil)
	if twin.SurfacesBuilt != 2 || twin.EdgesInRoster != 2 {
		t.Fatalf("законный близнец сосчитан неверно: %s", twin.Summary())
	}
	if twin.SurfacesBuilt != twin.EdgesInRoster+len(twin.LedgerResolved) {
		t.Fatalf("законный близнец окрашен: %s", twin.Summary())
	}

	defect := guardsOf(t, injSurfaceNobodyJudges, nil)
	if defect.SurfacesBuilt == defect.EdgesInRoster+len(defect.LedgerResolved) {
		t.Fatalf("построено %d, судится %d — расхождение НЕ увидено, и тогда поверхность, "+
			"чей транспорт не судит ничто, поднялась бы открытым текстом молча",
			defect.SurfacesBuilt, defect.EdgesInRoster)
	}
	// Инъекция роняет ТОЛЬКО проверяемое: перечень остался прежним.
	if defect.EdgesInRoster != 2 || defect.SurfacesBuilt != 3 {
		t.Errorf("инъекция уронила заодно соседа: %s", defect.Summary())
	}
}

func TestIAM2641_InjectionRedsTheEdgeWithoutASurface(t *testing.T) {
	c := guardsOf(t, injEdgeWithoutSurface, nil)
	if c.SurfacesBuilt == c.EdgesInRoster {
		t.Fatalf("ребро без поверхности НЕ увидено: %s — страж судил бы то, чего корень "+
			"не поднимает, и равенство перестало бы что-либо значить", c.Summary())
	}
	if c.SurfacesBuilt != 2 || c.EdgesInRoster != 3 {
		t.Errorf("вторая сторона неравенства сосчитана неверно: %s", c.Summary())
	}
}

func TestIAM2641_InjectionLedgerCoversTheSeparatelyGuardedSurface(t *testing.T) {
	c := guardsOf(t, injLedgerCoversTheThird, injLedger)
	if len(c.LedgerResolved) != 1 {
		t.Fatalf("запись ведомости НЕ разрешилась при ОБЪЯВЛЕННОМ страже: %s — тогда "+
			"осознанное решение читалось бы как недосмотр", c.Summary())
	}
	if len(c.LedgerExpired) != 0 {
		t.Fatalf("живая запись объявлена истёкшей: %v", c.LedgerExpired)
	}
	if c.SurfacesBuilt != c.EdgesInRoster+len(c.LedgerResolved) {
		t.Fatalf("ведомость не закрыла разницу: %s", c.Summary())
	}
}

func TestIAM2641_InjectionLedgerExpiresWhenItsGuardIsOnlyProse(t *testing.T) {
	c := guardsOf(t, injLedgerGuardOnlyInProse, injLedger)
	if len(c.LedgerExpired) != 1 {
		t.Fatalf("имя стража в КОММЕНТАРИИ и в строке засчитано объявлением (%s) — "+
			"проверка по подстроке зеленела бы на собственном объяснении ведомости, "+
			"и снятый страж остался бы прощённым навсегда", c.Summary())
	}
	if len(c.LedgerResolved) != 0 {
		t.Fatalf("запись разрешилась без объявления стража: %v", c.LedgerResolved)
	}
}

func TestIAM2641_InjectionProvesTheEmptyWalkIsRefused(t *testing.T) {
	c, err := countTransportGuardPopulations(nil, separatelyGuardedSurfaces)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if c.Parsed != 0 || c.SurfacesBuilt != 0 || c.EdgesInRoster != 0 {
		t.Fatalf("пустой состав дал непустую перепись: %s", c.Summary())
	}
	t.Logf("пустой состав: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", c.Summary())
}
