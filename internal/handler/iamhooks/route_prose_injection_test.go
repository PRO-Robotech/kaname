// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// route_prose_injection_test.go — доказательство того, что сверка прозы с
// производителем перечня СПОСОБНА УПАСТЬ, и того, что она молчит на законных
// близнецах.
//
// Инъекция идёт по СИНТЕТИКЕ в `t.TempDir()`, а не по живым файлам пакета.
// Фикстура, привязанная к живой шапке, истекла бы вместе с ней: в день, когда
// прозу поправят, инъекция позеленела бы и перестала доказывать что-либо, не
// сказав об этом ни слова.
//
// Инъекций три, и каждая меняет РОВНО ОДИН факт против своего близнеца:
//
//	опись неполна          опись называет 3 маршрута из 4        находка
//	опись полна            те же 3 маршрута + четвёртый          молчание
//	шапка обработчика      называет РОВНО ОДИН маршрут           молчание
//
// Сверх них — две предпосылки, у каждой свой отказ: пустой производитель
// перечня и каталог без единой описи. Оба обязаны давать ОТКАЗ, а не зелёное:
// «находок ноль» и «прочитано ноль» — разные исходы.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// syntheticRoutes — перечень, не зависящий от живого производителя: инъекция
// обязана переживать всякую правку полосы.
var syntheticRoutes = []string{"alpha", "beta", "gamma", "delta"}

// writeSyntheticPkg кладёт файл с ШАПКОЙ пакета из строк doc.
func writeSyntheticPkg(t *testing.T, dir, name string, doc []string) {
	t.Helper()
	var b strings.Builder
	for _, line := range doc {
		b.WriteString("// " + line + "\n")
	}
	b.WriteString("package synthetic\n")
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("синтетика не записана: %v", err)
	}
}

// inventoryDoc — шапка-опись, называющая перечисленные маршруты.
func inventoryDoc(routes ...string) []string {
	doc := []string{"Package synthetic — опись полосы.", ""}
	for _, r := range routes {
		doc = append(doc, "  POST "+routeHookPath(r)+" — маршрут.")
	}
	return doc
}

// TestRouteProseInjection_IncompleteInventoryIsFound — ПОЛОВИНА описи находится.
func TestRouteProseInjection_IncompleteInventoryIsFound(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "inventory.go", inventoryDoc("alpha", "beta", "gamma"))

	findings, census, err := judgeRouteProse(dir, syntheticRoutes)
	t.Log(census)
	if err != nil {
		t.Fatalf("прогон недействителен: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("неполная опись не найдена: находок %d, ожидалась 1 — сверка не способна упасть",
			len(findings))
	}
	if got := findings[0].Missing; len(got) != 1 || got[0] != "delta" {
		t.Fatalf("находка называет не тот недостающий маршрут: %v", got)
	}
	// ТЕКСТ находки — часть свойства: она обязана назвать координату, иначе
	// читателю нечего искать.
	if !strings.Contains(findings[0].String(), "inventory.go") {
		t.Fatalf("находка не называет файла: %q", findings[0].String())
	}
}

// TestRouteProseInjection_CompleteInventoryIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ первой
// инъекции: та же опись, отличающаяся РОВНО ОДНИМ фактом — четвёртой строкой.
func TestRouteProseInjection_CompleteInventoryIsSilent(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "inventory.go", inventoryDoc(syntheticRoutes...))

	findings, census, err := judgeRouteProse(dir, syntheticRoutes)
	t.Log(census)
	if err != nil {
		t.Fatalf("прогон недействителен: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("полная опись названа находкой: %v — сверка ловит форму, а не существо", findings)
	}
}

// TestRouteProseInjection_SingleRouteHeaderIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ второго
// рода: шапка обработчика называет ровно свой маршрут и описью не является.
//
// Без этой половины предикат требовал бы от каждой шапки перечислять чужие
// маршруты, то есть чинился бы вписыванием лжи.
func TestRouteProseInjection_SingleRouteHeaderIsSilent(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "inventory.go", inventoryDoc(syntheticRoutes...))
	writeSyntheticPkg(t, dir, "one_handler.go", inventoryDoc("beta"))

	findings, census, err := judgeRouteProse(dir, syntheticRoutes)
	t.Log(census)
	if err != nil {
		t.Fatalf("прогон недействителен: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("шапка одного обработчика названа находкой: %v", findings)
	}
	if census.FilesWithDoc != 2 {
		t.Fatalf("перепись не увидела обеих шапок: %s", census)
	}
	if census.FilesNaming != 1 {
		t.Fatalf("описью названа не одна шапка, а %d: %s", census.FilesNaming, census)
	}
}

// TestRouteProseInjection_EmptyProducerIsRefused — производитель перечня пуст.
// Исход — ОТКАЗ: «находок ноль» здесь означало бы «предмета нет».
func TestRouteProseInjection_EmptyProducerIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "inventory.go", inventoryDoc(syntheticRoutes...))

	findings, _, err := judgeRouteProse(dir, nil)
	if err == nil {
		t.Fatalf("пустой производитель перечня дал вердикт (находок %d) вместо отказа", len(findings))
	}
}

// TestRouteProseInjection_NoInventoryIsRefused — в каталоге нет ни одной описи.
// Исход — ОТКАЗ: пустой обход вердиктом не является.
func TestRouteProseInjection_NoInventoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "one_handler.go", inventoryDoc("beta"))

	findings, census, err := judgeRouteProse(dir, syntheticRoutes)
	t.Log(census)
	if err == nil {
		t.Fatalf("каталог без описи дал вердикт (находок %d) вместо отказа", len(findings))
	}
}

// TestRouteProseInjection_ExecutablePartIsNotProse — путь маршрута в
// ИСПОЛНЯЕМОЙ части описью не делает.
//
// Без этой половины предикат зеленел бы от `mux.Handle("/iam/v1/hooks/…")` и не
// сказал бы о прозе ничего: гейт читал бы текст, а не шапку.
func TestRouteProseInjection_ExecutablePartIsNotProse(t *testing.T) {
	dir := t.TempDir()
	writeSyntheticPkg(t, dir, "inventory.go", inventoryDoc(syntheticRoutes...))

	var b strings.Builder
	b.WriteString("package synthetic\n\nvar paths = []string{\n")
	for _, r := range syntheticRoutes {
		b.WriteString("\t\"" + routeHookPath(r) + "\",\n")
	}
	b.WriteString("}\n")
	if err := os.WriteFile(filepath.Join(dir, "code.go"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("синтетика не записана: %v", err)
	}

	_, census, err := judgeRouteProse(dir, syntheticRoutes)
	t.Log(census)
	if err != nil {
		t.Fatalf("прогон недействителен: %v", err)
	}
	if census.FilesWithDoc != 1 || census.FilesNaming != 1 {
		t.Fatalf("исполняемая часть прочитана как шапка: %s", census)
	}
}
