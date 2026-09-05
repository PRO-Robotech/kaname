// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// report_test.go — ПИСАТЕЛЬ ШАПКИ И ЕЁ ЧИТАТЕЛЬ СХОДЯТСЯ.
//
// Гейт свежести читает из шапки четыре величины: дату, ревизию и два отпечатка.
// Пишет их `Provenance.Header`. Это ДВА МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ, и расходятся
// такие места молча: разъехавшись, читатель скажет «в шапке нет строк
// отпечатка» — то есть покраснеет на исправном отчёте, — либо, что хуже,
// прочтёт пустоту как совпадение.
//
// Проба ниже гоняет настоящую шапку через настоящий разбор гейта. Своей копии
// формата она не заводит: копия и была бы третьим местом об одном предмете.

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
)

func TestHeaderIsReadableByTheFreshnessGate(t *testing.T) {
	grid := scalegrid.Small()
	prov := scalegrid.Provenance{
		TreeRev:     "abc123def456",
		When:        time.Date(2026, 8, 19, 10, 30, 0, 0, time.UTC),
		CPUModel:    "Проба",
		CPUCores:    8,
		Postgres:    "16.4",
		RunCommand:  "make scale-grid-full",
		GridDigest:  scalegrid.Digest(grid),
		GridText:    scalegrid.Describe(grid),
		Fingerprint: scalegrid.Fingerprint{Composition: "COMP000000000001", Content: "CONT000000000001"},
	}

	header, err := prov.Header("проба шапки")
	if err != nil {
		t.Fatalf("шапка не собрана: %v", err)
	}

	// Читатель — ТОТ ЖЕ разбор, каким пользуется гейт.
	if got := valueAfter(header, scalegrid.MarkerComposition); got != "COMP000000000001" {
		t.Errorf("гейт не прочитал отпечаток состава: получил %q. Писатель и читатель "+
			"разъехались — гейт краснел бы на исправном отчёте", got)
	}
	if got := valueAfter(header, scalegrid.MarkerContent); got != "CONT000000000001" {
		t.Errorf("гейт не прочитал отпечаток содержимого: получил %q", got)
	}
	if got := valueAfter(header, "  ревизия дерева      "); got != "abc123def456" {
		t.Errorf("гейт не прочитал ревизию: получил %q", got)
	}
	when, derr := reportDate(header)
	if derr != nil {
		t.Fatalf("гейт не разобрал дату из шапки, которую сам же формат и объявляет: %v", derr)
	}
	if !when.Equal(prov.When) {
		t.Errorf("дата прочитана как %s, записана %s", when, prov.When)
	}

	// Отчёт БЕЗ команды повторения невалиден: его число нечем проверить.
	bare := prov
	bare.RunCommand = "   "
	if _, err := bare.Header("проба"); err == nil {
		t.Error("шапка без дословной команды повторения ПРИНЯТА: через месяц такой отчёт " +
			"невоспроизводим, и это уже случилось с тремя отчётами соседнего прибора")
	}
}

func TestHeaderNamesTheStateOfTheTreeNotOnlyItsRevision(t *testing.T) {
	base := scalegrid.Provenance{
		TreeRev: "abc123", When: time.Now(), CPUCores: 1,
		RunCommand: "make scale-grid-full", GridText: "  ось N: 100\n",
	}

	// Чистое дерево: ревизия описывает исполнявшееся целиком.
	clean := base
	clean.TreeDirty, clean.DirtyPaths = false, 0
	cleanText := headerOf(t, clean)
	if !strings.Contains(cleanText, "чистое") {
		t.Errorf("на чистом дереве шапка этого не говорит:\n%s", cleanText)
	}

	// Грязное: ревизия НЕ описывает исполнявшееся, и это обязано быть сказано.
	dirty := base
	dirty.TreeDirty, dirty.DirtyPaths = true, 7
	dirtyText := headerOf(t, dirty)
	for _, want := range []string{"ГРЯЗНОЕ", "7", "НЕ описывает"} {
		if !strings.Contains(dirtyText, want) {
			t.Errorf("на грязном дереве шапка не называет %q — читатель принял бы ревизию за "+
				"описание исполнявшегося кода:\n%s", want, dirtyText)
		}
	}

	// Не установлено — это НЕ «чисто»: чистоту никто не проверял.
	unknown := base
	unknown.TreeDirty, unknown.DirtyPaths = true, -1
	unknownText := headerOf(t, unknown)
	if !strings.Contains(unknownText, "НЕ УСТАНОВЛЕНО") {
		t.Errorf("несостоявшаяся проверка чистоты подана как состояние:\n%s", unknownText)
	}
	if strings.Contains(unknownText, "чистое (") {
		t.Errorf("«не проверяли» напечатано как «чисто» — это ровно та подмена, ради которой "+
			"признак и заведён:\n%s", unknownText)
	}
}

func headerOf(t *testing.T, p scalegrid.Provenance) string {
	t.Helper()
	h, err := p.Header("проба")
	if err != nil {
		t.Fatalf("шапка не собрана: %v", err)
	}
	return h
}
