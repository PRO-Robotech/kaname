// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// type_dictionaries_test.go — свойства переходника между словарями имён типа.
//
// Проверяется не таблица (она и есть предмет), а СВОЙСТВА, на которых стоят
// вызывающие: обратимость, идемпотентность, пропуск неизвестного и —
// отдельным утверждением — признак, которым словари различает схема БД.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

// Перевод обратим на КАЖДОЙ записи каталога, и перепись объявляется числом:
// «расхождений нет» при нуле осмотренных записей — утверждение ни о чём.
func TestTypeDictionariesRoundTripOverTheWholeCatalog(t *testing.T) {
	seen := 0
	for _, e := range authzmap.Catalog() {
		dotted := e.Module + "." + e.Resource
		model := authzmap.ModelTypeName(dotted)
		if model == dotted {
			t.Errorf("%q: имя каталога не переведено в словарь модели", dotted)
			continue
		}
		if back := authzmap.CatalogTypeName(model); back != dotted {
			t.Errorf("%q → %q → %q: перевод не обратим", dotted, model, back)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("каталог пуст — проба ничего не осмотрела")
	}
	t.Logf("осмотрено записей каталога: %d", seen)
}

// Идемпотентность: повторный перевод уже переведённого имени возвращает его же.
//
// На этом свойстве стоит писатель: он приводит к словарю модели значение, часть
// которого УЖЕ в нём (типы предков приезжают от владельца ресурса модельными
// именами), и не вправе испортить его вторым переводом.
func TestTypeDictionaryTranslationIsIdempotent(t *testing.T) {
	for _, e := range authzmap.Catalog() {
		dotted := e.Module + "." + e.Resource
		model := authzmap.ModelTypeName(dotted)
		if twice := authzmap.ModelTypeName(model); twice != model {
			t.Errorf("%q: повторный перевод в словарь модели дал %q", model, twice)
		}
		if twice := authzmap.CatalogTypeName(dotted); twice != dotted {
			t.Errorf("%q: повторный перевод в словарь каталога дал %q", dotted, twice)
		}
	}
}

// Неизвестное имя проходит НАСКВОЗЬ, а не превращается в пустую строку.
//
// `cluster` — не выдумка пробы: вершина иерархии в словаре модели есть, а в
// каталоге ресурсов её нет и быть не должно (кластер не ресурс). Пустая
// подстановка на его месте совпала бы с пустым значением колонки — то есть «типа
// не знаем» стало бы «совпало».
func TestUnknownTypeNamePassesThrough(t *testing.T) {
	for _, name := range []string{"cluster", "opaque_foreign_type", ""} {
		if got := authzmap.CatalogTypeName(name); got != name {
			t.Errorf("CatalogTypeName(%q) = %q, а обязано пропустить как есть", name, got)
		}
		if got := authzmap.ModelTypeName(name); got != name {
			t.Errorf("ModelTypeName(%q) = %q, а обязано пропустить как есть", name, got)
		}
	}
}

// ТОЧКА — признак, которым словари различает схема БД.
//
// Проверки `*_type NOT LIKE '%.%'` на колонках словаря модели верны ровно пока
// это свойство держится. Здесь оно утверждается по каталогу целиком, чтобы
// первый же тип, нарушивший его, покраснел ЗДЕСЬ — рядом с объяснением, — а не
// отказом вставки на стенде.
func TestOnlyTheCatalogDictionaryUsesADot(t *testing.T) {
	for _, e := range authzmap.Catalog() {
		dotted := e.Module + "." + e.Resource
		if !strings.Contains(dotted, ".") {
			t.Errorf("имя каталога %q без точки — признак, которым различает схема, "+
				"перестал работать", dotted)
		}
		if model := authzmap.ModelTypeName(dotted); strings.Contains(model, ".") {
			t.Errorf("имя модели %q содержит точку — проверка схемы "+
				"`NOT LIKE '%%.%%'` на колонках словаря модели отвергнет законную строку",
				model)
		}
	}
}
