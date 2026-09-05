// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_roundtrip_test.go — предпосылка, на которой стоят читатели каталога
// сборки (#1980).
//
// `Catalog()` производит пары, разбивая ключи закрытой таблицы по ПЕРВОЙ точке;
// `ObjectType(module, resource)` ищет по склейке `module + "." + resource`.
// Пока разбиение и склейка обратны друг другу, промах у пары, ПРИШЕДШЕЙ ИЗ
// `Catalog()`, невозможен by construction — и именно на этом стоят ветви
// вызывающих, которые промах называют, но исполниться не могут.
//
// Предпосылка проверяется, а не предполагается: смени кто-нибудь разбиение (на
// последнюю точку, на строгую пару сегментов), обратность отпадёт молча, а
// вызывающие начнут получать тип `""` — значение, которое дальше сравнивается,
// печатается и попадает в проекции наравне с настоящим.
package authzmap_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

// TestCatalogPairsAlwaysResolveBackToTheirType — каждая пара, которую отдал
// `Catalog()`, резолвится обратно в тип.
func TestCatalogPairsAlwaysResolveBackToTheirType(t *testing.T) {
	entries := authzmap.Catalog()

	// Положительный контроль: на пустом перечне утверждение ниже истинно
	// вакуумно — «промахов ноль» означало бы «ничего не спрашивали».
	if len(entries) == 0 {
		t.Fatal("перечень сборки пуст: обход пустой, и «промахов ноль» неотличимо от " +
			"«ноль спрошенного»")
	}

	misses := 0
	for _, e := range entries {
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			misses++
			t.Errorf("пара %q.%q пришла из Catalog(), но ObjectType её не знает: разбиение "+
				"ключа и склейка перестали быть обратными, и вызывающие получают тип \"\"",
				e.Module, e.Resource)
			continue
		}
		if fgaType == "" {
			t.Errorf("пара %q.%q резолвится в ПУСТОЙ тип: пустое значение неотличимо от "+
				"промаха у всякого, кто читает только тип", e.Module, e.Resource)
		}
	}

	// Тот же вопрос со стороны посева: его строки производны от Catalog(), и
	// расхождение здесь означало бы, что производная разошлась с источником.
	seeded := authzmap.CatalogSeedResources()
	if len(seeded) == 0 {
		t.Fatal("перечень посева пуст: сверять нечего")
	}
	for _, r := range seeded {
		if _, ok := authzmap.ObjectType(r.Module, r.Resource); !ok {
			misses++
			t.Errorf("строка посева %q не резолвится в тип", r.Dotted)
		}
		if want := r.Module + "." + r.Resource; r.Dotted != want {
			t.Errorf("точечный ключ строки посева %q не равен склейке её сегментов %q — "+
				"два написания одной пары разойдутся молча", r.Dotted, want)
		}
	}

	t.Logf("осмотрено: пар перечня сборки %d, строк посева %d; промахов %d",
		len(entries), len(seeded), misses)
}

// TestCatalogKeysSplitOnTheFirstDot — обратность разбиения и склейки, спрошенная
// у самой функции разбиения, а не выведенная из результата выше.
//
// Без неё предыдущая проба зеленела бы и на разбиении, которое обратно СЛУЧАЙНО
// — например, пока ни один ключ не несёт второй точки.
func TestCatalogKeysSplitOnTheFirstDot(t *testing.T) {
	checked, multiDot := 0, 0
	for _, k := range authzmap.CatalogKeys() {
		module, resource, ok := authzmap.SplitObjectType(k)
		if !ok {
			t.Errorf("ключ %q не разбирается вовсе", k)
			continue
		}
		checked++
		if strings.Count(k, ".") > 1 {
			multiDot++
		}
		if got := module + "." + resource; got != k {
			t.Errorf("склейка сегментов ключа %q даёт %q — разбиение и склейка не обратны", k, got)
		}
	}
	if checked == 0 {
		t.Fatal("ключей не осмотрено ни одного")
	}
	t.Logf("осмотрено: ключей %d, из них с несколькими точками %d", checked, multiDot)
}

// TestRoundtripPredicateIsCapableOfSayingNo — предъявление предиката.
//
// Обе пробы выше на живом дереве зелены, и это делает их неотличимыми от проб,
// чей предикат отвечает «да» всему. Здесь предикату подаются входы, на которых
// он ОБЯЗАН сказать «нет»: иначе его молчание выше ничего не стоит.
func TestRoundtripPredicateIsCapableOfSayingNo(t *testing.T) {
	// Половина 1: `ObjectType` обязана знать «не знаю».
	if _, ok := authzmap.ObjectType("nosuchmodule", "nosuchresource"); ok {
		t.Error("ObjectType обязана отвечать ok=false на паре вне закрытой таблицы — " +
			"иначе проба обратности зеленела бы на любом разбиении")
	}
	// Законный близнец: настоящая пара по-прежнему резолвится.
	if _, ok := authzmap.ObjectType("vpc", "network"); !ok {
		t.Error("положительный близнец: настоящая пара обязана резолвиться")
	}

	// Половина 2: `SplitObjectType` обязана отвергать ключ без точки и ключ,
	// у которого сегмент пуст, — то есть ровно те формы, на которых склейка
	// перестала бы быть обратной.
	for _, bad := range []string{"nodot", ".leading", "trailing.", ""} {
		if _, _, ok := authzmap.SplitObjectType(bad); ok {
			t.Errorf("SplitObjectType обязана отвергать %q", bad)
		}
	}
	// Законный близнец: ключ с несколькими точками разбирается по ПЕРВОЙ и
	// склеивается обратно. Он же показывает, что обратность не держится на том,
	// что вторых точек сегодня нет.
	module, resource, ok := authzmap.SplitObjectType("mod.res.sub")
	if !ok || module != "mod" || resource != "res.sub" || module+"."+resource != "mod.res.sub" {
		t.Errorf("ключ с несколькими точками обязан разбираться по первой и склеиваться "+
			"обратно, получено (%q, %q, %v)", module, resource, ok)
	}
}
