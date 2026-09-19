// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// canon_test.go — разбор канона на блоки и вывод перечня типов вне модулей
// (Н-06 приёмки; сценарий B-06).

// TestB06CanonBlockUnitIsTheBodyNotTheBanner — единица блока есть ТЕЛО, а не тело
// с баннером следующего домена.
//
// Проба утверждает ЧИСЛО внутриблочных комментариев, а не только число блоков:
// разборщик, взявший единицу B, дал бы то же число блоков (33) и другое число
// комментариев, то есть ошибка была бы невидима по первой величине.
//
// ЕДИНИЦА здесь — из §0.7 приёмки (строка-комментарий с отступом внутри тела
// `type`), а ЧИСЛО — свойство ревизии канона, и его переснимают вместе с ним.
// §0.7 записала 720 на своей ревизии, и оба разборщика тогда сошлись; #1820
// сдвинул канон, `kacho#1281` сдвинул снова, а заведение типа `iam_membership`
// (S3.1) прибавило блок с четырьмя пояснениями — та же единица даёт сегодня
// 728. Число приёмки при этом НЕ
// правится: она свидетельствует о замере, который был верен, — правка сделала
// бы ложной верную запись. Сходится единица, а не число.
//
// Снимок здесь неизбежен: вывести ожидаемое можно было бы только тем же
// разборщиком, а проба, сверяющая разборщик с самим собой, зеленеет при любом
// его ответе. Цена снимка — красное на каждой правке канона; это не поломка, а
// требование переснять его вместе с шапкой пакета (тот же уговор, что у
// `TestCanonHeaderNamesItsUnitAndReproducesTheMeasurement`).
func TestB06CanonBlockUnitIsTheBodyNotTheBanner(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	blocks := modelrender.SplitCanon(dsl)
	if len(blocks) != 33 {
		t.Fatalf("блоков %d, ожидалось 33 (канон %s)", len(blocks), path)
	}

	inner := 0
	for _, b := range blocks {
		for _, line := range strings.Split(string(b.Body), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				inner++
			}
		}
		if strings.Contains(string(b.Body), "\n\n") {
			t.Errorf("блок %s несёт пустую строку — взята единица B, а не тело блока", b.Type)
		}
	}
	if inner != 728 {
		t.Errorf("внутриблочных комментариев %d, ожидалось 728 (перепись HEAD; единица — "+
			"§0.7 приёмки: строка-комментарий с отступом внутри тела `type`); расхождение "+
			"означает либо что единица блока не тело, либо что канон правился, а снимок "+
			"здесь и шапка пакета не пересняты", inner)
	}
	t.Logf("перепись: блоков %d · внутриблочных комментариев %d · канон %s", len(blocks), inner, path)
}

// TestB06TypesOutsideModulesAreDerivedNotWritten — перечень типов вне модулей
// ВЫВОДИТСЯ вычитанием.
//
// Утверждается СОСТАВ, а не длина: перечень из пяти других имён прошёл бы проверку
// длины и означал бы совсем другое.
func TestB06TypesOutsideModulesAreDerivedNotWritten(t *testing.T) {
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	got := modelrender.TypesOutsideModules(seed.LiteralRows().Resources, dsl)
	want := []string{"cluster", "group", "iam_fgaproxy", "service_account", "user"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("типы вне модулей = %v, ожидалось %v", got, want)
	}
}

// TestB06AnAddedTypeOutsideModulesIsAFinding — ПРИРОСТ перечня есть находка.
//
// Половина «пять сегодня» без этой половины ничего не держит: она зелена и на
// шестом типе, дописанном рукой, — а это дословно признак #1089.
func TestB06AnAddedTypeOutsideModulesIsAFinding(t *testing.T) {
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	before := len(modelrender.TypesOutsideModules(seed.LiteralRows().Resources, dsl))

	injected := append(append([]byte(nil), dsl...),
		[]byte("\ntype smuggled_by_hand\n  relations\n    define cluster: [cluster]\n")...)
	after := modelrender.TypesOutsideModules(seed.LiteralRows().Resources, injected)

	if len(after) != before+1 {
		t.Fatalf("дописанный рукой тип не увеличил перечень: было %d, стало %d", before, len(after))
	}
	if sort.SearchStrings(after, "smuggled_by_hand") >= len(after) ||
		after[sort.SearchStrings(after, "smuggled_by_hand")] != "smuggled_by_hand" {
		t.Fatalf("перечень не называет дописанный тип поимённо: %v", after)
	}
}

// TestB06AKnownTypeIsNotReportedAsOutside — законный близнец предыдущей: тип,
// который таблица модулю ОТНОСИТ, в перечень не попадает.
//
// Без этой половины предыдущая проба зеленела бы на разборщике, объявляющем «вне
// модулей» ВСЁ подряд.
func TestB06AKnownTypeIsNotReportedAsOutside(t *testing.T) {
	_, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	for _, typ := range modelrender.TypesOutsideModules(seed.LiteralRows().Resources, dsl) {
		if typ == "vpc_network" || typ == "account" || typ == "project" {
			t.Fatalf("тип %s отнесён закрытой таблицей к модулю, но объявлен вне модулей", typ)
		}
	}
}

// helperTree — синтетическое дерево ПЛАТФОРМЕННОЙ ПОСАДКИ: канон по каноническому
// относительному пути И дом манифестов соседних модулей.
//
// Дом заводится ЗДЕСЬ, а не в отдельных пробах, потому что он и есть предпосылка
// вопроса «манифест модуля набора отсутствует»: в дереве, которое соседей не
// несёт, их отсутствие есть свойство поставки, а не находка (задача
// PRO-Robotech/kaname#56). Проба, чей предмет — самостоятельная поставка,
// заводит дерево БЕЗ дома (`noSiblingsHomeTree`), и этим одним фактом пара и
// различается.
func helperTree(t *testing.T, canon string) string {
	t.Helper()
	root := noSiblingsHomeTree(t, canon)
	withSiblingsHome(t, root)
	return root
}

// noSiblingsHomeTree — то же дерево БЕЗ дома манифестов соседей: так выглядит
// самостоятельный клон службы.
func noSiblingsHomeTree(t *testing.T, canon string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proto", "kaname", "cloud", "iam", "v1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог канона: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fga_model.fga"), []byte(canon), 0o600); err != nil {
		t.Fatalf("запись канона: %v", err)
	}
	return root
}

// withSiblingsHome — заводит в дереве дом манифестов соседних модулей.
//
// Имя каталога берётся у ЕДИНСТВЕННОГО объявления (`treeposture.SiblingsDir`), а
// не пишется здесь: голый литерал был бы второй копией соглашения, и разошёлся
// бы он молча — фикстура перестала бы заводить то, что ищет обход, не дав ни
// одной находки.
func withSiblingsHome(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, treeposture.SiblingsDir, "vpc"), 0o750); err != nil {
		t.Fatalf("дом манифестов соседей: %v", err)
	}
}
