// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// canon_test.go — разбор канона на блоки и вывод перечня типов вне модулей
// (Н-06 приёмки; сценарий B-06).

// TestB06CanonBlockUnitIsTheBodyNotTheBanner — единица блока есть ТЕЛО, а не тело
// с баннером следующего домена.
//
// Проба утверждает ЧИСЛО внутриблочных комментариев, а не только число блоков:
// разборщик, взявший единицу B, дал бы то же число блоков (32) и другое число
// комментариев, то есть ошибка была бы невидима по первой величине. 720 —
// величина §0.7 приёмки, и совпадение означает, что разборщик здесь и разборщик
// приёмки СОГЛАСНЫ, а не «оба молчат».
func TestB06CanonBlockUnitIsTheBodyNotTheBanner(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	blocks := modelrender.SplitCanon(dsl)
	if len(blocks) != 32 {
		t.Fatalf("блоков %d, ожидалось 32 (канон %s)", len(blocks), path)
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
	if inner != 720 {
		t.Errorf("внутриблочных комментариев %d, ожидалось 720 (§0.7 приёмки); "+
			"расхождение означает, что единица блока не тело", inner)
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

// helperTree — синтетическое дерево с каноном по каноническому относительному пути.
func helperTree(t *testing.T, canon string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "proto", "kacho", "cloud", "iam", "v1")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог канона: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fga_model.fga"), []byte(canon), 0o600); err != nil {
		t.Fatalf("запись канона: %v", err)
	}
	return root
}
