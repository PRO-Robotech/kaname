// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_vocabulary_injection_test.go — доказательство падучести ЯДРА гейта
// (порт СУЖЕН до основных осей монорепошного
// `internal/repohygiene/verbvocabulary_test.go`'s injection-style checks,
// снят вынесением службы доступа — `kacho#2597`). Полный набор проб
// дисциплины реестра (обнаружение, полнота субъекта) не перенесён — см.
// шапку verb_vocabulary_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVerbVocabulary_ParseStringSliceVar_FindsTheDeclaration — КОНТРОЛЬ:
// разбор находит объявление, которое реестр называет, по настоящему пути.
func TestVerbVocabulary_ParseStringSliceVar_FindsTheDeclaration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "x.go")
	src := `package x

var verbsHere = []string{"get", "list"}
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("запись синтетики: %v", err)
	}
	got, ok := parseStringSliceVar(t, path, "verbsHere")
	if !ok || len(got) != 2 {
		t.Fatalf("объявление не найдено верно: %v ok=%v", got, ok)
	}
}

// TestVerbVocabulary_RedOnAStrayVerb — ИНЪЕКЦИЯ: литерал несёт имя, которого
// модель не знает.
func TestVerbVocabulary_RedOnAStrayVerb(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{"get": true, "list": true, "v_get": true, "v_list": true}
	got := []string{"get", "phantomverb"}
	var stray []string
	for _, v := range got {
		if !allowed[normalizeVerbToken(v)] {
			stray = append(stray, v)
		}
	}
	if len(stray) != 1 || stray[0] != "phantomverb" {
		t.Fatalf("чужое имя НЕ распознано находкой: %v", stray)
	}
}

// TestVerbVocabulary_SilentOnASubsetOfTheModel — ЗАКОННЫЙ БЛИЗНЕЦ: литерал —
// подмножество модели (предикат вхождение, не равенство).
func TestVerbVocabulary_SilentOnASubsetOfTheModel(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{"get": true, "list": true, "create": true, "delete": true, "update": true}
	got := []string{"get", "list"} // подмножество, не все пять
	var stray []string
	for _, v := range got {
		if !allowed[normalizeVerbToken(v)] {
			stray = append(stray, v)
		}
	}
	if len(stray) != 0 {
		t.Fatalf("законное подмножество модели объявлено находкой: %v", stray)
	}
}

// TestVerbVocabulary_DefineRelationName_KnowsTheVerbForm — распознаватель
// строки модели отличает `define v_get: …` от строки объявления типа.
func TestVerbVocabulary_DefineRelationName_KnowsTheVerbForm(t *testing.T) {
	t.Parallel()
	if name, ok := defineRelationName("    define v_get: [user]"); !ok || name != "v_get" {
		t.Fatalf("объявление отношения не распознано: %q ok=%v", name, ok)
	}
	if _, ok := defineRelationName("type kaname_role"); ok {
		t.Fatal("строка объявления ТИПА (без отступа) распознана как отношение")
	}
	if _, ok := defineRelationName("  // define v_get — комментарий, не объявление"); ok {
		t.Fatal("КОММЕНТАРИЙ, упоминающий форму define, распознан как объявление")
	}
}
