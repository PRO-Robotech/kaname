// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_axis_model_test.go — ось ГЛАГОЛОВ привязана к модели ПО КАЖДОМУ ТИПУ, по
// образцу TestDrift_GuardMatchesModel, который так же привязывает ось ТИПОВ.
//
// Что этот гейт даёт сверх словарного (internal/repohygiene/verbvocabulary_test.go).
// Словарный сверяет НАБОРЫ ИМЁН. Этот сверяет РАСПРЕДЕЛЕНИЕ ПО ТИПАМ: он ловит
// случай «модель определила v_X у типа T, а эмиттер на T его не напишет» — при
// котором оба словаря совпадают, а поведение расходится. Лишнее у эмиттера даёт
// кортеж, который владелец модели отвергает окончательно; недостающее — молча не
// выданный доступ. Существующий гейт полноты требует НАЛИЧИЯ общей пятёрки и
// молчит об ОТСУТСТВИИ шестого отношения у конкретного типа.
//
// emitterVerbRelations — ЕДИНСТВЕННАЯ точка, зависящая от формы таблиц. Следующая
// фаза меняет её тело (набор читается у типа) и НЕ трогает утверждение ниже:
// проверка остаётся той же самой с другой правой частью.
package authzmap_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// emitterVerbRelations — какие `v_*` эмиттер написал бы НА ЭТОМ типе.
//
// S1Ф2: набор читается У ТИПА. Сменилась ТОЛЬКО эта функция — утверждение ниже не
// тронуто ни на строку: гейт остался той же проверкой с другой правой частью. В
// этом и был смысл выносить правую часть отдельно.
func emitterVerbRelations(fgaType string) []string {
	return authzmap.VerbRelationsOfType(fgaType)
}

// readCanonicalModel читает каноническую модель тем же путём, что и гейт дрейфа
// (canonicalModelPath уже отказывает при отсутствии файла — пропуска нет).
func readCanonicalModel(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(canonicalModelPath(t))
	if err != nil {
		t.Fatalf("каноническая модель не прочитана: %v", err)
	}
	return string(data)
}

// verbRelationsOf — какие `v_*` модель определяет У ЭТОГО типа, отсортированно.
func verbRelationsOf(f modelFacts, typ string) []string {
	var out []string
	for rel := range f.relations[typ] {
		if strings.HasPrefix(rel, "v_") {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// TestVerbAxis_EmitterMatchesModel — точное равенство по каждому каталожному типу
// в ОБЕ стороны.
func TestVerbAxis_EmitterMatchesModel(t *testing.T) {
	f := parseModelDSL(readCanonicalModel(t))
	if len(f.types) == 0 {
		t.Fatalf("модель не разобрана — предпосылка гейта сломана, его молчание ничего не доказывает")
	}
	// Источник типов один — тот же каталог, который проецируется тенанту, а не
	// отдельное перечисление: перечисление само стало бы поверхностью дрейфа.
	types := catalogObjectTypes(t)
	if len(types) == 0 {
		t.Fatalf("каталог типов пуст — предпосылка гейта сломана")
	}

	verbNames := 0
	for _, ot := range types {
		want := verbRelationsOf(f, ot)  // что модель определяет У ЭТОГО ТИПА
		got := emitterVerbRelations(ot) // что эмиттер написал бы НА ЭТОМ ТИПЕ
		verbNames += len(want)
		if d := axisSymmetricDiff(got, want); len(d) != 0 {
			t.Errorf("тип %q: эмиттер и модель разошлись по глаголам: %v\nэмиттер: %v\nмодель:  %v\n"+
				"Расхождение видно в ОБЕ стороны: лишнее у эмиттера даёт кортеж, который владелец "+
				"модели отвергает окончательно; недостающее — молча не выданный доступ.",
				ot, d, got, want)
		}
	}
	t.Logf("перепись: сверено типов: %d; сверено имён отношений: %d", len(types), verbNames)
}

// axisSymmetricDiff — симметрическая разность с пометкой стороны: `+x` только у
// эмиттера, `-x` только в модели.
func axisSymmetricDiff(got, want []string) []string {
	l := map[string]bool{}
	for _, s := range got {
		l[s] = true
	}
	r := map[string]bool{}
	for _, s := range want {
		r[s] = true
	}
	var out []string
	for s := range l {
		if !r[s] {
			out = append(out, "+"+s)
		}
	}
	for s := range r {
		if !l[s] {
			out = append(out, "-"+s)
		}
	}
	sort.Strings(out)
	return out
}
