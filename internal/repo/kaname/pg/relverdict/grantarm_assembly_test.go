// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// grantarm_assembly_test.go — метка предиката ветви выдач расходуется ровно
// один раз (kaname#857). Шаблон без метки — запрос без предиката, то есть
// выдача без сужения; с двумя метками — вторая осталась бы текстом. Обе формы
// обязаны вернуть ошибку сборки, а не собрать запрос.

import (
	"errors"
	"strings"
	"testing"
)

// withNesting — сборщик формы вопроса при заданном признаке вложенности
// (kaname#874): форма собирается дважды — без вложенных правил над типом (вид
// ствола) и с ними, — и гейты судят обе.
func withNesting(build func(labelTable string, nesting bool) (string, error), nesting bool) func(string) (string, error) {
	return func(labelTable string) (string, error) { return build(labelTable, nesting) }
}

// nestingName — имя формы сборки в сообщении гейта.
func nestingName(nesting bool) string {
	if nesting {
		return "с вложенными правилами"
	}
	return "без вложенных правил"
}

// mustAssemble — сборщик запроса для проб и гейтов: ошибка сборки здесь —
// ошибка дерева, и проба падает на ней сразу.
func mustAssemble(build func(labelTable string) (string, error)) func(string) string {
	return func(labelTable string) string {
		sql, err := build(labelTable)
		if err != nil {
			panic(err)
		}
		return sql
	}
}

func TestReplaceOnce_RefusesAnAbsentOrRepeatedMark(t *testing.T) {
	for name, c := range map[string]struct {
		tmpl  string
		count string
	}{
		"метки нет":    {"WHERE true", "0 раз"},
		"метка дважды": {"(" + armPredicateMark + ") AND (" + armPredicateMark + ")", "2 раз"},
	} {
		got, err := replaceOnce(c.tmpl, "x")
		if !errors.Is(err, errTemplateMark) {
			t.Errorf("%s: ошибка %v, ждали errTemplateMark", name, err)
			continue
		}
		if got != "" {
			t.Errorf("%s: вместе с ошибкой отдан текст %q", name, got)
		}
		if msg := err.Error(); !strings.Contains(msg, armPredicateMark) || !strings.Contains(msg, c.count) {
			t.Errorf("%s: ошибка не называет метку и число вхождений: %q", name, msg)
		}
	}
	got, err := replaceOnce("WHERE ("+armPredicateMark+")", "p")
	if err != nil || got != "WHERE (p)" {
		t.Errorf("метка ровно один раз: %q, %v", got, err)
	}
}

// Каждый сборщик формы вопроса собирается без ошибки, несёт предикат ровно один
// раз и метки не оставляет — в обеих формах сборки.
func TestEveryAssembledQueryCarriesTheGrantPredicateOnce(t *testing.T) {
	// Форма С вложенными правилами опознаётся ВХОДНОЙ развилкой вложенной строки
	// (kaname#874). Пара «тип, id» цели внутри одного предиката сверяется в ней
	// ЧЕТЫРЕЖДЫ: контейнер у вложенной строки, объект у строки верхнего уровня,
	// объект и контейнер в опускаемом условии привязки (разложение — в шапке
	// grantArmPredicate). Форма БЕЗ вложенных правил — вид ствола: развилки нет,
	// пара сверяется ОДИН раз, и вложенная строка отсечена явно.
	const predicateHead = "(rs.container_type IS NULL OR (bs.subject_type <> 'system_class' AND EXISTS ("
	const targetAxis = "b.target -> 'resources' @>"
	const flatCut = "AND rs.container_type IS NULL\n"
	for name, build := range map[string]func(string, bool) (string, error){
		"прямой вопрос":     verdictQuerySQL,
		"вопрос о странице": verdictManyQuerySQL,
		"перечень":          listQuerySQL,
		"кто имеет право":   subjectsQuerySQL,
		"разбор оснований":  expandQuerySQL,
	} {
		for _, nesting := range []bool{false, true} {
			form := name + ", " + nestingName(nesting)
			sql, err := build("", nesting)
			if err != nil {
				t.Errorf("%s: сборка: %v", form, err)
				continue
			}
			if strings.Contains(sql, armPredicateMark) {
				t.Errorf("%s: метка предиката осталась в запросе", form)
			}
			wantHead, wantAxis, wantCut := 0, 1, 1
			if nesting {
				wantHead, wantAxis, wantCut = 1, 4, 0
			}
			if n := strings.Count(sql, predicateHead); n != wantHead {
				t.Errorf("%s: развилка вложенной строки стоит %d раз, ждали %d", form, n, wantHead)
			}
			if n := strings.Count(sql, targetAxis); n != wantAxis {
				t.Errorf("%s: пара цели сверяется %d раз, ждали %d (одного предиката)", form, n, wantAxis)
			}
			if n := strings.Count(sql, flatCut); n != wantCut {
				t.Errorf("%s: отсечение вложенной строки стоит %d раз, ждали %d", form, n, wantCut)
			}
		}
	}
}
