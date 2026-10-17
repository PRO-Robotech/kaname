// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// grantarm_assembly_test.go — метка предиката ветви выдач расходуется ровно
// один раз (kaname#857). Шаблон без метки — запрос без предиката, то есть
// выдача без сужения; с двумя метками — вторая осталась бы текстом. Обе формы
// обязаны остановить сборку, а не собрать запрос.

import (
	"strings"
	"testing"
)

func mustPanic(t *testing.T, why string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: сборка прошла молча", why)
		}
	}()
	f()
}

func TestReplaceOnce_RefusesAnAbsentOrRepeatedMark(t *testing.T) {
	mustPanic(t, "метки нет", func() { replaceOnce("WHERE true", armPredicateMark, "x") })
	mustPanic(t, "метка дважды", func() {
		replaceOnce("("+armPredicateMark+") AND ("+armPredicateMark+")", armPredicateMark, "x")
	})
	if got := replaceOnce("WHERE ("+armPredicateMark+")", armPredicateMark, "p"); got != "WHERE (p)" {
		t.Errorf("метка ровно один раз: %q", got)
	}
}

// Каждый сборщик формы вопроса несёт предикат ровно один раз и метки не
// оставляет.
func TestEveryAssembledQueryCarriesTheGrantPredicateOnce(t *testing.T) {
	const targetAxis = "b.target -> 'resources' @>"
	for name, sql := range map[string]string{
		"прямой вопрос":     verdictQuerySQL(""),
		"вопрос о странице": verdictManyQuerySQL(""),
		"перечень":          listQuerySQL(""),
		"кто имеет право":   subjectsQuerySQL(""),
		"разбор оснований":  expandQuerySQL(""),
	} {
		if strings.Contains(sql, armPredicateMark) {
			t.Errorf("%s: метка предиката осталась в запросе", name)
		}
		if n := strings.Count(sql, targetAxis); n != 1 {
			t.Errorf("%s: предикат ветви выдач стоит %d раз, ждали 1", name, n)
		}
	}
}
