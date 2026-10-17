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
		got, err := replaceOnce(c.tmpl, armPredicateMark, "x")
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
	got, err := replaceOnce("WHERE ("+armPredicateMark+")", armPredicateMark, "p")
	if err != nil || got != "WHERE (p)" {
		t.Errorf("метка ровно один раз: %q, %v", got, err)
	}
}

// Каждый сборщик формы вопроса собирается без ошибки, несёт предикат ровно один
// раз и метки не оставляет.
func TestEveryAssembledQueryCarriesTheGrantPredicateOnce(t *testing.T) {
	// Предикат опознаётся своей ВХОДНОЙ развилкой вложенного правила (kaname#874).
	// Пара «тип, id» цели внутри одного предиката сверяется ЧЕТЫРЕЖДЫ: контейнер у
	// вложенной строки, объект у строки верхнего уровня, объект и контейнер в
	// опускаемом условии привязки (разложение — в шапке grantArmPredicate).
	// Признак вложенности стоит ТРИЖДЫ — по разу в каждой части — и это параметр
	// своей формы: номер у форм разный, а перепутанный номер связал бы признак
	// с чужим значением.
	const predicateHead = "AND bs.subject_type <> 'system_class' AND EXISTS ("
	const targetAxis = "b.target -> 'resources' @>"
	type form struct {
		build   func(string) (string, error)
		nesting string
	}
	for name, f := range map[string]form{
		"прямой вопрос":     {verdictQuerySQL, "$12::boolean"},
		"вопрос о странице": {verdictManyQuerySQL, "$12::boolean"},
		"перечень":          {listQuerySQL, "$12::boolean"},
		"кто имеет право":   {subjectsQuerySQL, "$10::boolean"},
		"разбор оснований":  {expandQuerySQL, "$8::boolean"},
	} {
		build := f.build
		sql, err := build("")
		if err != nil {
			t.Errorf("%s: сборка: %v", name, err)
			continue
		}
		if strings.Contains(sql, armPredicateMark) {
			t.Errorf("%s: метка предиката осталась в запросе", name)
		}
		if n := strings.Count(sql, predicateHead); n != 1 {
			t.Errorf("%s: предикат ветви выдач стоит %d раз, ждали 1", name, n)
		}
		if n := strings.Count(sql, targetAxis); n != 4 {
			t.Errorf("%s: пара цели сверяется %d раз, ждали 4 (одного предиката)", name, n)
		}
		if n := strings.Count(sql, f.nesting); n != 3 {
			t.Errorf("%s: признак вложенности %s стоит %d раз, ждали 3 (по разу в каждой части)", name, f.nesting, n)
		}
	}
}
