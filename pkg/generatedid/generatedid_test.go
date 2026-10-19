// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package generatedid_test

// generatedid_test.go — предикат формы в обе стороны (задача
// PRO-Robotech/kaname#908): порождённые продуктом идентификаторы проходят,
// чужие формы — нет. Близнецы различаются одним фактом: длиной тела, знаком
// вне алфавита, длиной префикса, регистром, краевым пробелом.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/pkg/generatedid"
)

func TestMatches_GeneratedFormsPass(t *testing.T) {
	for _, id := range []string{
		"usr0000000000000bat1",  // человек
		"sva0000000000000bat1",  // служебная учётка
		"sva_0000000000000bat1", // прежняя форма через подчёркивание
		"ak-0123456789abcdefg",  // вид, чей префикс пишется через дефис
		"cag_0123456789abcdefg",
		"ab0123456789abcdefg", // префикс в два знака
	} {
		if !generatedid.Matches(id) {
			t.Errorf("Matches(%q) = false, а это форма порождённого идентификатора", id)
		}
	}
}

func TestMatches_ForeignFormsFail(t *testing.T) {
	for name, id := range map[string]string{
		"пусто":                       "",
		"тело в 16 знаков":            "ak-0123456789abcdef",
		"тело в 18 знаков":            "usr0000000000000bat12",
		"знак вне алфавита (i)":       "usr0000000000000bati",
		"знак вне алфавита (u)":       "usr0000000000000batu",
		"префикс в один знак":         "u0000000000000bat1abc",
		"префикс в пять знаков":       "abcde0123456789abcdefg",
		"верхний регистр":             "USR0000000000000BAT1",
		"краевой пробел":              " usr0000000000000bat1",
		"двухсловное имя через дефис": "registry-anonymous",
		"запись субъекта модели":      "user:usr0000000000000bat1",
		"подстановка":                 "*",
	} {
		if generatedid.Matches(id) {
			t.Errorf("%s: Matches(%q) = true, а форма чужая", name, id)
		}
	}
}

// TestPattern_IsTheMatchedForm — объявленный текст формы и предикат — одно:
// потребитель, печатающий форму в отказе, называет ту, которой судят.
func TestPattern_IsTheMatchedForm(t *testing.T) {
	if generatedid.Pattern != `^[a-z]{2,4}[-_]?[0-9a-hjkmnp-tv-z]{17}$` {
		t.Fatalf("Pattern = %q", generatedid.Pattern)
	}
}
