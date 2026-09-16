// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// symbol_choice_test.go — из сообщения с ДВУМЯ кавычечными именами берётся имя
// СНЯТОГО символа, а не его контейнера (задача kaname#127).
//
// ПРЕДМЕТ. Какой символ ложится в координату разрыва, решает код, а читатель
// верил комментарию: тот говорил «ПОСЛЕДНЕЕ кавычечное вхождение», тогда как
// цикл возвращает первое подходящее. На сообщении с двумя именами запись
// ведомости и находка назвали бы РАЗНЫЕ символы, и сопоставление рассыпалось бы
// молча — обе стороны остались бы синтаксически верными.
//
// ВХОД НАСТОЯЩИЙ. Форма сообщения принадлежит buf, а не нам: выбор проверяется
// на захваченном выводе (`testdata/buf-breaking-real.jsonl`), а не на строке,
// сочинённой под ожидание. Сочинённая строка подтвердила бы ровно то, что в неё
// вписали.
package declaredbreak_test

import (
	"regexp"
	"testing"
)

// twoQuotedNames — сообщения фикстуры, несущие ДВА и более имени в кавычках. Без
// них проба беспредметна: выбор между первым и последним на одном имени не
// различим, и зелёный ничего не значил бы.
var quotedRe = regexp.MustCompile(`"([^"]+)"`)
var nameShapeRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

func TestSymbolTakesTheRemovedNameNotItsContainer(t *testing.T) {
	got := realFindings(t)

	type pair struct{ first, last string }
	withTwo := map[string]pair{}
	for _, f := range got {
		var names []string
		for _, g := range quotedRe.FindAllStringSubmatch(f.Message, -1) {
			if nameShapeRe.MatchString(g[1]) {
				names = append(names, g[1])
			}
		}
		if len(names) >= 2 {
			withTwo[f.Type] = pair{first: names[0], last: names[len(names)-1]}
		}
	}
	t.Logf("перепись: находок в фикстуре %d, из них с двумя и более именами в кавычках %d — %v",
		len(got), len(withTwo), withTwo)

	if len(withTwo) == 0 {
		t.Fatalf("фикстура не несёт НИ ОДНОГО сообщения с двумя именами: выбор между первым " +
			"и последним на таком входе не различим, и зелёный сказан ни о чём. Захватите " +
			"вывод buf на снятии поля либо RPC")
	}

	byRule := map[string]string{}
	for _, f := range got {
		byRule[f.Type] = f.Symbol()
	}

	for rule, p := range withTwo {
		if p.first == p.last {
			t.Fatalf("%s: первое и последнее имя совпали (%q) — различить выбор нечем", rule, p.first)
		}
		if byRule[rule] != p.first {
			t.Errorf("%s: взято %q, а снятый символ — %q (контейнер: %q).\n"+
				"Предмет находки — то, что СНЯЛИ, а не то, ОТКУДА сняли: контейнер в "+
				"координате разойдётся с записью ведомости молча, обе стороны останутся "+
				"синтаксически верными", rule, byRule[rule], p.first, p.last)
		}
		if byRule[rule] == p.last {
			t.Errorf("%s: взят КОНТЕЙНЕР %q — код вернулся к тому, что обещал прежний "+
				"комментарий", rule, p.last)
		}
	}

	// Положительный контроль: у снятия ФАЙЛА имя совпадает с путём. Без него
	// проба выше зеленела бы на разборе, который для всякой находки берёт первое
	// имя и ничего больше не умеет.
	for _, f := range got {
		if f.Type == "FILE_NO_DELETE" && f.Symbol() != f.Path {
			t.Errorf("у снятия файла символ обязан совпадать с путём: %q vs %q",
				f.Symbol(), f.Path)
		}
	}
}
