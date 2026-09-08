// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// planarmdiscriminator_test.go — ИНЪЕКЦИЯ ДИСКРИМИНАТОРА ВЕТВЕЙ ПЛАНА.
//
// Гейт `TestVerdictBindingArmIsBoundedAndRunsFirst` утверждает порядок ветвей по
// позициям двух имён в тексте плана. Такой дискриминатор ломается тихо: стоит
// имени появиться в плане по ВТОРОЙ причине, и гейт начнёт сравнивать не то, что
// объявил, — оставаясь при этом либо вечно красным, либо, что хуже, вечно
// зелёным.
//
// Ровно это и случилось с #781: цепь областей стала читать таблицу прямых фактов
// вторым читателем, и первое вхождение перестало принадлежать ветви фактов.
// Дискриминатор исправлен, и здесь доказывается, что он РАЗЛИЧАЕТ, а не просто
// перестал краснеть, — инъекцией в обе стороны на синтетических планах.
//
// Пробе не нужна база: предмет — чистая функция над текстом плана. Настоящий
// план снимается соседним гейтом; здесь проверяется способность отличить
// исправный порядок от переставленного.

import (
	"strings"
	"testing"
)

// planWith собирает текст плана заданной раскладки: сначала цепь областей (она
// читает таблицу фактов ПО ПОСТРОЕНИЮ раньше обеих ветвей), затем две ветви в
// указанном порядке.
func planWith(bindingsFirst bool) string {
	var b strings.Builder
	b.WriteString(`{"Plan":{"Node Type":"Limit",`)
	// Цепь областей — всегда первая: пока она не собрана, присоединять нечего.
	b.WriteString(`"CTE Name":"scope","Relation Name":"relation_fact",`)
	b.WriteString(strings.Repeat(" ", 64))
	bind := `"Relation Name":"access_binding_subjects",`
	facts := `"Relation Name":"relation_fact",`
	if bindingsFirst {
		b.WriteString(bind + strings.Repeat(" ", 64) + facts)
	} else {
		b.WriteString(facts + strings.Repeat(" ", 64) + bind)
	}
	b.WriteString(`}}`)
	return b.String()
}

// TestFactsArmPosDiscriminatesTheArmNotTheChain — обе стороны инъекции.
func TestFactsArmPosDiscriminatesTheArmNotTheChain(t *testing.T) {
	// ── законный близнец: порядок исправен, гейт обязан МОЛЧАТЬ ───────────────
	good := planWith(true)
	iBind := strings.Index(good, "access_binding_subjects")
	iFact, nFact := factsArmPos(good)
	if nFact != 2 {
		t.Fatalf("на исправном плане читателей таблицы фактов %d, ожидалось 2 (цепь и ветвь): "+
			"фикстура не воспроизводит ту раскладку, ради которой дискриминатор исправлен", nFact)
	}
	if iBind > iFact {
		t.Errorf("на ИСПРАВНОМ плане дискриминатор объявил порядок нарушенным (выдачи %d, "+
			"ветвь фактов %d) — гейт краснел бы на здоровом дереве, и его сняли бы первым же "+
			"ложным срабатыванием", iBind, iFact)
	}

	// ── дефект: ветви переставлены, гейт обязан УВИДЕТЬ ──────────────────────
	bad := planWith(false)
	jBind := strings.Index(bad, "access_binding_subjects")
	jFact, mFact := factsArmPos(bad)
	if mFact != 2 {
		t.Fatalf("на переставленном плане читателей %d, ожидалось 2", mFact)
	}
	if jBind <= jFact {
		t.Errorf("дискриминатор НЕ УВИДЕЛ перестановки ветвей (выдачи %d, ветвь фактов %d): "+
			"гейт остался бы зелёным на том самом дефекте, ради которого написан — раннее "+
			"замыкание исчезло бы тихо, потому что исход вопроса от перестановки не меняется",
			jBind, jFact)
	}

	// ── предпосылка: один читатель — различать нечем ─────────────────────────
	// Прежняя раскладка (до #781): таблица фактов читается ровно один раз.
	// Дискриминатор обязан сообщить об этом числом, а не молча взять вхождение
	// цепи за вхождение ветви.
	single := `{"Plan":{"Relation Name":"access_binding_subjects","x":"relation_fact"}}`
	if _, n := factsArmPos(single); n != 1 {
		t.Errorf("на плане с ОДНИМ читателем таблицы фактов насчитано %d — гейт не смог бы "+
			"отличить исчезнувшую предпосылку от исправного дерева", n)
	}
}
