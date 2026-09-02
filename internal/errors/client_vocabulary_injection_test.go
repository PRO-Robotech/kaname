// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package errors_test

// client_vocabulary_injection_test.go — доказательство, что гейт словаря
// СПОСОБЕН упасть и способен смолчать.
//
// Вход синтетический: проба, опирающаяся на живую находку, зеленеет навсегда в
// тот момент, когда находку закрыли, — и перестаёт что-либо удостоверять.
//
// Оси по одной: имя слоя в клиентском тексте · законный близнец (тот же текст
// в пакете, адресованном оператору) · законный близнец (контракт-тон без имён
// слоя) · послабление, потерявшее предмет.

import (
	"strings"
	"testing"
)

func TestClientVocabularyGateInjection(t *testing.T) {
	const clientPkg = "internal/apps/kacho/api/group"
	const operatorPkg = "internal/apps/kacho/api/internal_iam"

	t.Run("инъекция: имя слоя в клиентском тексте — находка", func(t *testing.T) {
		findings, _ := vocabularyFindings([]clientText{
			{pkg: clientPkg, pos: "synthetic.go:1", text: "marshal group"},
		}, map[string]string{})
		if len(findings) != 1 || !strings.Contains(findings[0], "marshal group") {
			t.Fatalf("гейт не назвал имя слоя, вернул %v", findings)
		}
	})

	t.Run("контроль: контракт-тон без имён слоя — молчание", func(t *testing.T) {
		findings, _ := vocabularyFindings([]clientText{
			{pkg: clientPkg, pos: "synthetic.go:1", text: "Group grp_1 not found"},
			{pkg: clientPkg, pos: "synthetic.go:2", text: "permission denied"},
			{pkg: clientPkg, pos: "synthetic.go:3", text: "internal error"},
		}, map[string]string{})
		if len(findings) != 0 {
			t.Fatalf("гейт краснеет на законном контракт-тоне: %v", findings)
		}
	})

	t.Run("контроль: тот же текст у адресата-оператора — молчание", func(t *testing.T) {
		findings, exempted := vocabularyFindings([]clientText{
			{pkg: operatorPkg, pos: "synthetic.go:1", text: "marshal group"},
		}, map[string]string{operatorPkg: "внутренний слушатель"})
		if len(findings) != 0 {
			t.Fatalf("адресат-оператор не прощён: %v", findings)
		}
		if exempted[operatorPkg] != 1 {
			t.Fatalf("прощение не посчитано: %v", exempted)
		}
	})

	t.Run("инъекция: послабление, которому нечего исключать", func(t *testing.T) {
		// Ведомость называет пакет, в котором находок нет вовсе. Такая запись —
		// слепая зона, выданная вперёд: следующее имя слоя, попавшее в этот
		// пакет, будет прощено молча.
		_, exempted := vocabularyFindings([]clientText{
			{pkg: clientPkg, pos: "synthetic.go:1", text: "Group grp_1 not found"},
		}, map[string]string{operatorPkg: "предмета уже нет"})
		if exempted[operatorPkg] != 0 {
			t.Fatalf("прощение засчитано там, где прощать нечего: %v", exempted)
		}
		// Именно нулевой счётчик и есть признак, на который гейт падает
		// (`stale` в `TestClientRefusalTextNamesNoInternalLayer`).
	})

	t.Run("контроль: разбор судит СЛОВО в тексте, а не в объяснении", func(t *testing.T) {
		// Собранные тексты приходят только из литералов сообщений (разбор AST),
		// поэтому проза про `marshal` в комментарии сюда не попадает вовсе.
		// Утверждается тем, что перепись живого дерева непуста и при этом
		// зелена: если бы комментарии считались, находок было бы много.
		texts := collectClientTexts(t)
		if len(texts) == 0 {
			t.Fatal("перепись пуста — предпосылка контроля не выполняется")
		}
		findings, _ := vocabularyFindings(texts, map[string]string{})
		if len(findings) != 0 {
			t.Fatalf("на живом дереве гейт краснеет: %v", findings)
		}
	})
}
