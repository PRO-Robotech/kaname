// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_edit_after_verdict_test.go — по дереву СВОЕГО модуля (порт с
// монорепо, см. годок `acceptance_edit_after_verdict.go`).
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// acceptanceHomeDir — дом одобренных приёмок службы, ОТ КОРНЯ своего модуля
// (было `services/iam/docs/engineering/acceptance` в монорепо).
const acceptanceHomeDir = "docs/engineering/acceptance"

// TestAcceptanceEditedAfterItsVerdictSaysSo — несущее утверждение. Имя
// сохранено дословно из монорепо.
func TestAcceptanceEditedAfterItsVerdictSaysSo(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	ownDir := root
	if prefix != "" {
		ownDir = root + "/" + prefix
	}

	findings, census, err := check.AuditAcceptanceEditsAfterVerdict(ownDir, acceptanceHomeDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.DocsRead == 0 {
		t.Fatalf("дом приёмок пуст: прочитано 0 документов — вердикт беспредметен (%s)", census)
	}
	// ─────────────────────────────────────────────────────────────────────────
	// ТРЕТИЙ ИСХОД — И ОН НАЗНАЧАЕТСЯ ДЕРЕВОМ, А НЕ ПРОБОЙ
	//
	// Признак «правлено ПОСЛЕ вердикта» есть СРАВНЕНИЕ двух отметок git: когда
	// последний раз правилась строка состояния и когда сам файл. В дереве с
	// одним коммитом обе отметки равны у КАЖДОГО документа by construction —
	// сравнивать нечего, и ветвь ниже не исполнится ни при каком содержимом.
	//
	// Такое дерево не «красное»: у него НЕ СОЗДАНО УСЛОВИЕ. Различает их
	// глубина истории — свойство дерева, а не выбор пробы, поэтому ветвь
	// пропуска в полном клоне НЕДОСТИЖИМА (на день заведения дом приёмок нёс 24
	// коммита при пороге 2).
	//
	// Наблюдалось: `make test-standalone` в фикстуре гейта целей
	// (`tools/standalonetargets`) собирает клон из состава ОДНОГО коммита — и
	// эта проба отказывала там как находка о продукте, роняя цель, объявленную
	// рабочей вне монорепо (#43). Исход подан МЕТКОЙ, которую перепись
	// `scripts/test-standalone.sh` считает отдельной величиной: «пропущено по
	// непостроенной предпосылке» никогда не смешивается с «пропущено по флагам
	// прогона» и в успех не зачитывается.
	if census.HistoryDepth < check.AcceptanceHistoryFloor {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): дом приёмок %s тронут %d коммитом(ами) "+
			"при пороге %d — отметка строки состояния и отметка файла совпадают у каждого "+
			"документа by construction, и признак «правлено после вердикта» НЕВЫРАЗИМ. "+
			"Это свойство дерева (состав одного коммита, выгрузка архивом, клон глубины 1), "+
			"а не находка о продукте (%s)",
			acceptanceHomeDir, census.HistoryDepth, check.AcceptanceHistoryFloor, census)
	}
	if census.EditedAfter == 0 {
		t.Fatalf("ни один документ не правлен после объявления состояния при %d "+
			"прочитанных и глубине истории %d: ветвь сравнения не исполнялась, и "+
			"молчание гейта ничего не означает (%s)",
			census.DocsRead, census.HistoryDepth, census)
	}
	for _, d := range census.NoStateLine {
		t.Logf("без строки состояния (предмет ДРУГОГО держателя, не находка): %s", d)
	}
	for _, d := range census.NoHistory {
		t.Logf("без построчной истории (вердикт не выносится): %s", d)
	}
	for _, f := range findings {
		t.Error(f)
	}
	t.Logf("перепись: %s", census)
}
