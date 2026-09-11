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
	if census.EditedAfter == 0 {
		t.Fatalf("ни один документ не правлен после объявления состояния при %d "+
			"прочитанных: ветвь сравнения не исполнялась, и молчание гейта ничего "+
			"не означает (%s)", census.DocsRead, census)
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
