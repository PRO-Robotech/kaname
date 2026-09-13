// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// trunk_verdict_holder_test.go — ГЕЙТ: у вердикта ствола есть читатель, и он
// видит исход КАЖДОГО задания (задача PRO-Robotech/kaname#62).
//
// Предмет и три свойства — в шапке `trunk_verdict_holder.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// trunk_verdict_holder_injection_test.go. Способность САМОГО ДЕРЖАТЕЛЯ
// производить событие и молчать на зелёном стволе доказана его собственной
// самопроверкой (`--self-test`), и она зовётся конвейером ДО вердикта.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// trunkWorkflowRel — объявление процесса, в котором живёт держатель.
const trunkWorkflowRel = ".github/workflows/ci.yml"

func TestTrunkVerdictHasAReaderThatSeesEveryJob(t *testing.T) {
	t.Parallel()

	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(trunkWorkflowRel))) // #nosec G304 -- координата объявлена постоянной
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v — «ноль находок» означало бы "+
			"«ноль прочитанного»", trunkWorkflowRel, err)
	}

	// ДЕРЖАТЕЛЬ ОБЯЗАН ЛЕЖАТЬ В ДЕРЕВЕ. Провязка на несуществующий файл есть та
	// же форма без содержания: объявление зовёт то, чего нет, и падает у
	// каждого, кто склонирует.
	if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(check.TrunkHolderScript))); serr != nil {
		t.Fatalf("держателя %s в дереве нет: %v", check.TrunkHolderScript, serr)
	}

	findings, census, aerr := check.AuditTrunkHolderWiring(string(raw))
	if aerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", aerr)
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s · находок %d", census, len(findings))

	// ПРЕДПОСЫЛКИ — своими утверждениями, а не одной строкой.
	if census.Jobs < 2 {
		t.Fatalf("заданий в процессе %d — сверять перечень зависимостей не с чем", census.Jobs)
	}
	if census.RunBodies == 0 {
		t.Fatal("у держателя ноль шагов с телом `run:` — разбор не дошёл до шагов, и его " +
			"молчание сказано ни о чём")
	}

	for _, f := range findings {
		t.Error(f)
	}
}
