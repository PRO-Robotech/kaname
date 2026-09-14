// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// trunk_verdict_holder_test.go — ГЕЙТ: у вердикта ствола есть читатель, он
// стоит в КАЖДОМ процессе ствола и видит исход КАЖДОГО задания
// (задача PRO-Robotech/kaname#62).
//
// Предмет и свойства — в шапке `trunk_verdict_holder.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// trunk_verdict_holder_injection_test.go. Способность САМОГО ДЕРЖАТЕЛЯ
// производить событие, молчать на зелёном стволе и НЕ ВЫДАВАТЬ отказ
// производителя за заведённого читателя доказана его собственной самопроверкой
// (`--self-test`), и она зовётся конвейером ДО вердикта.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// trunkWorkflowDir — дом объявлений процессов. Перечень САМИХ процессов
// выводится обходом этого каталога, а не выписывается: выписанный устарел бы при
// первом же новом процессе, и его красное снова осталось бы без читателя.
const trunkWorkflowDir = ".github/workflows"

// trunkWorkflowRel — объявление, на котором ставится инъекция. Одно из корпуса,
// а не весь корпус: инъекция меняет один факт против своего близнеца.
const trunkWorkflowRel = trunkWorkflowDir + "/ci.yml"

// readTrunkCorpus — объявления процессов из дерева.
func readTrunkCorpus(t *testing.T) (map[string]string, string) {
	t.Helper()

	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	dir := filepath.Join(root, filepath.FromSlash(trunkWorkflowDir))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог объявлений %s не прочитан: %v — "+
			"«ноль находок» означало бы «ноль прочитанного»", trunkWorkflowDir, err)
	}

	corpus := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- имя из обхода объявленного каталога
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", name, rerr)
		}
		corpus[name] = string(raw)
	}
	if len(corpus) == 0 {
		t.Fatalf("в %s ноль объявлений — вердикт беспредметен", trunkWorkflowDir)
	}
	return corpus, root
}

// TestEveryTrunkProcessHasAReaderOfItsVerdict — НЕСУЩЕЕ утверждение.
//
// Прежде держатель стоял в одном процессе из трёх, и по объявлению этого
// процесса дефект был невидим: там всё исправно. Свойство принадлежит КОРПУСУ
// процессов, а не одному из них, и потому судится обходом.
func TestEveryTrunkProcessHasAReaderOfItsVerdict(t *testing.T) {
	t.Parallel()

	corpus, root := readTrunkCorpus(t)

	// ДЕРЖАТЕЛЬ ОБЯЗАН ЛЕЖАТЬ В ДЕРЕВЕ. Провязка на несуществующий файл есть та
	// же форма без содержания: объявление зовёт то, чего нет, и падает у
	// каждого, кто склонирует.
	if _, serr := os.Stat(filepath.Join(root, filepath.FromSlash(check.TrunkHolderScript))); serr != nil {
		t.Fatalf("держателя %s в дереве нет: %v", check.TrunkHolderScript, serr)
	}

	findings, census, aerr := check.AuditTrunkProcesses(corpus)
	if aerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", aerr)
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s · находок %d", census, len(findings))

	// ПРЕДПОСЫЛКИ — своими утверждениями, а не одной строкой.
	if census.OnTrunk < 2 {
		t.Fatalf("процессов ствола найдено %d: на одном свойство «держатель в КАЖДОМ» "+
			"проверяется вырожденно и молчание гейта ничего не стоит", census.OnTrunk)
	}
	if census.WithHolder != census.OnTrunk {
		t.Errorf("держателя несут %d процессов ствола из %d — красное остальных не "+
			"производит события вовсе", census.WithHolder, census.OnTrunk)
	}

	for _, f := range findings {
		t.Error(f)
	}
}

// TestTrunkVerdictHasAReaderThatSeesEveryJob — провязка держателя ВНУТРИ
// процесса: перечень зависимостей полон, самопроверку зовут, права наименьшие.
func TestTrunkVerdictHasAReaderThatSeesEveryJob(t *testing.T) {
	t.Parallel()

	corpus, _ := readTrunkCorpus(t)
	raw, ok := corpus[filepath.Base(trunkWorkflowRel)]
	if !ok {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан", trunkWorkflowRel)
	}

	findings, census, aerr := check.AuditTrunkHolderWiring(raw)
	if aerr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", aerr)
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s · находок %d", census, len(findings))

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
