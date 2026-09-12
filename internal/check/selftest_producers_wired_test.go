// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// selftest_producers_wired_test.go — КЛАСС той же находки, что у соседа
// `basic_credential_proof_run_test.go`, взятый обходом дерева, а не перечнем.
//
// # Почему класс, а не третий поимённый гейт
//
// Сосед стережёт ОДНОГО производителя — самопроверку формы базового
// удостоверения. Замер при заведении этого файла (kaname#15) дал ТРИ
// самопроверки против подставного края, и НИ ОДНА не была звана конвейером: ни
// `selftest_basic_access_token.py`, ни `selftest_authz_allow_lanes.py`, ни
// `selftest_token_facade_forms.py` — упоминаний в сыром тексте описаний
// процесса ноль, то есть их зелёное существовало только в чужой голове.
//
// Поимённый гейт на каждую закрыл бы три случая и пропустил четвёртый: следующая
// самопроверка приедет незваной и никем не замеченной. Поэтому состав берётся
// ОБХОДОМ каталога проб по образцу имени — новый производитель попадает под гейт
// by construction, а не после того, как кто-то вспомнит.
//
// # Чем этот гейт НЕ является
//
// Он не судит, что самопроверка ПРОХОДИТ, и не заменяет её вердикт. Его предмет
// — существует ли у неё вызывающий среди того, что исполняется САМО.
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// selfTestDir — каталог проб набора, ОТ КОРНЯ своего модуля.
	selfTestDir = "tests/newman/scripts"
	// selfTestPrefix — образец имени самопроверки против подставного края.
	// Отличается от `*_test.py` (пробы набора, их зовёт общий прогонщик
	// `.github/scripts/run-python-probes.py`): у самопроверки свой `main`, и
	// прогонщик её НЕ подхватывает — по построению, а не по забывчивости.
	selfTestPrefix = "selftest_"
)

// TestEverySelfTestProducerIsCalledByThePipeline — сам гейт.
func TestEverySelfTestProducerIsCalledByThePipeline(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	entries, err := os.ReadDir(filepath.Join(root, selfTestDir))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", selfTestDir, err)
	}
	var producers []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, selfTestPrefix) && strings.HasSuffix(name, ".py") {
			producers = append(producers, selfTestDir+"/"+name)
		}
	}
	sort.Strings(producers)
	if len(producers) == 0 {
		t.Fatalf("в %s не найдено ни одной самопроверки по образцу %s*.py — обход сломан, "+
			"а не дерево чисто: «вызовов ноль» означало бы «прочитано ноль»", selfTestDir, selfTestPrefix)
	}

	files := listWorkflows(t, root)
	if len(files) == 0 {
		t.Fatalf("в %s не найдено ни одного workflow — обход сломан", workflowsDir)
	}

	bodies := make([]string, 0, 64)
	parsed, runSteps := 0, 0
	for _, f := range files {
		raw, rerr := os.ReadFile(filepath.Join(root, f))
		if rerr != nil {
			t.Errorf("%s не прочитан: %v — файл НЕ проверен", f, rerr)
			continue
		}
		got, steps, perr := check.ExecutableRunBodies(string(raw))
		if perr != nil {
			t.Errorf("%s: не разобран YAML: %v — файл НЕ проверен", f, perr)
			continue
		}
		parsed++
		runSteps += steps
		bodies = append(bodies, got...)
	}
	if parsed == 0 {
		t.Fatal("не разобрано ни одного workflow — вердикт беспредметен")
	}
	if runSteps == 0 {
		t.Fatal("ни в одном файле конвейера не найдено шага с телом `run:` — разбор сломан, " +
			"и «вызова нет» означало бы «не прочитано ничего»")
	}

	wired := 0
	for _, p := range producers {
		calls := check.InvocationsOf(p, bodies)
		if calls == 0 {
			t.Errorf("%s не зовётся НИ ОДНИМ шагом конвейера (осмотрено workflow %d, тел `run:` %d).\n"+
				"Самопроверке против подставного края поднятый стенд НЕ нужен, то есть провязка "+
				"её — вопрос установки newman в задании, а не подъёма стека. Незваная, она не "+
				"производит ничего: её зелёное существует только в чужой голове.\n"+
				"Упоминание в комментарии вызовом не является и здесь намеренно не считается.", p, len(files), runSteps)
			continue
		}
		wired++
	}

	t.Logf("перепись: самопроверок в %s %d · провязано %d · workflow осмотрено %d (разобрано %d) · "+
		"тел `run:` %d", selfTestDir, len(producers), wired, len(files), parsed, runSteps)
}
