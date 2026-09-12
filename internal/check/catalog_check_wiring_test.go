// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_check_wiring_test.go — у сверки каталога прав с копией края обязан
// быть вызывающий среди того, что исполняется само, И пишущая форма обязана
// оставаться вне конвейера. Порт с монорепо (сужённая форма — прямая
// достижимость, а не граф Makefile), см. годок `catalog_check_wiring.go`.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestCatalogParityCheckIsWiredIntoThePipeline — сам гейт.
//
// Портированное имя было `TestCatalogSyncTargetIsCalledByThePipeline`; почему
// сменилось вместе с предметом — в годке, §«ПРЕДМЕТ У ГЕЙТА ФОРМА-ПРОВЕРКА».
func TestCatalogParityCheckIsWiredIntoThePipeline(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	makefileRaw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корневой Makefile не прочитан: %v", err)
	}
	for _, target := range []string{check.CatalogCheckTarget, check.CatalogSyncTarget} {
		if !check.MakefileDeclaresTarget(string(makefileRaw), target) {
			t.Fatalf("цель %s не объявлена в корневом Makefile — сверять копию каталога прав "+
				"с копией края некому, и молчание про провязку ничего не значит", target)
		}
	}

	files := listWorkflows(t, root)
	if len(files) == 0 {
		t.Fatalf("в %s не найдено ни одного workflow — обход сломан", workflowsDir)
	}

	parsed, runSteps, checkCalls, syncCalls := 0, 0, 0, 0
	for _, f := range files {
		raw, rerr := os.ReadFile(filepath.Join(root, f))
		if rerr != nil {
			t.Errorf("%s не прочитан: %v — файл НЕ проверен", f, rerr)
			continue
		}
		bodies, steps, perr := check.ExecutableRunBodies(string(raw))
		if perr != nil {
			t.Errorf("%s: не разобран YAML: %v — файл НЕ проверен", f, perr)
			continue
		}
		parsed++
		runSteps += steps
		for _, b := range bodies {
			if check.CallsMakeTarget(b, check.CatalogCheckTarget) {
				checkCalls++
			}
			if check.CallsMakeTarget(b, check.CatalogSyncTarget) {
				syncCalls++
			}
		}
	}
	if parsed == 0 {
		t.Fatal("не разобрано ни одного workflow — вердикт беспредметен")
	}
	if runSteps == 0 {
		t.Fatal("ни в одном файле конвейера не найдено шага с телом `run:` — разбор сломан, " +
			"и «вызова нет» означало бы «не прочитано ничего»")
	}

	t.Logf("перепись: workflow осмотрено %d (разобрано %d), тел `run:` %d, вызовов %s: %d, "+
		"вызовов %s: %d (обязано быть 0)",
		len(files), parsed, runSteps, check.CatalogCheckTarget, checkCalls,
		check.CatalogSyncTarget, syncCalls)

	if checkCalls == 0 {
		t.Errorf("цель %s не звана НИ ОДНИМ шагом конвейера (осмотрено workflow %d, тел `run:` "+
			"%d).\n\nКопия каталога прав у службы доступа обязана побайтово совпадать с копией "+
			"края (об этом говорит комментарий самой цели в Makefile) — но никто в CI это не "+
			"проверяет. Снимут цель из числа звучащих в CI, копия расходится молча.",
			check.CatalogCheckTarget, len(files), runSteps)
	}

	if syncCalls > 0 {
		t.Errorf("конвейер зовёт ПИШУЩУЮ форму %s (вызовов %d) — задание правит дерево, а не "+
			"судит его.\n\n«Копии совпали» после собственного `cp` истинно всегда, то есть "+
			"вердикта у такого шага нет вовсе. В конвейере зовут %s; пишущая форма — ручная "+
			"операция выпуска, и так она и объявлена в рецепте.",
			check.CatalogSyncTarget, syncCalls, check.CatalogCheckTarget)
	}
}
