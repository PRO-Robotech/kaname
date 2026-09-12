// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_proof_run_test.go — по конвейеру СВОЕГО репозитория. Порт
// с монорепо, см. годок `basic_credential_proof_run.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// credentialFormDeclaration — ЕДИНСТВЕННОЕ объявление формы, ОТ КОРНЯ
	// своего модуля (было `services/iam/tests/newman/credential-secret-form.json`).
	credentialFormDeclaration = "tests/newman/credential-secret-form.json"
	// credentialFormMintProof — сверка объявления с ЧЕКАНКОЙ продукта.
	credentialFormMintProof = "tests/newman/scripts/credsecretmint/form_test.go"
	// credentialFormRunProof — НАСТОЯЩИЙ newman-скрипт против подставного края.
	credentialFormRunProof = "tests/newman/scripts/selftest_basic_access_token.py"
	// workflowsDir — конвейер СВОЕГО репозитория.
	workflowsDir = ".github/workflows"
)

// listWorkflows — файлы конвейера, ОТ КОРНЯ своего модуля.
func listWorkflows(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, workflowsDir))
	if err != nil {
		t.Fatalf("%s не прочитан: %v — обход сломан, а не дерево чисто", workflowsDir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			out = append(out, workflowsDir+"/"+name)
		}
	}
	return out
}

// TestBasicCredentialFormProofIsProducedByARun — по дереву. Имя сохранено
// дословно из монорепо.
func TestBasicCredentialFormProofIsProducedByARun(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}

	for _, rel := range []string{
		credentialFormDeclaration, credentialFormMintProof, credentialFormRunProof,
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Fatalf("предпосылка не выполнена: %s не читается (%v).\n"+
				"Это один из трёх предметов задачи #1253 — объявление формы и два его "+
				"читателя. Если предмет снят осознанно, снимайте вместе с ним и этот гейт.",
				rel, err)
		}
	}

	mintRaw, err := os.ReadFile(filepath.Join(root, credentialFormMintProof))
	if err != nil {
		t.Fatalf("%s не прочитан: %v", credentialFormMintProof, err)
	}
	if strings.Contains(string(mintRaw), "//go:build") {
		t.Errorf("%s несёт ограничение сборки — умолчательный `go test ./...` может её "+
			"не исполнить, и сверка формы с чеканкой продукта перестанет производиться "+
			"прогоном", credentialFormMintProof)
	}

	files := listWorkflows(t, root)
	if len(files) == 0 {
		t.Fatalf("в %s не найдено ни одного workflow — обход сломан, а не дерево чисто", workflowsDir)
	}

	runSteps, calls, parsed := 0, 0, 0
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
		calls += check.InvocationsOf(credentialFormRunProof, bodies)
	}

	if parsed == 0 {
		t.Fatal("не разобрано ни одного workflow — вердикт беспредметен")
	}
	if calls == 0 {
		t.Errorf("%s не зовётся НИ ОДНИМ шагом конвейера (осмотрено workflow %d, тел `run:` %d).\n"+
			"Это единственный производитель зелёного утверждения о форме базового "+
			"удостоверения, которому не нужен поднятый стенд, — и он не производит ничего. "+
			"Упоминание в комментарии вызовом не является и здесь намеренно не считается",
			credentialFormRunProof, len(files), runSteps)
	}

	t.Logf("перепись: workflow осмотрено %d (разобрано %d) · тел `run:` %d · "+
		"вызовов производителя %d · читателей объявления 2 (чеканка + newman)",
		len(files), parsed, runSteps, calls)
}
