// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// project_deletion_surfaces_injection_test.go — доказательство, что держатель
// поверхностей удаления проекта СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Инъекция идёт НАСТОЯЩИМ входом из дерева: живой файл правится по ОДНОМУ факту
// (возвращено снятое отрицание · снята формулировка границы · снята ссылка на
// преемника · возвращён второй тон), и находка обязана назвать координату.
// Законный близнец — живой файл без правки — обязан молчать.
package supplyhygiene

import (
	"strings"
	"testing"
)

func mutate(t *testing.T, body, old, replacement string) string {
	t.Helper()
	if !strings.Contains(body, old) {
		t.Fatalf("инъекция беспредметна: фрагмента %q в живом файле нет", old)
	}
	return strings.Replace(body, old, replacement, 1)
}

func requireFinding(t *testing.T, findings []string, wantInText string) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatalf("инъекция не покраснела: держатель не способен упасть на этом входе")
	}
	if !strings.Contains(strings.Join(findings, " | "), wantInText) {
		t.Fatalf("находка не называет %q: %v", wantInText, findings)
	}
}

func TestProjectDeletionSurfaces_Injection_ProjectPage(t *testing.T) {
	t.Parallel()
	live := readSurface(t, projectPagePath)
	require0 := func(name string, findings []string) {
		t.Helper()
		if len(findings) != 0 {
			t.Fatalf("%s: законный близнец покраснел: %v", name, findings)
		}
	}
	require0("живая страница", judgeProjectPage(live))

	t.Run("возвращено отрицание проверки", func(t *testing.T) {
		mutated := live + "\n\nУ проекта проверки ссылок **нет**.\n"
		requireFinding(t, judgeProjectPage(mutated), "проверки ссылок **нет**")
	})
	t.Run("снята формулировка границы", func(t *testing.T) {
		mutated := mutate(t, live, "защита от штатной ошибки", "защита")
		requireFinding(t, judgeProjectPage(mutated), "§7.4")
	})
	t.Run("снят признак полосы", func(t *testing.T) {
		mutated := strings.ReplaceAll(live, "REFERENCE_IN_USE", "REFERENCE-IN-USE")
		requireFinding(t, judgeProjectPage(mutated), "REFERENCE_IN_USE")
	})
	t.Run("снята ссылка на преемника", func(t *testing.T) {
		mutated := strings.ReplaceAll(live, "issues/"+successorIssueNumber, "issues/0")
		requireFinding(t, judgeProjectPage(mutated), "#"+successorIssueNumber)
	})
	t.Run("возвращено обещание немедленного прекращения", func(t *testing.T) {
		mutated := live + "\n| создание новых ресурсов | **прекращается** |\n"
		requireFinding(t, judgeProjectPage(mutated), "прекращается")
	})
}

func TestProjectDeletionSurfaces_Injection_ContractAndHeaders(t *testing.T) {
	t.Parallel()
	contract := readSurface(t, projectContractPath)
	useCase := readSurface(t, projectUseCasePath)
	repo := readSurface(t, projectRepoPath)
	note := readSurface(t, projectEngNotePath)
	if f := judgeContractAndHeaders(contract, useCase, repo, note); len(f) != 0 {
		t.Fatalf("законный близнец покраснел: %v", f)
	}

	t.Run("контракт снова обещает отсутствие проверки", func(t *testing.T) {
		requireFinding(t, judgeContractAndHeaders(contract+"\n// NOT BLOCKED BY LIVE RESOURCES\n", useCase, repo, note),
			"NOT BLOCKED BY LIVE RESOURCES")
	})
	t.Run("контракт потерял границу", func(t *testing.T) {
		mutated := mutate(t, contract, "does not arrive instantly", "arrives")
		requireFinding(t, judgeContractAndHeaders(mutated, useCase, repo, note), "does not arrive instantly")
	})
	t.Run("контракт потерял преемника", func(t *testing.T) {
		mutated := strings.ReplaceAll(contract, "#"+successorIssueNumber, "#0")
		requireFinding(t, judgeContractAndHeaders(mutated, useCase, repo, note), "#"+successorIssueNumber)
	})
	t.Run("шапка прикладника снова обещает peer-callback", func(t *testing.T) {
		requireFinding(t, judgeContractAndHeaders(contract, "// Future: peer-callback\n"+useCase, repo, note), "peer-callback")
	})
	t.Run("шапка писателя снова называет DELETE простым", func(t *testing.T) {
		requireFinding(t, judgeContractAndHeaders(contract, useCase, "// Простой DELETE.\n"+repo, note), "Простой DELETE")
	})
	t.Run("записка снова называет peer-API", func(t *testing.T) {
		requireFinding(t, judgeContractAndHeaders(contract, useCase, repo, note+"\nпроверяется через peer-API\n"), "peer-API")
	})
}

func TestProjectDeletionSurfaces_Injection_OtherSurfaces(t *testing.T) {
	t.Parallel()
	tfModule := readSurface(t, tfModuleProjectPath)
	tfProvider := readSurface(t, tfProviderPath)
	overview := readSurface(t, apiOverviewPath)
	if f := judgeOtherSurfaces(tfModule, tfProvider, overview); len(f) != 0 {
		t.Fatalf("законный близнец покраснел: %v", f)
	}

	t.Run("модуль Terraform снова называет роль единственным условием", func(t *testing.T) {
		mutated := tfModule + "\nПроект удалится последним, только если в нём не осталось пользовательских ролей.\n"
		requireFinding(t, judgeOtherSurfaces(mutated, tfProvider, overview), "только если")
	})
	t.Run("клетка строки «Проект» потеряла второй род", func(t *testing.T) {
		cell, ok := providerBlockerCell(tfProvider)
		if !ok {
			t.Fatalf("инъекция беспредметна: строки «Проект» нет")
		}
		mutated := strings.Replace(tfProvider, cell, " Пользовательская роль ", 1)
		requireFinding(t, judgeOtherSurfaces(tfModule, mutated, overview), "не оба рода")
	})
	t.Run("строка кодов потеряла непустой проект", func(t *testing.T) {
		row, ok := overviewFailedPreconditionRow(overview)
		if !ok {
			t.Fatalf("инъекция беспредметна: строки FAILED_PRECONDITION нет")
		}
		mutated := strings.Replace(overview, row,
			"<tr><td><code>FAILED_PRECONDITION</code></td><td>400</td><td>Состояние не позволяет</td></tr>", 1)
		requireFinding(t, judgeOtherSurfaces(tfModule, tfProvider, mutated), "непустого проекта")
	})
	t.Run("второй тон отказа", func(t *testing.T) {
		mutated := tfProvider + "\nProject <id> contains roles and cannot be deleted\n"
		requireFinding(t, judgeOtherSurfaces(tfModule, mutated, overview), "второй тон")
	})
}
