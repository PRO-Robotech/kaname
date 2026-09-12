// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_operation_response_state_test.go — вердикт о НАСТОЯЩЕМ дереве kaname.
//
// Порт с монорепо (`internal/repohygiene/roleoperationresponsestate_test.go`,
// снят вынесением службы — `kacho#2597`). Изменилось: `ServiceRoot` пустая
// строка (в kaname дерево службы лежит от корня), обход корня
// (`repoRoot(t)` → `platformtree.RequireCorpus(t)`).
//
// Способность падать доказывает не этот прогон, а инъекция
// (`role_operation_response_state_injection_test.go`): здесь только вердикт.
package check_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func roleOpStateOptions(t *testing.T) check.RoleOperationResponseStateOptions {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	return check.RoleOperationResponseStateOptions{
		Root:             corpusRoot,
		ServiceRoot:      filepath.ToSlash(modulePrefix),
		DomainPkg:        "domain",
		RoleType:         "Role",
		TransferFunc:     "Transfer",
		ProjectionMethod: "WithoutComputedState",
	}
}

// TestRoleOperationResponseCarriesNoComputedState — сам гейт.
func TestRoleOperationResponseCarriesNoComputedState(t *testing.T) {
	var log strings.Builder
	findings, census, err := check.AuditRoleOperationResponseState(roleOpStateOptions(t), &log)
	if err != nil {
		t.Fatalf("анализатор не отработал: %v", err)
	}
	t.Log(strings.TrimSpace(log.String()))

	if census.Files < 200 {
		t.Fatalf("файлов Go прочитано %d — обход пуст, вердикт беспредметен", census.Files)
	}
	if census.Funcs < 1000 {
		t.Fatalf("функций разобрано %d — разбор перестал видеть объявления", census.Funcs)
	}
	if census.AnypbFuncs < 20 {
		t.Fatalf("функций, возвращающих ответ операции, %d — признак разошёлся с деревом",
			census.AnypbFuncs)
	}
	if census.RoleTranslators < 2 {
		t.Fatalf("переводчиков роли найдено %d, ожидалось не меньше 2 — признак разошёлся "+
			"с деревом", census.RoleTranslators)
	}

	if len(findings) == 0 {
		return
	}
	lines := make([]string, 0, len(findings))
	for _, f := range findings {
		lines = append(lines, "  "+f.String())
	}
	t.Errorf("ответ операции над ролью может понести ВЫЧИСЛЕННОЕ состояние "+
		"(переводчиков роли %d, зовут проекцию %d):\n%s\n\n"+
		"Контракт обещает арендатору, что нулевые health и lifecycle в ответе операции "+
		"означают «этим ответом не вычислено», а не «роль здорова и объявлена». Состояние, "+
		"посчитанное на пути мутации, относится к ДРУГОМУ снимку проекции — публиковать его "+
		"значит отвечать про состояние, которого у роли не было ни до, ни после. Снятие — "+
		"звать domain.Role.WithoutComputedState() в переводчике.",
		census.RoleTranslators, census.ProjectionCalled, strings.Join(lines, "\n"))
}
