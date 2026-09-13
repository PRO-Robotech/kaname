// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_scope_double_test.go — ГЕЙТ КЛАССА: у снисходительного дублёра области
// видимости назван ЖИВОЙ держатель настоящего отбора (задача #17, порт
// семейства `listscopedoubleisnotlenient`).
//
// Предмет, довод в пользу разбора синтаксиса для одной части и комментариев для
// другой, и почему распознаватель знает ДВЕ формы координаты — в шапке
// `list_scope_double.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// list_scope_double_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestLenientScopeDoubleNamesALiveHolder — имя сохранено дословно с монорепо:
// семейство перенесено, а не заведено заново, и переименование сделало бы
// ссылки на него ложными молча.
func TestLenientScopeDoubleNamesALiveHolder(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	census, findings, err := check.AuditLenientScopes(
		filepath.Join(root, filepath.FromSlash(check.UseCaseAPIRootRel)))
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Log(census.String())
	for _, f := range findings {
		t.Error(f)
	}
}
