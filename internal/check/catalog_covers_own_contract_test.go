// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_covers_own_contract_test.go — TestOwnCatalogCopyCoversOwnContract:
// у каждого RPC контракта службы есть строка в её копии каталога прав, и строка
// совпадает с аннотациями; своя строка без RPC — находка. Разбор — в годке
// `catalog_covers_contract.go`.
//
// Стабы контракта линкуются сюда явно: обход идёт по реестру дескрипторов
// этого двоичного файла, и без импорта он был бы пуст — гейт сказал бы об этом
// третьим исходом, а не зелёным.
package check_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/check"
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1" // регистрирует дескрипторы контракта службы
)

const (
	// ownContractPathPrefix — корень контрактов службы в её дереве `proto/`;
	// путь файла в реестре дескрипторов относителен ему.
	ownContractPathPrefix = "kaname/"
	// ownCatalogCopyPath — своя копия каталога прав, вшиваемая в образ.
	ownCatalogCopyPath = "internal/apps/kaname/seed/embedded/permission_catalog.json"
)

func TestOwnCatalogCopyCoversOwnContract(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ownCatalogCopyPath)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: своя копия каталога не прочитана: %v", err)
	}
	var rows []catalogderive.Entry
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: своя копия каталога не разобрана: %v", err)
	}

	methods, files := check.OwnContractMethods(ownContractPathPrefix)
	if files == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: под приставкой %q не зарегистрирован ни один файл контракта", ownContractPathPrefix)
	}

	findings, census, err := check.CompareCatalogWithContract(rows, methods)
	t.Logf("%s · файлов контракта %d · находок %d", census, files, len(findings))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	for _, f := range findings {
		t.Errorf("копия каталога прав разошлась с контрактом службы:\n  %s", f)
	}
}
