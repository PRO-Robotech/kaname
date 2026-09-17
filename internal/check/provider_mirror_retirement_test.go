// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"

	// Регистрирует дескрипторы контракта службы в глобальном реестре.
	_ "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// providerMirrorPageTerms — что страница решения обязана называть. Имя ряда
// берётся у производителя, а не выписывается.
func providerMirrorPageTerms() []string {
	return []string{
		"service_account_oauth_clients",
		"user_oauth_clients",
		check.ProviderMirrorFieldName,
		string(check.ProviderMirrorLegacyValue),
		metrics.ProviderMirrorRowsMetric,
		"hydra_client_id <> id",
		"hydra_client_id IS NOT NULL",
		"reserved",
	}
}

// TestProviderMirrorFieldAndLegacyKindAreDeclaredLeaving — три места согласны:
// контракт объявляет уходящее уходящим, страница решения записана и называет
// окно, ряд и снимаемые имена.
func TestProviderMirrorFieldAndLegacyKindAreDeclaredLeaving(t *testing.T) {
	t.Parallel()

	findings, census := check.JudgeProviderMirrorContract(protoregistry.GlobalFiles)
	t.Log(census)
	if census.MessagesFound == 0 {
		t.Fatalf("ни одно из %d сообщений контракта не найдено в реестре — обход беспредметен",
			len(check.ProviderMirrorMessages))
	}
	for _, f := range findings {
		t.Error(f)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.ProviderMirrorRetirementPageRel)))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("чтение %s: %v", check.ProviderMirrorRetirementPageRel, err)
	}
	pageFindings, pageCensus := check.JudgeProviderMirrorPage(string(body), providerMirrorPageTerms())
	t.Log(pageCensus)
	for _, f := range pageFindings {
		t.Error(f)
	}
}
