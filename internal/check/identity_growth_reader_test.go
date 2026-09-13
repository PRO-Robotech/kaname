// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_growth_reader_test.go — ГЕЙТ КЛАССА: у каждого ряда семейства роста
// числа личностей есть НАЗВАННЫЙ читатель (задача #17, порт семейства
// `identitygrowthreader`).
//
// Предмет, граница «исполняемое против объяснения» и довод в пользу своего
// обхода — в шапке `identity_growth_reader.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// identity_growth_reader_injection_test.go.
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

// TestIdentityGrowthMetricsHaveANamedReader — каждый ряд семейства назван хотя
// бы одним выражением правила оповещения.
//
// Имя сохранено дословно с монорепо: семейство перенесено, а не заведено
// заново, и переименование сделало бы ссылки на него ложными молча.
func TestIdentityGrowthMetricsHaveANamedReader(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	collector, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.IdentityGrowthCollectorFile)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: файл коллектора не прочитан (%s): %v",
			check.IdentityGrowthCollectorFile, err)
	}
	declared := check.IdentityGrowthMetricNamesIn(string(collector))
	if len(declared) == 0 {
		t.Fatalf("предпосылка гейта не выполнена: в %s не найдено ни одного имени ряда — "+
			"форма объявления либо приставка словаря изменились, и гейт судит пустоту",
			check.IdentityGrowthCollectorFile)
	}

	doc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.IdentityGrowthReadersFile)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: документ наблюдаемости не прочитан (%s): %v",
			check.IdentityGrowthReadersFile, err)
	}
	exprs := check.AlertExpressionsIn(string(doc))
	if len(exprs) == 0 {
		t.Fatalf("предпосылка гейта не выполнена: в %s не найдено ни одного выражения "+
			"правила — разбор перестал их видеть, и гейт судит пустоту",
			check.IdentityGrowthReadersFile)
	}

	t.Logf("перепись: рядов объявлено %d %v; выражений правил прочитано %d",
		len(declared), declared, len(exprs))

	joined := strings.Join(exprs, "\n")
	var findings []string
	for _, metric := range declared {
		if !strings.Contains(joined, metric) {
			findings = append(findings, "ряд «"+metric+"» объявлен, но его не читает ни одно "+
				"правило оповещения: величина печатается на витрине, ничего не утверждает "+
				"и создаёт уверенность, которой нет")
		}
	}

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("у величины роста числа личностей нет читателя (%d):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}
