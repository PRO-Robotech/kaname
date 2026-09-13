// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package supplyhygiene

// delivered_package_edge_test.go — сам гейт: ребро из поставляемого пакета во
// внутренний объявлено поимённо (kaname#48).

import (
	"os"
	"path/filepath"
	"testing"
)

// deliveredEdgeLedger — объявленные рёбра «поставляемый пакет → внутренний».
//
// Все записи — о РЕШЕНИИ, а не об отсрочке: у каждой названо, почему перенос
// одной из сторон был бы хуже ребра, и чем запись истечёт.
var deliveredEdgeLedger = []DeclaredEdge{
	{
		FromPkg: "subjectchange",
		To:      ModulePath + "/internal/refusaldomain",
		Why: "домен отказа — ИМЯ, которым продукт называет себя перед клиентом, и дом " +
			"у него в дереве один. Перенести объявление в `pkg/` значило бы поставлять " +
			"имя продукта как API — его начали бы настраивать; перенести полосу отказа " +
			"в `internal/` значило бы отнять её у края, который её читает",
		Until: "производитель отказа полосы уехал из `pkg/` ЛИБО имя продукта перестало " +
			"быть величиной процесса",
	},
}

// TestDeliveredPackagesDeclareTheirInternalEdges — гейт.
func TestDeliveredPackagesDeclareTheirInternalEdges(t *testing.T) {
	root := deliveredEdgeTreeRoot(t)

	scan, err := ScanDeliveredEdges(filepath.Join(root, DeliveredDir))
	if err != nil {
		t.Fatalf("обход поставляемых пакетов: %v", err)
	}

	hit := map[string]bool{}
	var findings []string
	for _, e := range scan.Edges {
		d, declared := EdgeIsDeclared(e, deliveredEdgeLedger)
		if !declared {
			findings = append(findings, e.From+" → "+e.To+
				": ребро из поставляемого пакета во внутренний не объявлено. Внешний "+
				"потребитель получает зависимость, которой не может ни настроить, ни "+
				"подменить, и узнать о ней ему неоткуда")
			continue
		}
		hit[d.FromPkg+" → "+d.To] = true
		t.Logf("объявлено: %s → %s — %s (истекает, когда %s)", e.From, e.To, d.Why, d.Until)
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, импортов %d, рёбер в `internal/` %d, "+
		"ведомость объявлений: %d записей, из них сработало %d, находок %d",
		scan.Files, scan.Imports, len(scan.Edges), len(deliveredEdgeLedger), len(hit), len(findings))

	if scan.Files == 0 {
		t.Fatalf("обход пуст: в %s не разобрано ни одного файла — вердикт беспредметен",
			filepath.Join(root, DeliveredDir))
	}
	if scan.Imports == 0 {
		t.Fatalf("на %d файлах не найдено НИ ОДНОГО импорта — разбор перестал видеть предмет",
			scan.Files)
	}
	for _, d := range deliveredEdgeLedger {
		if !hit[d.FromPkg+" → "+d.To] {
			t.Errorf("ведомости нечего объявлять в %s → %s: записи здесь больше не место — %s",
				d.FromPkg, d.To, d.Until)
		}
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

// deliveredEdgeTreeRoot — корень дерева службы: подъём до `go.mod`.
//
// Своё, а не чужой помощник соседнего файла: имя пакета общее, и полоса,
// снявшая свой файл, унесла бы с собой чужой гейт.
func deliveredEdgeTreeRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень дерева не найден: `go.mod` не встретился до корня файловой системы")
		}
		dir = parent
	}
}
