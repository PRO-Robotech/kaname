// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// mirror_divergence_wiring_test.go — сам гейт: у читателя разности есть
// вызывающий в композиционном корне (kacho#1828).

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMirrorDivergenceIsReadByTheCompositionRoot — гейт.
func TestMirrorDivergenceIsReadByTheCompositionRoot(t *testing.T) {
	root := filepath.Join(mirrorWiringTreeRoot(t), "cmd")

	scan, err := ScanMirrorDivergenceWiring(root)
	if err != nil {
		t.Fatalf("обход композиционного корня: %v", err)
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, вызовов `%s` найдено %d, "+
		"места вызова: %v", scan.Files, MirrorDivergenceFunc, scan.Calls, scan.CallSites)

	if scan.Files == 0 {
		t.Fatalf("обход пуст: в %s не разобрано ни одного файла — вердикт беспредметен", root)
	}
	if scan.Calls == 0 {
		t.Errorf("читателя разности зеркала и каталога не зовёт ни один путь исполнения: "+
			"на поднятом стенде величина не производится, и «разности нет» неотличимо от "+
			"«никто не мерил» (разобрано файлов %d)", scan.Files)
	}
}

// mirrorWiringTreeRoot — корень дерева службы: подъём до `go.mod`.
//
// Своё, а не чужой помощник соседнего файла: имя пакета общее, и полоса,
// снявшая свой файл, унесла бы с собой чужой гейт.
func mirrorWiringTreeRoot(t *testing.T) string {
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
