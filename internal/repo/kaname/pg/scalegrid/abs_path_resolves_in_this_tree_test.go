// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// abs_path_resolves_in_this_tree_test.go — координата артефакта приводится к
// диску ТЕМ ЖЕ разрешителем, каким её читает гейт свежести.
//
// # Предмет
//
// Координата отчёта названа ОДНА, а мест, приводящих её к диску, было два:
// гейт свежести (через `treeposture`, знающий про приставку поставки модуля) и
// писатель отчёта (склейка с вершиной git). В монорепо оба отвечали одинаково,
// и расхождения не было видно. После выноса службы отдельным репозиторием
// читатель файл находит, а писатель — нет.
//
// # Цена измерена, а не предположена
//
// Пересъёмка отчёта объёма отработала все четыре точки сетки — 944 с на
// поднятой базе — и не смогла записать результат: «no such file or directory».
// Гейт свежести объявлял отчёт устаревшим, а исполнить его требование было
// НЕЧЕМ.
package scalegrid_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestArtifactPathResolvesWhereTheFreshnessGateReadsIt — писатель и читатель
// приводят ОДНУ координату к ОДНОМУ месту.
//
// Утверждение проверяемо в обеих посадках: в монорепо приставка есть и
// сохраняется, в самостоятельном клоне снимается, — и в обеих каталог отчёта
// обязан существовать, иначе запись отказывает.
func TestArtifactPathResolvesWhereTheFreshnessGateReadsIt(t *testing.T) {
	t.Parallel()

	for _, rel := range []string{scalegrid.ReportPath, scalegrid.StrengthReportPath} {
		byWriter, err := scalegrid.AbsPathOf(rel)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: писатель не разрешил %s: %v", rel, err)
		}
		byReader := platformtree.RequirePath(t, rel)
		if byWriter != byReader {
			t.Errorf("координата %s приводится к РАЗНЫМ местам:\n  писатель: %s\n  читатель: %s\n"+
				"Гейт свежести объявит отчёт устаревшим, а исполнить его требование будет нечем: "+
				"замер отработает и не запишется.", rel, byWriter, byReader)
			continue
		}
		// Каталог обязан существовать: писать некуда — то же самое, что не писать.
		if st, serr := os.Stat(filepath.Dir(byWriter)); serr != nil || !st.IsDir() {
			t.Errorf("каталог артефакта %s не существует (%v) — запись отчёта отказала бы",
				filepath.Dir(byWriter), serr)
		}
		t.Logf("координата %s → %s", rel, byWriter)
	}
}

// TestArtifactRootIsTheTreeRoot — пустая координата означает КОРЕНЬ дерева
// прогона, и это поведение сохранено: его читает соседний прибор.
func TestArtifactRootIsTheTreeRoot(t *testing.T) {
	t.Parallel()
	root, err := scalegrid.AbsPathOf("")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень не разрешён: %v", err)
	}
	if st, serr := os.Stat(filepath.Join(root, "go.mod")); serr != nil || st.IsDir() {
		t.Fatalf("разрешённый корень %s не несёт go.mod — это не корень дерева прогона", root)
	}
}
