// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// peekobjecttypes_internal_test.go — ПРЕДПОСЫЛКА того, что столкновение типов
// судит обход (задача #2015).
//
// Обход снимает типы отдельным разбором ([peekObjectTypes]), потому что перечень
// объявленных типов обязан быть известен ДО того, как хоть один документ будет
// судим целиком, — иначе вердикт о столкновении стал бы функцией порядка обхода.
// Разбор идёт в ТУ ЖЕ структуру и читает ТОТ ЖЕ yaml-тег, поэтому разойтись ему
// не с чем — но «не с чем» есть УТВЕРЖДЕНИЕ О ДЕРЕВЕ, и держит его проба, а не
// эта фраза: смени кто-нибудь тег либо заведи второй разбор — и обход начнёт
// объявлять НЕ ТЕ типы, не дав при этом ни одной находки.
//
// Проба — близнец `peekmodule_internal_test.go` и заведена по тому же доводу.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPeekedObjectTypesAgreeWithTheParsedOnes — снятые типы равны разобранным на
// КАЖДОМ манифесте дерева и на синтетике.
//
// Дерево читается прод-обходом, а не перечнем путей: выписанный перечень
// разошёлся бы с деревом молча ровно на том манифесте, который завели последним.
func TestPeekedObjectTypesAgreeWithTheParsedOnes(t *testing.T) {
	root := repoRootForPeek(t)
	report := CheckTree(root)
	if report.ExitCode() == CheckVoid {
		t.Fatalf("обход дерева %s не дал ни одного манифеста — сверять нечего: %s",
			root, report.Summary())
	}
	if len(report.Manifests) != len(report.Paths) {
		t.Fatalf("разобранных %d при прочитанных %d — дерево несёт находки, и сверка "+
			"шла бы по неполному множеству: %v",
			len(report.Manifests), len(report.Paths), report.Findings)
	}

	seen := 0
	for i, m := range report.Manifests {
		data, err := os.ReadFile(filepath.Join(root, report.Paths[i]))
		if err != nil {
			t.Fatalf("манифест %s не перечитан: %v", report.Paths[i], err)
		}
		want := make([]string, 0, len(m.Resources))
		for k := range m.Resources {
			if typ := m.Resources[k].ObjectType; typ != "" {
				want = append(want, typ)
			}
		}
		got := peekObjectTypes(data)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: снято %v, разобрано %v — обход объявил бы НЕ ТЕ типы, "+
				"не дав ни одной находки", report.Paths[i], got, want)
		}
		seen += len(want)
	}
	if seen == 0 {
		t.Fatal("ни один манифест дерева не объявил типа объекта — сверка беспредметна: " +
			"«снято столько же» здесь неотличимо от «снято ноль»")
	}
	t.Logf("перепись: манифестов дерева сверено %d, типов объекта в них %d",
		len(report.Manifests), seen)

	// Отрицательная сторона: документ, который не разбирается вовсе, типов не
	// даёт — и потому в перечень объявленных не попадает. Без этого «снято
	// пусто» было бы неотличимо от «снят пустой тип».
	for _, doc := range []string{"", "\t: :\n", "- список, а не отображение\n"} {
		if got := peekObjectTypes([]byte(doc)); len(got) != 0 {
			t.Errorf("неразбираемый документ дал типы %v", got)
		}
	}

	// И вторая сторона того же контроля: годный документ типы ДАЁТ. Без неё
	// отрицание выше зеленело бы на разборе, не дающем типов никогда.
	if got := peekObjectTypes([]byte(
		"apiVersion: iam/v1\nmodule: acme\nresources:\n  - name: widget\n    objectType: acme_widget\n",
	)); len(got) != 1 || got[0] != "acme_widget" {
		t.Errorf("годный документ не дал объявленного типа: %v", got)
	}
}
