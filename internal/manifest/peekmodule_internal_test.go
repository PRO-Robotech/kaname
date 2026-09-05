// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// peekmodule_internal_test.go — ПРЕДПОСЫЛКА двухступенчатого обхода.
//
// Обход снимает имя модуля отдельным разбором (PeekModule), потому что перечень
// объявленных модулей обязан быть известен ДО того, как хоть один документ будет
// судим целиком. Разбор идёт в ТУ ЖЕ структуру и читает ТОТ ЖЕ yaml-тег, поэтому
// разойтись ему не с чем — но «не с чем» есть УТВЕРЖДЕНИЕ О ДЕРЕВЕ, и держит его
// проба, а не эта фраза: смени кто-нибудь тег либо заведи второй разбор — и
// обход начнёт объявлять НЕ ТЕ модули, не дав при этом ни одной находки.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPeekedModuleAgreesWithTheParsedOne — снятое имя равно разобранному на
// КАЖДОМ манифесте дерева и на синтетике.
//
// Дерево читается прод-обходом, а не перечнем путей: выписанный перечень
// разошёлся бы с деревом молча ровно на том манифесте, который завели последним.
func TestPeekedModuleAgreesWithTheParsedOne(t *testing.T) {
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

	for i, m := range report.Manifests {
		data, err := os.ReadFile(filepath.Join(root, report.Paths[i]))
		if err != nil {
			t.Fatalf("манифест %s не перечитан: %v", report.Paths[i], err)
		}
		if got := PeekModule(data); got != m.Module {
			t.Errorf("%s: снято %q, разобрано %q — обход объявил бы НЕ ТОТ модуль, "+
				"не дав ни одной находки", report.Paths[i], got, m.Module)
		}
	}
	t.Logf("перепись: манифестов дерева сверено %d (%s)",
		len(report.Manifests), strings.Join(report.Modules(), ", "))

	// Отрицательная сторона: документ, который не разбирается вовсе, имени не
	// даёт — и потому в перечень объявленных не попадает. Без этого «снято
	// пусто» было бы неотличимо от «снят пустой модуль».
	for _, doc := range []string{"", "\t: :\n", "- список, а не отображение\n"} {
		if got := PeekModule([]byte(doc)); got != "" {
			t.Errorf("неразбираемый документ дал имя %q", got)
		}
	}
}

// repoRootForPeek — корень дерева продукта: вверх от рабочего каталога до
// каталога с `go.mod`. Выводится, а не выписывается: путь до корня зависит от
// того, откуда запущен прогон.
func repoRootForPeek(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не прочитан: %v", err)
	}
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("корень дерева не найден вверх от рабочего каталога")
		}
		dir = parent
	}
}
