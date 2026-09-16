// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package servicemanifest

// identity_test.go — встроенная копия манифеста службы равна манифесту дерева
// ПОБАЙТОВО (приёмка MRW-1, Р2; признак готовности S1).
//
// Копий две, и это цена принятого исхода: директива встраивания родительского
// каталога не принимает, поэтому копия лежит в каталоге ЭТОГО пакета. Держат
// пару ДВА артефакта разного рода, и путать их нельзя: цель сборки
// `make service-manifest-embed` копию ПОРОЖДАЕТ (восстанавливает), а равенство
// ДЕРЖИТ эта проба — правка `manifest.yaml` без пересборки копии роняет ЕЁ, а не
// цель. Образец — `internal/authzmodel` `TestEmbeddedModelIsByteIdenticalToCanonical`.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

func TestEmbeddedManifestIsByteIdenticalToTheTree(t *testing.T) {
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("корень модуля не назван: %v — сверять не с чем, и это не ноль находок", err)
	}
	treePath := filepath.Join(root, manifest.TreeFileName())
	tree, err := os.ReadFile(treePath) // #nosec G304 -- путь от корня модуля, снаружи не приходит
	if err != nil {
		t.Fatalf("манифест дерева %s не прочитан: %v", treePath, err)
	}
	if len(tree) == 0 {
		t.Fatal("манифест дерева прочитан как ноль байт — сравнивать не с чем")
	}
	embedded := Raw()
	if len(embedded) == 0 {
		t.Fatal("встроенная копия пуста — применитель посева получил бы документ без раздела `seed`")
	}
	t.Logf("перепись: манифест дерева %d байт · встроенная копия %d байт", len(tree), len(embedded))
	if string(tree) != string(embedded) {
		t.Fatalf("встроенная копия разошлась с %s (дерево %d байт, копия %d байт). "+
			"Правится ТОЛЬКО манифест дерева; копия порождается `make service-manifest-embed`. "+
			"Пока они разные, оснастка дерева судит один документ, а до старта службы "+
			"доезжает другой — и это не отказ, а группа, объявленная не тем, что проверяли",
			treePath, len(tree), len(embedded))
	}
}

// TestEmbeddedManifestLoadsWithTheSameJudgeAsTheTree — копия читается ТЕМ ЖЕ
// загрузчиком, что и манифест дерева, и без оракула модели: второй судья для
// второго документа разошёлся бы с первым молча (Р3).
func TestEmbeddedManifestLoadsWithTheSameJudgeAsTheTree(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("встроенный манифест не разобран: %v", err)
	}
	if m.Module != "iam" {
		t.Fatalf("встроенный манифест объявляет модуль %q, а не iam", m.Module)
	}
}
