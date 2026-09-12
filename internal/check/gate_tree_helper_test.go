// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// gate_tree_helper_test.go — тонкая обёртка над составом git-дерева для
// гейтов, читающих индекс git своего модуля (не платформы). Аналог
// `trackedTree` монорепо (`internal/repohygiene/trackedtree_test.go`),
// сведённый к тому минимуму, который здесь нужен — `has(rel)` и перечень
// файлов.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// gateFileTree — состав дерева, прочитанный ИНДЕКСОМ git.
type gateFileTree struct {
	files map[string]bool
}

func (t gateFileTree) has(rel string) bool { return t.files[rel] }

// gateTree читает индекс git. Недоступность git — ОТКАЗ, а не пропуск.
func gateTree(t *testing.T, root string) gateFileTree {
	t.Helper()
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("состав дерева %s: %v — гейт не может назвать дерево, о котором "+
			"он говорит", root, err)
	}
	return gateFileTree{files: tree.Files()}
}
