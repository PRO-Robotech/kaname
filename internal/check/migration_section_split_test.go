// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestMigrationSectionSplitIsDeclaredOnce — несущее утверждение: директива
// секции мигратора выписана в не-тестовом дереве ровно там, где объявлена.
//
// Предмет, границы и замер, из которого гейт выведен, — в шапке
// `migration_section_split.go`; здесь они не пересказываются.
func TestMigrationSectionSplitIsDeclaredOnce(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен")

	root, err := platformtree.ModuleRootFrom(wd)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден")

	tree, err := treecorpus.NewTree(root)
	require.NoErrorf(t, err, "состав дерева не установлен — «ноль находок» здесь "+
		"означало бы «ноль прочитанного»")

	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корпус не собран")

	findings, census, err := check.AuditMigrationSectionSplit(corpus)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ")

	t.Logf("перепись: не-тестовых файлов Go прочитано %d (разобрано %d) · литералов с "+
		"директивой секции встречено %d · из них у владельца разбора %d · находок %d",
		census.FilesRead, census.FilesParsed, census.Literals, census.OwnerLiterals,
		len(findings))

	require.Empty(t, findings,
		"директива секции мигратора выписана вторым местом — разрез разойдётся молча:\n%s",
		findings)
}
