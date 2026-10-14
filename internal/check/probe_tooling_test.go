// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// probe_tooling_test.go — оснастка проб (`internal/testsupport/`) не
// импортируется ни одним файлом прод-сборки (задача PRO-Robotech/kaname#816).
// Это предпосылка, на которой гейты прод-кода не судят оснастку проб так же,
// как не судят `*_test.go`: без неё исключение было бы дырой.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestProbeToolingIsImportedOnlyByProbes(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	module, err := check.TreeModulePath(root)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: путь модуля не установлен")
	tree, err := treecorpus.NewTree(root)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не установлен")
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корпус не собран")

	c, err := check.ProbeToolingImports(corpus, module)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ")
	t.Logf("перепись: не-тестовых файлов Go разобрано %d · из них оснастки проб %d · прод-сборки %d · импортов оснастки из прод-сборки %d",
		c.FilesParsed, c.ProbeToolingFiles, c.ShippedFiles, len(c.Findings))
	for _, f := range c.Findings {
		t.Error(f)
	}
}

const ptModule = "example.org/m"

func ptRun(t *testing.T, files map[string]string) check.ProbeToolingCensus {
	t.Helper()
	c, err := check.ProbeToolingImports(check.TreeCorpus(files), ptModule)
	require.NoError(t, err)
	return c
}

// Законный близнец: оснастка импортирует оснастку, прод-код — свой пакет с
// похожим именем; молчит.
func TestProbeToolingInjection_LawfulTwinIsSilent(t *testing.T) {
	t.Parallel()
	c := ptRun(t, map[string]string{
		"internal/testsupport/a/a.go": "package a\nimport _ \"" + ptModule + "/internal/testsupport/b\"\n",
		"internal/testsupport/b/b.go": "package b\n",
		"internal/app/x.go":           "package app\nimport _ \"" + ptModule + "/internal/testsupportlike\"\n",
		"internal/testsupportlike/y.go": "package testsupportlike\n" +
			"// \"" + ptModule + "/internal/testsupport/a\" в комментарии — не импорт\n",
	})
	require.Empty(t, c.Findings, "законный близнец обязан молчать")
	require.Equal(t, 4, c.FilesParsed)
	require.Equal(t, 2, c.ProbeToolingFiles)
	require.Equal(t, 2, c.ShippedFiles)
}

// Каждая законная форма импорта из прод-сборки краснеет и называет координату.
func TestProbeToolingInjection_EveryImportFormIsFound(t *testing.T) {
	t.Parallel()
	tooling := map[string]string{"internal/testsupport/a/a.go": "package a\n"}
	cases := map[string]struct {
		src  string
		want string
	}{
		"обычный":    {"package app\nimport \"" + ptModule + "/internal/testsupport/a\"\n", "internal/app/x.go:2"},
		"псевдоним":  {"package app\nimport z \"" + ptModule + "/internal/testsupport/a\"\n", "internal/app/x.go:2"},
		"с точкой":   {"package app\nimport . \"" + ptModule + "/internal/testsupport/a\"\n", "internal/app/x.go:2"},
		"пустое имя": {"package app\nimport _ \"" + ptModule + "/internal/testsupport/a\"\n", "internal/app/x.go:2"},
		"группа":     {"package app\nimport (\n\t\"fmt\"\n\t\"" + ptModule + "/internal/testsupport/a\"\n)\n", "internal/app/x.go:4"},
		"корень":     {"package app\nimport \"" + ptModule + "/internal/testsupport\"\n", "internal/app/x.go:2"},
		"тег сборки": {"//go:build never\n\npackage app\nimport \"" + ptModule + "/internal/testsupport/a\"\n", "internal/app/x.go:4"},
		"вложенный":  {"package app\nimport \"" + ptModule + "/internal/testsupport/a/deep\"\n", "internal/app/x.go:2"},
		"из cmd":     {"package main\nimport \"" + ptModule + "/internal/testsupport/a\"\n", "cmd/x/main.go:2"},
	}
	for name, tc := range cases {
		files := map[string]string{}
		for k, v := range tooling {
			files[k] = v
		}
		rel := "internal/app/x.go"
		if strings.HasPrefix(tc.want, "cmd/") {
			rel = "cmd/x/main.go"
		}
		files[rel] = tc.src
		c := ptRun(t, files)
		found := false
		for _, f := range c.Findings {
			if strings.Contains(f, tc.want) && strings.Contains(f, "internal/testsupport") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: импорт оснастки из прод-сборки не найден (ждали %q): %v", name, tc.want, c.Findings)
		}
	}
}

// Исключение, которому нечего исключать, — находка: оснастки проб в дереве
// нет, и гейты, снимающие её с суда, исключают пустоту.
func TestProbeToolingInjection_ExemptionWithoutSubjectIsFound(t *testing.T) {
	t.Parallel()
	c := ptRun(t, map[string]string{"internal/app/x.go": "package app\n"})
	require.Len(t, c.Findings, 1)
	require.Contains(t, c.Findings[0], "оснастки проб в обходе нет")
}

// Пустой обход — отказ, а не «находок нет».
func TestProbeToolingInjection_EmptyCorpusIsARefusal(t *testing.T) {
	t.Parallel()
	_, err := check.ProbeToolingImports(check.TreeCorpus{}, ptModule)
	require.ErrorIs(t, err, check.ErrEmptyTraversal)
}

// Нечитаемый файл — отказ прогона с координатой, а не молчание.
func TestProbeToolingInjection_UnparsableFileIsARefusal(t *testing.T) {
	t.Parallel()
	_, err := check.ProbeToolingImports(check.TreeCorpus{
		"internal/testsupport/a/a.go": "package a\n",
		"internal/app/x.go":           "package app\nimport (\n",
	}, ptModule)
	require.ErrorContains(t, err, "internal/app/x.go")
}

// Отбор гейтов прод-кода: оснастка проб — не прод-сборка, `*_test.go` — тоже.
func TestShippedGoFileSelection(t *testing.T) {
	t.Parallel()
	for rel, want := range map[string]bool{
		"internal/app/x.go":                          true,
		"cmd/kaname/main.go":                         true,
		"internal/testsupport/activewayin/a.go":      false,
		"internal/testsupport/activewayin/a_test.go": false,
		"internal/app/x_test.go":                     false,
		"internal/testsupportlike/y.go":              true,
	} {
		require.Equalf(t, want, check.ShippedGoFile(rel), "%s", rel)
		require.Equalf(t, strings.HasPrefix(rel, "internal/testsupport/") && !strings.HasSuffix(rel, "_test.go"),
			check.ProbeToolingGoFile(rel), "%s", rel)
	}
}
