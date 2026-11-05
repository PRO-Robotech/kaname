// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHarnessModelStepsRecursiveControls(t *testing.T) {
	const legal = `package p
import "github.com/PRO-Robotech/kaname/internal/modelcompose"
import "github.com/PRO-Robotech/kaname/internal/authzmodel"
func entry(){ prepare(); authzmodel.Install(text) }
func prepare(){ modelcompose.Compose(text); authzmodel.Admit(text); authzmodel.New(text) }`
	want := []string{"modelcompose.Compose", "authzmodel.Admit", "authzmodel.New", "authzmodel.Install"}
	for _, tc := range []struct {
		name, source string
		red          bool
	}{
		{"helper вызван", legal, false},
		{"неисполненная closure", strings.Replace(legal, "prepare();", "unused := func(){ prepare() }; _ = unused;", 1), true},
		{"shadowed helper", strings.Replace(legal, "prepare();", "prepare := func(){}; prepare();", 1), true},
		{"defer helper", strings.Replace(legal, "prepare();", "defer prepare();", 1), true},
		{"go helper", strings.Replace(legal, "prepare();", "go prepare();", 1), true},
		{"shadowed model package", strings.Replace(legal, "authzmodel.Admit(text);", "authzmodel := fakePackage{}; authzmodel.Admit(text);", 1), true},
		{"правильный import alias", strings.ReplaceAll(strings.Replace(legal, `import "github.com/PRO-Robotech/kaname/internal/authzmodel"`, `import az "github.com/PRO-Robotech/kaname/internal/authzmodel"`, 1), "authzmodel.", "az."), false},
		{"alias New пятый шаг", strings.ReplaceAll(strings.Replace(strings.Replace(legal, `import "github.com/PRO-Robotech/kaname/internal/authzmodel"`, `import az "github.com/PRO-Robotech/kaname/internal/authzmodel"`, 1), "prepare();", "prepare(); authzmodel.New(text);", 1), "authzmodel.", "az."), true},
		{"helper не вызван", strings.Replace(legal, "prepare();", "", 1), true},
		{"потеря Compose", strings.Replace(legal, "modelcompose.Compose(text);", "", 1), true},
		{"потеря Admit", strings.Replace(legal, "authzmodel.Admit(text);", "", 1), true},
		{"потеря New", strings.Replace(legal, "authzmodel.New(text)", "", 1), true},
		{"потеря Install", strings.Replace(legal, "authzmodel.Install(text)", "", 1), true},
		{"перестановка", strings.Replace(legal, "authzmodel.Admit(text); authzmodel.New(text)", "authzmodel.New(text); authzmodel.Admit(text)", 1), true},
		{"вычисляемый callee", strings.Replace(legal, "authzmodel.Install(text)", "authzmodel.New(text).Install(text)", 1), true},
		{"цикл", strings.Replace(legal, "modelcompose.Compose(text);", "prepare();", 1), true},
		{"неизвестный helper", strings.Replace(legal, "prepare();", "missing();", 1), true},
		{"entry переименован", strings.Replace(legal, "func entry", "func other", 1), true},
		{"пустой корпус", "package p", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tc.source, 0)
			require.NoError(t, err)
			got, _, err := expandedModelSteps(f, "entry")
			if tc.name == "alias New пятый шаг" {
				require.NoError(t, err)
				require.Len(t, got, 5)
				require.Equal(t, "authzmodel.New", got[3])
			}
			if tc.red {
				require.True(t, err != nil || strings.Join(got, "/") != strings.Join(want, "/"))
				return
			}
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}

func TestHarnessModelSourceCollectorControls(t *testing.T) {
	const header = `package p
import "github.com/PRO-Robotech/kaname/internal/modelcompose"
import "github.com/PRO-Robotech/kaname/internal/authzmodel"
`
	const helper = `func prepare(){modelcompose.Compose(text);authzmodel.Admit(text);authzmodel.New(text)}`
	want := []string{"modelcompose.Compose", "authzmodel.Admit", "authzmodel.New", "authzmodel.Install"}
	for _, tc := range []struct {
		name                      string
		sibling, child, duplicate bool
		red                       bool
	}{
		{"соседний helper", true, false, false, false},
		{"только чужой child helper", false, true, false, true},
		{"child не подменяет legal helper", true, true, false, false},
		{"повторное объявление", true, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			entry := filepath.Join(dir, "entry.go")
			sources := map[string]string{entry: header + `func entry(){prepare();authzmodel.Install(text)}`}
			if tc.sibling {
				sources[filepath.Join(dir, "helper.go")] = header + helper
			}
			if tc.child {
				sources[filepath.Join(dir, "child", "helper.go")] = header + strings.Replace(helper, "authzmodel.New(text)", "authzmodel.Other(text)", 1)
			}
			if tc.duplicate {
				sources[filepath.Join(dir, "duplicate.go")] = header + helper
			}
			var paths []string
			for p := range sources {
				paths = append(paths, p)
			}
			read := func(p string) ([]byte, error) {
				body, ok := sources[p]
				if !ok {
					return nil, fmt.Errorf("нет source %s", p)
				}
				return []byte(body), nil
			}
			for _, selected := range []string{entry, filepath.Join(dir, ".", "entry.go")} {
				parsed, err := collectModelSources(selected, append(paths, entry), read)
				require.NoError(t, err)
				got, _, err := expandModelSources(parsed, "entry")
				if tc.red {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, want, got)
					require.Len(t, parsed, 2)
				}
			}
			// Относительный entry проходит тот же collector без повторного добавления.
			relative, err := filepath.Rel(".", entry)
			if err != nil {
				absolute, absErr := filepath.Abs(".")
				require.NoError(t, absErr)
				relative, err = filepath.Rel(absolute, entry)
			}
			require.NoError(t, err)
			parsed, err := collectModelSources(relative, append(paths, entry), read)
			require.NoError(t, err)
			got, _, err := expandModelSources(parsed, "entry")
			if tc.red {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, want, got)
				require.Len(t, parsed, 2)
			}
		})
	}
}
