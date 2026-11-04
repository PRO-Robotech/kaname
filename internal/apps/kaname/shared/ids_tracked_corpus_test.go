// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package shared_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Каждый вариант имеет собственный индекс: treecorpus кеширует список одного
// дерева и его нельзя использовать как изменяемую подстановку внутри одного run.
func TestIDCorpusUsesOnlyTrackedSources(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		t.Run(map[bool]string{false: "непривязанные копии", true: "tracked обычный пакет"}[tracked], func(t *testing.T) {
			dir := t.TempDir()
			run := func(args ...string) {
				cmd := exec.Command("git", args...)
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))
			}
			run("init", "-q")
			write := func(name, src string) {
				p := filepath.Join(dir, name)
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0700))
				require.NoError(t, os.WriteFile(p, []byte(src), 0600))
			}
			write("base.go", "package p")
			write("internal/domain/constants.go", domainFixture)
			write("base_test.go", "package p")
			write(".git/copied.go", "package broken {")
			write("output/copied_test.go", "package broken {")
			write("ordinary/prod.go", injProdCall)
			write("ordinary/fixture_test.go", "package x; var userID = \"usrwrong\"")
			run("add", "base.go", "base_test.go", "internal/domain/constants.go")
			if tracked {
				run("add", "ordinary")
			}
			prod, err := readIDCorpus(dir, false)
			require.NoError(t, err)
			tests, err := readIDCorpus(dir, true)
			require.NoError(t, err)
			want := 1
			if tracked {
				want = 2
			}
			require.Len(t, prod, want+1)
			require.Len(t, tests, want)
			var production []sourceFile
			for _, f := range prod {
				production = append(production, sourceFile{Path: f.Path, AST: f.AST})
			}
			census := inspectFixtureForm(production, tests, dir, nil)
			if tracked {
				require.Len(t, census.Findings, 1)
			} else {
				require.Empty(t, census.Findings)
			}
			if tracked {
				foundProd, foundTest := false, false
				for _, f := range prod {
					if filepath.Base(f.Path) == "prod.go" {
						foundProd = true
					}
				}
				for _, f := range tests {
					if filepath.Base(f.Path) == "fixture_test.go" {
						foundTest = true
					}
				}
				require.True(t, foundProd)
				require.True(t, foundTest)
			}
		})
	}
}

func TestIDCorpusIndexReadAndParseFailures(t *testing.T) {
	for _, mode := range []string{"index", "read", "parse", "empty"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if mode != "index" {
				cmd := exec.Command("git", "init", "-q")
				cmd.Dir = dir
				require.NoError(t, cmd.Run())
				p := filepath.Join(dir, "source.go")
				require.NoError(t, os.WriteFile(p, []byte("package p"), 0600))
				cmd = exec.Command("git", "add", "source.go")
				cmd.Dir = dir
				require.NoError(t, cmd.Run())
				if mode == "read" {
					require.NoError(t, os.Remove(p))
				}
				if mode == "parse" {
					require.NoError(t, os.WriteFile(p, []byte("package {"), 0600))
				}
			}
			_, err := readIDCorpus(dir, mode == "empty")
			require.Error(t, err)
		})
	}
}
