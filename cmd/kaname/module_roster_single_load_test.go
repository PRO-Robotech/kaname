// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_roster_single_load_test.go — перечень личностей модулей читается из
// настройки ОДИН раз, в корне, с проверкой ошибки, и одно значение уходит всем
// потребителям (kaname#987 вместе с kaname#984).
//
// # Предмет
//
// Нулевой перечень у потребителей значит разное: политике вызывающего — «модуль
// никто», то есть отказ; обработчику внутреннего Check — «сужать некого», то
// есть привязка плоскости данных к домену не применяется. Чтение, глотающее
// ошибку, отдавало бы нулевое значение одним потребителям, пока корень, читавший
// позже с проверкой, отдавал разобранное другим: обработчик и политика судили бы
// по разным перечням. Поэтому чтение одно, и других путей к перечню у корня нет.
//
// Судится узлом разбора: вызов с именем `LoadModuleRoster` (чтение с ошибкой) и
// вызов без доводов с именем `ModuleRoster` (чтение, глотающее ошибку). Слово в
// комментарии и в строке предметом не является.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// rosterReads — координаты чтений перечня в файлах: с проверкой ошибки и без неё.
func rosterReads(fset *token.FileSet, files []*ast.File) (loads, swallows []string) {
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch {
			case sel.Sel.Name == "LoadModuleRoster":
				loads = append(loads, fset.Position(call.Pos()).String())
			case sel.Sel.Name == "ModuleRoster" && len(call.Args) == 0:
				swallows = append(swallows, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return loads, swallows
}

// parseRosterSources — разбор набора исходников «имя → текст».
func parseRosterSources(t *testing.T, fset *token.FileSet, sources map[string]string) []*ast.File {
	t.Helper()
	files := make([]*ast.File, 0, len(sources))
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		require.NoErrorf(t, err, "разбор %s", name)
		files = append(files, f)
	}
	return files
}

// TestModuleRosterIsLoadedOnceInTheRoot — прод-код корня читает перечень ровно
// одним вызовом с проверкой ошибки и ни одним, глотающим её.
func TestModuleRosterIsLoadedOnceInTheRoot(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var files []*ast.File
	lines := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		require.NoError(t, err)
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		require.NoErrorf(t, err, "разбор %s", name)
		files = append(files, f)
		lines += strings.Count(string(src), "\n")
	}
	loads, swallows := rosterReads(fset, files)
	t.Logf("осмотрено: файлов прод-кода корня %d, строк %d; чтений перечня с проверкой ошибки %d, глотающих её %d",
		len(files), lines, len(loads), len(swallows))
	require.NotEmpty(t, files, "обход корня не прочёл ни одного файла: вердикта нет")
	require.Emptyf(t, swallows, "чтение перечня, глотающее ошибку, в корне: %v", swallows)
	require.Lenf(t, loads, 1, "перечень читается из настройки не одним вызовом: %v", loads)
}

// TestModuleRosterReadJudge_FindsBothDefectsAndSparesTheLawfulForm — судья
// чтений краснеет на обоих дефектах с координатой и молчит на законной форме.
func TestModuleRosterReadJudge_FindsBothDefectsAndSparesTheLawfulForm(t *testing.T) {
	const lawful = `package main
func build(cfg Config) error {
	// ModuleRoster() в комментарии предметом не является
	roster, err := cfg.AuthN.LoadModuleRoster()
	if err != nil {
		return err
	}
	_ = policy.WithModuleRoster(roster)
	_ = handler.WithModuleRoster(roster)
	_ = "cfg.AuthN.ModuleRoster()"
	return nil
}
`
	const swallowing = `package main
func wire(cfg Config) { _ = handler.WithModuleRoster(cfg.AuthN.ModuleRoster()) }
`
	const secondLoad = `package main
func other(cfg Config) { r, _ := cfg.AuthN.LoadModuleRoster(); _ = r }
`
	t.Run("законная форма — молчание", func(t *testing.T) {
		fset := token.NewFileSet()
		loads, swallows := rosterReads(fset, parseRosterSources(t, fset, map[string]string{"serve.go": lawful}))
		require.Len(t, loads, 1)
		require.Empty(t, swallows)
	})
	t.Run("чтение, глотающее ошибку, — находка с координатой", func(t *testing.T) {
		fset := token.NewFileSet()
		_, swallows := rosterReads(fset, parseRosterSources(t, fset, map[string]string{"serve.go": lawful, "wiring.go": swallowing}))
		require.Equal(t, []string{"wiring.go:2:54"}, swallows)
	})
	t.Run("второе чтение с ошибкой — находка с координатой", func(t *testing.T) {
		fset := token.NewFileSet()
		loads, _ := rosterReads(fset, parseRosterSources(t, fset, map[string]string{"serve.go": lawful, "other.go": secondLoad}))
		require.Len(t, loads, 2)
		require.Contains(t, loads, "other.go:2:34")
	})
}
