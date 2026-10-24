// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package contracttext — пробы того, что ПРОЗА контракта iam v1 говорит о
// поведении службы то же, что делает её код.
//
// # Что читается и почему так
//
// Тексты контракта берутся из комментариев ПОРОЖДЁННЫХ заглушек, привязанных к
// узлу разбора: шапка типа, поле сообщения, метод клиентского интерфейса.
// Заглушки порождаются из `.proto` и сверяются с ним целью `proto-gen-diff`,
// поэтому их текст и есть текст контракта; Go-разбор привязывает текст к узлу,
// а не к строке файла. Правится всегда `.proto`, заглушки — регенерацией.
//
// Каждая проба — чистый предикат над текстами плюс прогон на дереве. Предикат
// гоняется инъекцией (дефектный текст краснит, исправный молчит), прогон на
// дереве отказывает, если не прочитал ни одного предмета: «ноль находок»
// отличим от «ноль прочитанного».
package contracttext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// stubDir — порождённые заглушки контракта службы, от корня модуля.
const stubDir = "pkg/api/kaname/cloud/iam/v1"

// stubTexts — тексты контракта по узлам: "Тип" (шапка объявления),
// "Тип.Поле" (поле структуры), "Интерфейс.Метод" (метод интерфейса).
type stubTexts map[string]string

// readStubTexts разбирает все порождённые `.pb.go` каталога контракта.
func readStubTexts(t *testing.T) stubTexts {
	t.Helper()
	root := platformtree.Require(t)
	dir := filepath.Join(root, filepath.FromSlash(stubDir))
	entries, err := os.ReadDir(dir)
	require.NoErrorf(t, err, "чтение каталога заглушек %s", stubDir)
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pb.go") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	require.NotEmptyf(t, files, "в %s нет ни одной заглушки — судить нечего", stubDir)
	out := stubTexts{}
	fset := token.NewFileSet()
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		require.NoErrorf(t, err, "разбор %s", path)
		collectStubTexts(f, out)
	}
	return out
}

// collectStubTexts — тексты одного файла заглушек в общий словарь.
func collectStubTexts(f *ast.File, out stubTexts) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts := spec.(*ast.TypeSpec)
			name := ts.Name.Name
			doc := gd.Doc
			if ts.Doc != nil {
				doc = ts.Doc
			}
			out[name] = doc.Text()
			switch typ := ts.Type.(type) {
			case *ast.StructType:
				for _, fld := range typ.Fields.List {
					if len(fld.Names) == 1 {
						out[name+"."+fld.Names[0].Name] = fld.Doc.Text()
					}
				}
			case *ast.InterfaceType:
				for _, m := range typ.Methods.List {
					if len(m.Names) == 1 {
						out[name+"."+m.Names[0].Name] = m.Doc.Text()
					}
				}
			}
		}
	}
}

// requireTexts — каждый названный узел прочитан и несёт прозу.
func requireTexts(t *testing.T, texts stubTexts, keys ...string) {
	t.Helper()
	for _, k := range keys {
		require.NotEmptyf(t, strings.TrimSpace(texts[k]),
			"текст контракта %q не прочитан: узел заглушки не найден либо без комментария — "+
				"предпосылка пробы сломана", k)
	}
}

// oneLine — проза без переносов строк: фразы контракта переносятся где угодно.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
