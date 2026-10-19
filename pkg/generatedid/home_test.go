// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package generatedid_test

// home_test.go — общая форма порождённого идентификатора определена ОДИН раз,
// в этом пакете (задача PRO-Robotech/kaname#908).
//
// Форма — предмет двух сторон: страж старта службы (публичный принципал
// анонимного чтения не вправе иметь её) и приёмная сторона реестра платформы,
// судящая форму субъекта. Второе определение в любом из деревьев разошлось бы с
// первым молча, поэтому проба обходит не-тестовый Go модуля и ищет СТРОКОВЫЕ
// литералы (узлы разбора, не текст: комментарий формой не является), чьё
// содержимое — общая форма: префикс вида переменной длины перед телом из 17
// знаков crockford-base32. Формы одного вида (`^usr…`, `^ak-…`) — другой
// предмет: они называют вид литералом и общей формой не являются.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// genericFormRe — признак общей формы внутри литерала регулярного выражения:
// класс букв префикса с переменной длиной, затем тело crockford-base32 из 17.
var genericFormRe = regexp.MustCompile(`\[a-z\]\{\d,\d\}.*\[0-9a-hjkmnp-tv-z\]\{17\}`)

// findGenericForms — пути (относительно root) не-тестовых Go-файлов, где
// строковый литерал несёт общую форму, и число разобранных файлов.
func findGenericForms(t *testing.T, root string) (files int, homes []string) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || found {
				return !found
			}
			if s, uerr := strconv.Unquote(lit.Value); uerr == nil && genericFormRe.MatchString(s) {
				found = true
			}
			return !found
		})
		if found {
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return rerr
			}
			homes = append(homes, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", root, err)
	}
	slices.Sort(homes)
	return files, homes
}

func TestGeneratedIDForm_HasOneHomeInThePublicPackage(t *testing.T) {
	files, homes := findGenericForms(t, filepath.Join("..", ".."))
	t.Logf("осмотрено не-тестовых Go-файлов модуля: %d; определений общей формы: %d %v", files, len(homes), homes)
	if files == 0 {
		t.Fatal("обход не прочитал ни одного файла — вердикта нет")
	}
	want := []string{"pkg/generatedid/generatedid.go"}
	if !slices.Equal(homes, want) {
		t.Fatalf("общая форма порождённого идентификатора определена в %v, ждали ровно %v: "+
			"второе определение разошлось бы с публичным молча", homes, want)
	}
}

// TestGeneratedIDForm_HomeProbeFindsTheDefectAndSparesTheTwin — инъекция в обе
// стороны на синтетическом дереве: литерал общей формы найден с координатой;
// форма одного вида и общая форма В КОММЕНТАРИИ — законные близнецы, молчат.
func TestGeneratedIDForm_HomeProbeFindsTheDefectAndSparesTheTwin(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("a/defect.go", "package a\n\nimport \"regexp\"\n\n"+
		"var re = regexp.MustCompile(`^[a-z]{2,4}[-_]?[0-9a-hjkmnp-tv-z]{17}$`)\n")
	write("b/twin.go", "package b\n\nimport \"regexp\"\n\n"+
		"// общая форма ^[a-z]{2,4}[-_]?[0-9a-hjkmnp-tv-z]{17}$ — только в комментарии\n"+
		"var re = regexp.MustCompile(`^usr[0-9a-hjkmnp-tv-z]{17}$`)\n")
	write("c/defect_test.go", "package c\n\nconst f = `^[a-z]{2,4}[0-9a-hjkmnp-tv-z]{17}$`\n")

	files, homes := findGenericForms(t, root)
	if files != 2 {
		t.Fatalf("осмотрено %d не-тестовых файлов, ждали 2", files)
	}
	if !slices.Equal(homes, []string{"a/defect.go"}) {
		t.Fatalf("найдено %v, ждали ровно [a/defect.go]", homes)
	}
}
