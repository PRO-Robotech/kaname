// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

// layer_test.go — поверхность церемонии тонкая: разбор → вариант использования
// → ответ (задача PRO-Robotech/kaname#423, возврат ревью стиля сборки 425).
//
// Решения домена — суждение об уровне входа, граница семейства, отказ клиенту
// без получателя — и граница транзакции обмена принадлежат варианту
// использования (`internal/apps/kaname/api/oauth_ceremony`). Их признак в пакете
// поверхности узнаётся разбором, а не словом:
//
//   - импорт ранжирования уровня входа (`corelib/acrlevel`) и политики сроков
//     (`corelib/tokenpolicy`) — это инструменты этих решений;
//   - вызов порта, который оркеструет вариант использования: справочник
//     клиентов, шов входа, церемония, единица запроса.
//
// Проверка печатает перепись осмотренного и падает, если не увидела ни одного
// обработчика поверхности: пустой обход — не вердикт.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// orchestrationImports — импорты, которыми принимаются решения домена.
var orchestrationImports = map[string]string{
	"github.com/PRO-Robotech/corelib/acrlevel":    "суждение об уровне входа",
	"github.com/PRO-Robotech/corelib/tokenpolicy": "граница семейства",
}

// orchestrationCalls — методы портов, которые оркеструет вариант использования.
var orchestrationCalls = map[string]string{
	"LookupClient":          "справочник клиентов",
	"Resolve":               "шов входа",
	"Authorize":             "церемония",
	"CompleteAuthorization": "церемония",
	"Exchange":              "церемония",
	"OpenRequest":           "граница транзакции обмена",
}

type layerCensus struct {
	files, calls, handlers int
}

// orchestrationFindings — находки по разобранным файлам пакета поверхности.
func orchestrationFindings(fset *token.FileSet, files map[string]*ast.File) ([]string, layerCensus) {
	var findings []string
	var census layerCensus
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		f := files[name]
		census.files++
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if why, bad := orchestrationImports[path]; bad {
				findings = append(findings, fset.Position(imp.Pos()).String()+": импорт "+path+" ("+why+")")
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if x.Recv != nil && (x.Name.Name == "ServeHTTP" || x.Name.Name == "ServeGrant") {
					census.handlers++
				}
			case *ast.CallExpr:
				census.calls++
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if why, bad := orchestrationCalls[sel.Sel.Name]; bad {
					findings = append(findings, fset.Position(x.Pos()).String()+": вызов ."+sel.Sel.Name+" ("+why+")")
				}
			}
			return true
		})
	}
	return findings, census
}

func parseSurface(t *testing.T, dir string) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("разбор пакета поверхности: %v", err)
	}
	files := map[string]*ast.File{}
	for _, p := range pkgs {
		for name, f := range p.Files {
			files[name] = f
		}
	}
	return fset, files
}

func TestCeremonySurfaceCarriesNoDomainDecision(t *testing.T) {
	fset, files := parseSurface(t, ".")
	findings, census := orchestrationFindings(fset, files)
	t.Logf("перепись: файлов %d, вызовов %d, обработчиков %d, находок %d",
		census.files, census.calls, census.handlers, len(findings))
	if census.files == 0 || census.handlers < 3 {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: обход не увидел обработчиков поверхности (файлов %d, обработчиков %d)",
			census.files, census.handlers)
	}
	for _, f := range findings {
		t.Errorf("решение домена либо оркестровка портов в поверхности: %s", f)
	}
}

// Инъекция в обе стороны на синтетике: оркестровка находится, тонкий
// обработчик той же формы молчит.
func TestCeremonySurfaceLayerCheckIsProvenByInjection(t *testing.T) {
	parse := func(src string) (*token.FileSet, map[string]*ast.File) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "synthetic.go", src, 0)
		if err != nil {
			t.Fatalf("синтетика: %v", err)
		}
		return fset, map[string]*ast.File{"synthetic.go": f}
	}
	thick := `package x
import "github.com/PRO-Robotech/corelib/acrlevel"
type h struct{ units interface{ OpenRequest() } }
func (a *h) ServeHTTP() { _ = acrlevel.Rank("1"); a.units.OpenRequest() }`
	thin := `package x
type h struct{ uc interface{ Execute() } }
func (a *h) ServeHTTP() { a.uc.Execute() }`
	if got, _ := orchestrationFindings(parse(thick)); len(got) != 2 {
		t.Errorf("инъекция: оркестровка не найдена целиком: %v", got)
	}
	if got, census := orchestrationFindings(parse(thin)); len(got) != 0 || census.handlers != 1 {
		t.Errorf("близнец: тонкий обработчик назван находкой либо не сосчитан: %v, %+v", got, census)
	}
}
