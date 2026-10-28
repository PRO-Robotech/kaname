// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delegated_path_callers_test.go — гейт дерева условия CE-03 разбора классов к
// приёмке делегированных выдач (PRO-Robotech/kaname#986): четвёртый путь права
// выдавать живёт ОТДЕЛЬНОЙ функцией, и зовут её только выдача, отзыв и удаление.
//
// Встроенный в общую `requireGrantAuthority` (десять мест вызова в проде), он
// открыл бы делегату `ExpandAccess` и `ListByRole`: дверь их пропускает, решает
// обработчик. Гейт судит синтаксис пакета, а не имя файла: кто зовёт
// `delegatedGrantAuthority` и `removalAuthority`, и не тянут ли общие функции
// права выдавать делегированный путь. Перепись печатается; ноль прочитанных
// файлов — отказ, а не зелёное. Способность упасть доказывает инъекция ниже.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// delegatedPathRule — закрытый перечень законных мест вызова.
var delegatedPathRule = map[string][]string{
	"delegatedGrantAuthority": {"CreateAccessBindingUseCase.Execute", "removalAuthority"},
	"removalAuthority":        {"DeleteAccessBindingUseCase.Execute", "RevokeAccessBindingUseCase.Execute"},
}

// sharedAuthorityFuncs — общие функции права выдавать: делегированного пути в них
// быть не должно ни вызовом, ни чтением делегирований.
var sharedAuthorityFuncs = []string{"requireGrantAuthority", "grantAuthorityBeyondClusterAdmin"}

// judgeDelegatedPathCallers — находки по разобранным файлам пакета.
func judgeDelegatedPathCallers(files []*ast.File) (findings []string, callers map[string][]string) {
	callers = map[string][]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := dpFuncName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok {
						if _, watched := delegatedPathRule[id.Name]; watched {
							callers[id.Name] = append(callers[id.Name], name)
						}
					}
				case *ast.SelectorExpr:
					if dpIsShared(name) && x.Sel.Name == "GrantDelegations" {
						findings = append(findings, name+" читает делегирования — делегированный путь в общей функции права выдавать")
					}
				}
				return true
			})
			if dpIsShared(name) {
				for _, c := range dpCallees(fn) {
					if _, watched := delegatedPathRule[c]; watched {
						findings = append(findings, name+" зовёт "+c+" — делегированный путь в общей функции права выдавать")
					}
				}
			}
		}
	}
	for callee, want := range delegatedPathRule {
		got := append([]string(nil), callers[callee]...)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			findings = append(findings, callee+": места вызова "+strings.Join(got, ", ")+", законны ровно "+strings.Join(want, ", "))
		}
	}
	sort.Strings(findings)
	return findings, callers
}

func dpIsShared(name string) bool {
	for _, s := range sharedAuthorityFuncs {
		if name == s {
			return true
		}
	}
	return false
}

func dpCallees(fn *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok {
				out = append(out, id.Name)
			}
		}
		return true
	})
	return out
}

func dpFuncName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// parsePackageProd — непробные файлы пакета.
func dpParsePackageProd(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНЯЛСЯ: каталог пакета не прочитан: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(".", n), nil, 0)
		if perr != nil {
			t.Fatalf("гейт НЕ ИСПОЛНЯЛСЯ: %s не разобран: %v", n, perr)
		}
		files = append(files, f)
	}
	return files
}

// TestDelegatedGrantPathHasExactlyItsThreeVerbs — CE-03: делегированный путь
// зовут ровно выдача, отзыв и удаление; общие функции права выдавать его не
// тянут.
func TestDelegatedGrantPathHasExactlyItsThreeVerbs(t *testing.T) {
	files := dpParsePackageProd(t)
	if len(files) == 0 {
		t.Fatal("гейт НЕ ИСПОЛНЯЛСЯ: ноль непробных файлов пакета")
	}
	findings, callers := judgeDelegatedPathCallers(files)
	t.Logf("файлов %d · места вызова delegatedGrantAuthority %v · removalAuthority %v · находок %d",
		len(files), callers["delegatedGrantAuthority"], callers["removalAuthority"], len(findings))
	for _, f := range findings {
		t.Error(f)
	}
}

// TestDelegatedGrantPathGateCanFail — инъекция: тот же судья на дереве, где общая
// функция права выдавать зовёт делегированный путь, а `ListByRole` — путь снятия,
// краснеет обеими находками; законный близнец молчит.
func TestDelegatedGrantPathGateCanFail(t *testing.T) {
	const lawful = `package p
func requireGrantAuthority() error { return nil }
func (u *CreateAccessBindingUseCase) Execute() { delegatedGrantAuthority() }
func removalAuthority() { delegatedGrantAuthority() }
func (u *RevokeAccessBindingUseCase) Execute() { removalAuthority() }
func (u *DeleteAccessBindingUseCase) Execute() { removalAuthority() }
`
	const injected = `package p
func requireGrantAuthority() error { delegatedGrantAuthority(); return nil }
func (u *CreateAccessBindingUseCase) Execute() { delegatedGrantAuthority() }
func removalAuthority() { delegatedGrantAuthority() }
func (u *RevokeAccessBindingUseCase) Execute() { removalAuthority() }
func (u *DeleteAccessBindingUseCase) Execute() { removalAuthority() }
func (u *ListByRoleUseCase) Execute() { removalAuthority() }
`
	parse := func(src string) []*ast.File {
		f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
		if err != nil {
			t.Fatalf("инъекция не разобрана: %v", err)
		}
		return []*ast.File{f}
	}
	if got, _ := judgeDelegatedPathCallers(parse(lawful)); len(got) != 0 {
		t.Fatalf("законный близнец краснеет: %v", got)
	}
	got, _ := judgeDelegatedPathCallers(parse(injected))
	var shared, extra bool
	for _, f := range got {
		shared = shared || strings.HasPrefix(f, "requireGrantAuthority зовёт delegatedGrantAuthority")
		extra = extra || strings.Contains(f, "ListByRoleUseCase.Execute")
	}
	if !shared || !extra {
		t.Fatalf("инъекция не найдена обеими находками: %v", got)
	}
}
