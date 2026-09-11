// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_operation_response_state.go — анализатор «ответ операции над ролью не
// несёт вычисленного состояния, и это ОБЕСПЕЧЕНО, а не совпало».
//
// Порт с монорепо (`internal/repohygiene/roleoperationresponsestate.go`,
// снят вынесением службы — `kacho#2597`). Дословно: весь анализатор.
// Изменилось: пакет (`repohygiene` → `check`); `ServiceRoot` теперь пустая
// строка у вызывающего — в kaname дерево службы лежит от корня, а не под
// `services/iam`.
//
// # Предмет
//
// Контракт роли обещает арендатору буквально следующее: нулевое значение
// `health` и `lifecycle` означает «ЭТИМ ОТВЕТОМ НЕ ВЫЧИСЛЕНО» и никогда «роль
// здорова» либо «роль объявлена»; его несут ответы операций
// `Create`/`Update`, а `Get` и `List` заполняют состояние всегда.
//
// Обещание держится ТОЛЬКО ТЕМ, что производителя вычисленного состояния
// никто не звал на пути мутации. Свойство «by construction» тем и плохо, что
// его снятие ТИХОЕ.
//
// # Что судится
//
// ПЕРЕВОДЧИК ответа операции над ролью — не-тестовая функция, у которой (а)
// результаты ровно `(*anypb.Any, error)`, (б) есть параметр типа `domain.Role`
// и (в) в теле стоит вызов перевода `dto.Transfer`. Каждый такой переводчик
// обязан звать проекцию (`domain.Role.WithoutComputedState`). Не зовёт —
// находка с координатой.
//
// # ЧЕГО ОН НЕ СУДИТ
//
//  1. ПОЛНОТУ набора производных полей — предмет пробы самой проекции;
//  2. ЛИШНЮЮ РАБОТУ — расход без последствий для контракта;
//  3. ЧТЕНИЯ (`Get`/`List`) — у них результат не `(*anypb.Any, error)`.
//
// # Падает на ПУСТОМ ОБХОДЕ
//
// Ноль прочитанных файлов, ноль разобранных функций либо ноль найденных
// переводчиков роли — «находок ноль» неотличимо от «прочитано ноль».
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// RoleOperationResponseStateOptions — вход анализатора.
type RoleOperationResponseStateOptions struct {
	Root             string
	ServiceRoot      string
	DomainPkg        string
	RoleType         string
	TransferFunc     string
	ProjectionMethod string
}

// RoleOperationResponseStateCensus — объём осмотренного.
type RoleOperationResponseStateCensus struct {
	Files            int
	Funcs            int
	AnypbFuncs       int
	RoleTranslators  int
	ProjectionCalled int
}

func (c RoleOperationResponseStateCensus) String() string {
	return fmt.Sprintf(
		"файлов Go прочитано %d · функций разобрано %d · возвращающих ответ операции %d · "+
			"из них ПЕРЕВОДЧИКОВ роли %d · зовущих проекцию %d",
		c.Files, c.Funcs, c.AnypbFuncs, c.RoleTranslators, c.ProjectionCalled)
}

// RoleOperationResponseStateFinding — переводчик, не зовущий проекцию.
type RoleOperationResponseStateFinding struct {
	File string
	Line int
	Func string
}

func (f RoleOperationResponseStateFinding) String() string {
	return fmt.Sprintf("%s:%d: %s переводит роль в ответ операции и не зовёт проекцию",
		f.File, f.Line, f.Func)
}

// AuditRoleOperationResponseState выносит вердикт о дереве.
func AuditRoleOperationResponseState(
	opts RoleOperationResponseStateOptions,
	log io.Writer,
) ([]RoleOperationResponseStateFinding, RoleOperationResponseStateCensus, error) {
	var census RoleOperationResponseStateCensus
	var findings []RoleOperationResponseStateFinding

	root := opts.Root
	if opts.ServiceRoot != "" {
		root = filepath.Join(opts.Root, filepath.FromSlash(opts.ServiceRoot))
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return fmt.Errorf("%s: %w", p, perr)
		}
		census.Files++
		rel, _ := filepath.Rel(opts.Root, p)
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			census.Funcs++
			if !roleOpStateReturnsOperationPayload(fn.Type) {
				continue
			}
			census.AnypbFuncs++
			if !roleOpStateTakesRole(fn.Type, opts) {
				continue
			}
			if !roleOpStateCalls(fn.Body, opts.TransferFunc) {
				continue
			}
			census.RoleTranslators++
			if roleOpStateCalls(fn.Body, opts.ProjectionMethod) {
				census.ProjectionCalled++
				continue
			}
			findings = append(findings, RoleOperationResponseStateFinding{
				File: rel, Line: fset.Position(fn.Pos()).Line, Func: roleOpStateName(fn),
			})
		}
		return nil
	})
	if err != nil {
		return nil, census, err
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	if log != nil {
		_, _ = fmt.Fprintf(log, "перепись: %s\n", census)
	}

	switch {
	case census.Files == 0:
		return findings, census, fmt.Errorf(
			"прочитано ноль файлов Go в %s: обход пуст, вердикт беспредметен", root)
	case census.Funcs == 0:
		return findings, census, fmt.Errorf(
			"разобрано ноль функций в %s: разбор перестал видеть объявления", root)
	case census.RoleTranslators == 0:
		return findings, census, fmt.Errorf(
			"переводчиков роли в ответ операции найдено ноль: признак разошёлся с деревом, "+
				"и «находок ноль» здесь означает «прочитано ноль» (искали функцию с "+
				"результатами (*anypb.Any, error), параметром %s.%s и вызовом %s)",
			opts.DomainPkg, opts.RoleType, opts.TransferFunc)
	}
	return findings, census, nil
}

func roleOpStateReturnsOperationPayload(ft *ast.FuncType) bool {
	if ft.Results == nil || len(ft.Results.List) != 2 {
		return false
	}
	var names []string
	for _, r := range ft.Results.List {
		if len(r.Names) > 1 {
			return false
		}
		names = append(names, roleOpStateTypeString(r.Type))
	}
	return names[0] == "*anypb.Any" && names[1] == "error"
}

func roleOpStateTakesRole(ft *ast.FuncType, opts RoleOperationResponseStateOptions) bool {
	if ft.Params == nil {
		return false
	}
	want := opts.DomainPkg + "." + opts.RoleType
	for _, p := range ft.Params.List {
		t := roleOpStateTypeString(p.Type)
		if t == want || t == "*"+want {
			return true
		}
	}
	return false
}

func roleOpStateCalls(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				found = true
			}
		}
		return !found
	})
	return found
}

func roleOpStateName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + roleOpStateTypeString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func roleOpStateTypeString(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + roleOpStateTypeString(t.X)
	case *ast.SelectorExpr:
		return roleOpStateTypeString(t.X) + "." + t.Sel.Name
	case *ast.ArrayType:
		return "[]" + roleOpStateTypeString(t.Elt)
	default:
		return ""
	}
}
