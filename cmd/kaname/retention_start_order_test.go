// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// retention_start_order_test.go — уборки стартуют ПОСЛЕ последнего отказа
// старта и на корневом контексте задач (задача #253).
//
// # Предмет
//
// Уборки запускались в корне раньше стражей, которые ещё могли отвергнуть старт.
// Первый проход идёт сразу; на отказе стража пул закрывается `defer`-ом, и
// проходы в полёте докладывали «retention sweep failed: closed pool» как СВОЙ
// отказ — шесть WARN над единственной строкой ERROR, которая и есть предмет.
//
// Свойство держится порядком в `runServe`, поэтому гейт судит порядок по
// разбору: после вызова, стартующего уборку, в теле корня не остаётся ни одного
// условного `return` (отказа старта), а контекст старта — корневой контекст
// задач, который `defer rootShutdown.Stop()` отменяет раньше `pool.Close()`.
// Возвраты внутри замыканий — тела задач, а не отказы старта: они не судятся.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// retentionStarters — вызовы корня, стартующие уборку по сроку. Старт один на обе
// уборки и отказать не может: всё, что может отказать, — сборка, и она идёт
// раньше, среди стражей.
var retentionStarters = map[string]bool{
	"startRetentionSweeps": true,
}

// retentionStartCensus — объём осмотренного.
type retentionStartCensus struct {
	Starts       int // вызовов-стартов уборки в runServe
	Refusals     int // условных return в runServe вне замыканий
	AfterStart   int // из них — после первого старта
	RootCtxName  string
	RunServeSeen bool
}

func (c retentionStartCensus) Summary() string {
	return fmt.Sprintf("runServe разобран: %t · стартов уборки %d · условных отказов старта %d · из них после старта уборки %d · корневой контекст %q",
		c.RunServeSeen, c.Starts, c.Refusals, c.AfterStart, c.RootCtxName)
}

// containsStarter — несёт ли узел вызов старта уборки (вне замыканий).
func containsStarter(n ast.Node) bool {
	if n == nil {
		return false
	}
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if _, ok := m.(*ast.FuncLit); ok {
			return false
		}
		if c, ok := m.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && retentionStarters[id.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}

// scanRetentionStartOrder разбирает src и называет нарушения порядка.
func scanRetentionStartOrder(src string) (retentionStartCensus, []string, error) {
	var census retentionStartCensus
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "serve.go", src, 0)
	if err != nil {
		return census, nil, err
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == "runServe" && fd.Body != nil {
			body = fd.Body
		}
	}
	if body == nil {
		return census, nil, nil
	}
	census.RunServeSeen = true

	type start struct {
		pos  token.Pos
		name string
		ctx  string
	}
	var starts []start
	var refusals []token.Pos
	// Обход без замыканий; условный return — return, лежащий внутри if/switch/for
	// тела корня.
	var walk func(n ast.Node, conditional bool)
	walk = func(n ast.Node, conditional bool) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.FuncLit:
				return false
			case *ast.IfStmt:
				if m == n {
					break
				}
				// Собственный отказ старта — `if err := startRetentionSweeps(…); err != nil
				// { return err }`: по контракту старта он наступает раньше, чем запущена
				// хоть одна уборка, и отказом ПОСЛЕ старта не является.
				if containsStarter(x.Init) || containsStarter(x.Cond) {
					if x.Init != nil {
						walk(x.Init, conditional)
					}
					walk(x.Cond, conditional)
					if x.Else != nil {
						walk(x.Else, true)
					}
					return false
				}
				walk(m, true)
				return false
			case *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SelectStmt:
				if m != n {
					walk(m, true)
					return false
				}
			case *ast.ReturnStmt:
				if conditional {
					refusals = append(refusals, x.Pos())
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && retentionStarters[id.Name] {
					ctxName := ""
					if len(x.Args) > 0 {
						if a, ok := x.Args[0].(*ast.Ident); ok {
							ctxName = a.Name
						}
					}
					starts = append(starts, start{pos: x.Pos(), name: id.Name, ctx: ctxName})
				}
			case *ast.AssignStmt:
				// taskCtx := rootShutdown.Context()
				if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
					if call, ok := x.Rhs[0].(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Context" {
							if r, ok := sel.X.(*ast.Ident); ok && r.Name == "rootShutdown" {
								if l, ok := x.Lhs[0].(*ast.Ident); ok {
									census.RootCtxName = l.Name
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	walk(body, false)

	census.Starts = len(starts)
	census.Refusals = len(refusals)
	var findings []string
	if len(starts) == 0 {
		return census, nil, nil
	}
	first := starts[0].pos
	for _, s := range starts {
		if s.pos < first {
			first = s.pos
		}
	}
	for _, r := range refusals {
		if r > first {
			census.AfterStart++
			findings = append(findings, fmt.Sprintf(
				"serve.go:%d — отказ старта ПОСЛЕ старта уборки (serve.go:%d): на этом отказе пул закроется под проходом в полёте, "+
					"и уборка доложит «closed pool» как свой отказ",
				fset.Position(r).Line, fset.Position(first).Line))
		}
	}
	for _, s := range starts {
		if census.RootCtxName == "" || s.ctx != census.RootCtxName {
			findings = append(findings, fmt.Sprintf(
				"serve.go:%d — %s стартует на контексте %q, а не на корневом контексте задач %q: "+
					"гашение по краху не остановит её раньше закрытия пула",
				fset.Position(s.pos).Line, s.name, s.ctx, census.RootCtxName))
		}
	}
	return census, findings, nil
}

// TestRetentionSweepsStartAfterTheLastBootRefusal — живое дерево.
func TestRetentionSweepsStartAfterTheLastBootRefusal(t *testing.T) {
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("serve.go: %v", err)
	}
	census, findings, err := scanRetentionStartOrder(string(src))
	if err != nil {
		t.Fatalf("разбор serve.go: %v", err)
	}
	t.Logf("%s", census.Summary())
	// Проверка предпосылки: обход, не нашедший предмета, — «не выполнилось».
	if !census.RunServeSeen {
		t.Fatal("в serve.go нет runServe — гейт беспредметен")
	}
	if census.Starts != len(retentionStarters) {
		t.Fatalf("стартов уборки найдено %d, ожидалось %d (%v) — распознаватель потерял старт либо корень его не зовёт",
			census.Starts, len(retentionStarters), retentionStarters)
	}
	if census.Refusals == 0 {
		t.Fatal("в runServe не найдено ни одного условного отказа старта — распознаватель отказов мёртв, «после старта 0» он печатал бы by construction")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

const injStartOK = `package main

func runServe() error {
	pool := open()
	defer pool.Close()
	if err := guard(); err != nil {
		return err
	}
	rootShutdown := newRootShutdown(ctx, nil)
	defer rootShutdown.Stop()
	taskCtx := rootShutdown.Context()
	tasks := []func() error{func() error { if x { return nil }; return nil }}
	if err := startRetentionSweeps(taskCtx, sweeps, logger); err != nil {
		return err
	}
	return run(tasks)
}
`

// TestRetentionStartOrderInjection — гейт краснеет на дефекте и молчит на
// законном близнеце; дефекты меняют ровно один факт.
func TestRetentionStartOrderInjection(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		want int
		says string
	}{
		{"законный близнец", injStartOK, 0, ""},
		{"отказ после старта", strings.Replace(injStartOK, "\treturn run(tasks)", "\tif err := lateGuard(); err != nil {\n\t\treturn err\n\t}\n\treturn run(tasks)", 1), 1, "отказ старта ПОСЛЕ старта уборки"},
		{"сигнальный контекст", strings.Replace(injStartOK, "startRetentionSweeps(taskCtx", "startRetentionSweeps(ctx", 1), 1, "не на корневом контексте задач"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			census, findings, err := scanRetentionStartOrder(tc.src)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%s", census.Summary())
			if census.Starts != 1 {
				t.Fatalf("стартов %d, ожидалось 1", census.Starts)
			}
			if len(findings) != tc.want {
				t.Fatalf("находок %d, ожидалось %d: %v", len(findings), tc.want, findings)
			}
			if tc.says != "" && !strings.Contains(findings[0], tc.says) {
				t.Fatalf("находка не называет причину %q: %s", tc.says, findings[0])
			}
		})
	}
}
