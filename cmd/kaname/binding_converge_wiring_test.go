// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// binding_converge_wiring_test.go — повтор сводящего прохода провязан в
// композиционном корне, а его величины читаются ручками посадки (kaname#1006,
// находка M1 / I1).
//
// Проба цикла в пакете `seed` зовёт его напрямую и о вызывающем не утверждает
// ничего: цикл, написанный и не позванный, зелен ею, а лишний кортеж реплики
// прежней версии живёт до следующего старта. Гейт судит УЗЕЛ вызова, а не
// подстроку: имя метода стоит и в комментариях корня.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"
)

func TestBindingConvergeWindows_DefaultsAndOverride(t *testing.T) {
	cases := []struct {
		name             string
		interval, budget string
		want             bindingConvergeWindows
	}{
		{"умолчания", "", "", bindingConvergeWindows{
			Interval: defaultBindingConvergeInterval, BindingTimeout: defaultBindingConvergeTimeout}},
		{"переопределение", "60000", "15000", bindingConvergeWindows{
			Interval: time.Minute, BindingTimeout: 15 * time.Second}},
		{"мусор — умолчание", "abc", "-1", bindingConvergeWindows{
			Interval: defaultBindingConvergeInterval, BindingTimeout: defaultBindingConvergeTimeout}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(bindingConvergeIntervalKnob, c.interval)
			t.Setenv(bindingConvergeTimeoutKnob, c.budget)
			if got := readBindingConvergeWindows(); got != c.want {
				t.Fatalf("readBindingConvergeWindows() = %+v, ожидалось %+v", got, c.want)
			}
		})
	}
	if defaultBindingConvergeInterval <= 0 || defaultBindingConvergeTimeout <= 0 {
		t.Fatalf("умолчания обязаны быть положительными: интервал %v, срок %v",
			defaultBindingConvergeInterval, defaultBindingConvergeTimeout)
	}
}

func TestBindingConvergeLoopIsWiredInTheCompositionRoot(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, 0)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанное есть находка, а не согласие", err)
	}
	// Связывание `x := seed.NewBackfillRunner(…)`.
	runner := ""
	calls := 0
	ast.Inspect(file, func(n ast.Node) bool {
		if _, ok := n.(*ast.CallExpr); ok {
			calls++
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		id, idOK := as.Lhs[0].(*ast.Ident)
		if ok && idOK && sel.Sel.Name == "NewBackfillRunner" {
			runner = id.Name
		}
		return true
	})
	if calls == 0 {
		t.Fatalf("в serve.go не прочитано ни одного вызова — вердикт беспредметен")
	}
	if runner == "" {
		t.Fatalf("сводящий проход не построен в serve.go (`seed.NewBackfillRunner`); осмотрено вызовов %d", calls)
	}
	// Вызов `runner.RunEvery(…)` внутри литерала функции — задачи процесса.
	wired := false
	var inTask func(n ast.Node, depth int)
	inTask = func(n ast.Node, depth int) {
		ast.Inspect(n, func(m ast.Node) bool {
			if fl, ok := m.(*ast.FuncLit); ok && m != n {
				inTask(fl.Body, depth+1)
				return false
			}
			call, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "RunEvery" {
				return true
			}
			if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == runner && depth > 0 {
				wired = true
			}
			return true
		})
	}
	inTask(file, 0)
	if !wired {
		t.Fatalf("у сводящего прохода %q нет вызова RunEvery в задаче процесса (осмотрено вызовов %d): "+
			"сведение разовое, и лишний кортеж, записанный репликой прежней версии во время "+
			"перекрытия выкатки, живёт до следующего старта", runner, calls)
	}
}
