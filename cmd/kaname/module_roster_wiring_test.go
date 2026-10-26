// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_roster_wiring_test.go — перечень личностей модулей доезжает до КАЖДОГО
// пути признания вызывающего (kaname#984).
//
// Страж, собранный без перечня, не признаёт модулем никого — это fail-closed,
// но молчаливый: служба поднимается и отвергает край и модули отказом,
// неотличимым от вызова без личности. Поэтому провязка судится по разбору
// корня: каждый вызов конструктора стража стоит в цепочке, где есть
// `.WithModuleRoster(...)`, а у слушателя полосы входа в литерале настройки
// есть поле `Modules`.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// rosterConsumers — конструкторы стражей, признающих вызывающего, в записи
// корня (`пакет.Имя`).
var rosterConsumers = []string{
	"authzguard.NewCallerPolicy",
	"authzguard.NewPublicCallerPolicy",
	"authzguard.NewSystemViewerFloor",
	"authzguard.NewRelationWriteGate",
	"authorizeapp.NewHandler",
	"internaliamapp.NewHandler",
}

// rosterWiringCensus — перепись провязки одного исходника.
type rosterWiringCensus struct {
	constructors int
	wired        int
	configs      int
	configsWired int
	findings     []string
}

// auditRosterWiring судит провязку перечня в одном разобранном файле.
func auditRosterWiring(fset *token.FileSet, file *ast.File) rosterWiringCensus {
	consumer := map[string]bool{}
	for _, c := range rosterConsumers {
		consumer[c] = true
	}
	// Корни цепочек, у которых есть `.WithModuleRoster(...)`.
	wired := map[*ast.CallExpr]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithModuleRoster" {
			return true
		}
		// Спуск по получателю до корневого вызова конструктора.
		for x := sel.X; x != nil; {
			inner, isCall := x.(*ast.CallExpr)
			if !isCall {
				break
			}
			if consumer[callName(inner)] {
				wired[inner] = true
				break
			}
			s, isSel := inner.Fun.(*ast.SelectorExpr)
			if !isSel {
				break
			}
			x = s.X
		}
		return true
	})

	var c rosterWiringCensus
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			if name := callName(v); consumer[name] {
				c.constructors++
				if wired[v] {
					c.wired++
				} else {
					c.findings = append(c.findings, fset.Position(v.Pos()).String()+": "+name+
						" собран без .WithModuleRoster — страж не признает модулем никого")
				}
			}
		case *ast.CompositeLit:
			sel, ok := v.Type.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name+"."+sel.Sel.Name != "loginlanehttp.Config" {
				return true
			}
			c.configs++
			for _, el := range v.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Modules" {
						c.configsWired++
						return true
					}
				}
			}
			c.findings = append(c.findings, fset.Position(v.Pos()).String()+
				": loginlanehttp.Config без поля Modules — полоса входа не признает край")
		}
		return true
	})
	return c
}

// TestServeWiresTheModuleRosterIntoEveryCallerRecognitionPath — провязка корня.
func TestServeWiresTheModuleRosterIntoEveryCallerRecognitionPath(t *testing.T) {
	var total rosterWiringCensus
	files := []string{"serve.go", "wiring.go", "loginlane.go"}
	for _, name := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("%s не разбирается: %v", name, err)
		}
		c := auditRosterWiring(fset, file)
		total.constructors += c.constructors
		total.wired += c.wired
		total.configs += c.configs
		total.configsWired += c.configsWired
		total.findings = append(total.findings, c.findings...)
	}
	sort.Strings(total.findings)
	t.Logf("перепись: файлов %d · вызовов конструкторов стражей %d, с перечнем %d · настроек полосы входа %d, с перечнем %d",
		len(files), total.constructors, total.wired, total.configs, total.configsWired)
	if total.constructors == 0 || total.configs == 0 {
		t.Fatal("предпосылка: обход не нашёл ни одного стража либо настройки полосы входа — провязка не судилась")
	}
	if len(total.findings) > 0 {
		t.Errorf("перечень личностей не доехал:\n%s", strings.Join(total.findings, "\n"))
	}
}

// TestRosterWiringAuditFindsAnUnwiredGuardAndStaysSilentOnTheWiredTwin —
// инъекция в обе стороны: страж без перечня найден с координатой, тот же страж
// с перечнем — молчание.
func TestRosterWiringAuditFindsAnUnwiredGuardAndStaysSilentOnTheWiredTwin(t *testing.T) {
	for name, tc := range map[string]struct {
		src      string
		findings int
	}{
		"страж без перечня": {src: `package main
func f() { _ = authzguard.NewSystemViewerFloor(nil, nil).WithProductionMode(true) }`, findings: 1},
		"близнец: страж с перечнем": {src: `package main
func f() { _ = authzguard.NewSystemViewerFloor(nil, nil).WithModuleRoster(r).WithProductionMode(true) }`},
		"настройка полосы без поля": {src: `package main
func f() { _ = loginlanehttp.Config{SessionTTL: 1} }`, findings: 1},
		"близнец: настройка полосы с полем": {src: `package main
func f() { _ = loginlanehttp.Config{SessionTTL: 1, Modules: r} }`},
	} {
		t.Run(name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synthetic.go", tc.src, 0)
			if err != nil {
				t.Fatalf("синтетика не разобралась: %v", err)
			}
			if got := len(auditRosterWiring(fset, file).findings); got != tc.findings {
				t.Errorf("находок %d, ожидалось %d", got, tc.findings)
			}
		})
	}
}
