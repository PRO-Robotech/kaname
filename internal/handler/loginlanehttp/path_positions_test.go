// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp

// path_positions_test.go — гейт перечня Р2 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, §9 п. 3):
// каждый путь полосы объявлен одной из двух строк — «доступно в положении
// подтверждения» либо «отказ Р3», — путей столько, сколько в `Paths()`
// (перепись — в пробе), и путь, объявленный отказом, судится ступенью
// положения в своём обработчике. Разбор — синтаксическим
// деревом `handler.go`: путь — первый довод `h.mux.HandleFunc`, обработчик —
// метод, переданный через `h.method`, ступень — вызов `h.admitted(w, r, <путь>, …)`.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// pathPositionFindings — находки перечня Р2 по исходнику слушателя.
func pathPositionFindings(src string, positions map[string]PathPosition) (inspected int, findings []string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handler.go", src, parser.SkipObjectResolution)
	if err != nil {
		return 0, []string{"разбор handler.go: " + err.Error()}
	}
	// Значения констант путей: имя → литерал.
	consts := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						consts[n.Name] = strings.Trim(bl.Value, `"`)
					}
				}
			}
		}
	}
	// Регистрации: константа пути → имя метода-обработчика.
	routes := map[string]string{}
	methods := map[string]*ast.FuncDecl{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		methods[fd.Name.Name] = fd
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" || len(call.Args) != 2 {
				return true
			}
			pathID, ok := call.Args[0].(*ast.Ident)
			if !ok {
				return true
			}
			wrap, ok := call.Args[1].(*ast.CallExpr)
			if !ok || len(wrap.Args) != 2 {
				return true
			}
			if hs, ok := wrap.Args[1].(*ast.SelectorExpr); ok {
				routes[pathID.Name] = hs.Sel.Name
			}
			return true
		})
	}
	if len(routes) == 0 {
		return 0, []string{"регистраций путей в handler.go не найдено — обход пуст"}
	}
	seen := map[string]bool{}
	names := make([]string, 0, len(routes))
	for n := range routes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, pathConst := range names {
		inspected++
		path := consts[pathConst]
		seen[path] = true
		pos, declared := positions[path]
		if !declared {
			findings = append(findings, "путь "+path+" ("+pathConst+") не объявлен строкой Р2")
			continue
		}
		fd := methods[routes[pathConst]]
		var gated bool
		if fd != nil {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "admitted" || len(call.Args) < 3 {
					return true
				}
				if id, ok := call.Args[2].(*ast.Ident); ok && id.Name == pathConst {
					gated = true
				}
				return true
			})
		}
		switch {
		case pos == PathRefusedInVerification && !gated:
			findings = append(findings, "путь "+path+" объявлен отказом Р3, а обработчик "+routes[pathConst]+" ступени положения не проходит")
		case pos == PathAvailableInVerification && gated:
			findings = append(findings, "путь "+path+" объявлен доступным, а обработчик "+routes[pathConst]+" судит положение")
		}
	}
	for path := range positions {
		if !seen[path] {
			findings = append(findings, "строка Р2 "+path+" без пути")
		}
	}
	sort.Strings(findings)
	return inspected, findings
}

func handlerSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return string(b)
}

// TestEveryLanePathIsDeclaredInTheR2List — гейт перечня Р2 (§9 п. 3).
func TestEveryLanePathIsDeclaredInTheR2List(t *testing.T) {
	positions := PathPositions()
	inspected, findings := pathPositionFindings(handlerSource(t), positions)
	var refused int
	for _, p := range positions {
		if p == PathRefusedInVerification {
			refused++
		}
	}
	t.Logf("перепись: путей зарегистрировано %d · строк Р2 %d · из них отказом %d", inspected, len(positions), refused)
	for _, f := range findings {
		t.Error(f)
	}
	// Перепись популяции, а не предел: её двигает заведение глагола — Ф13
	// добавила два (`access-key/begin`, `access-key/login`, kaname#613), A7 —
	// один (`password/enroll`, kaname#213), свои сессии — три (`sessions`,
	// `sessions/end`, `sessions/end-others`, kaname#634).
	if len(Paths()) != 21 || len(positions) != 21 {
		t.Errorf("путей полосы не 21: перечень %d, строк Р2 %d", len(Paths()), len(positions))
	}
	for _, p := range Paths() {
		if _, ok := positions[p]; !ok {
			t.Errorf("путь перечня %s без строки Р2", p)
		}
	}
}

// TestR2ListInjection — путь без объявления и путь-отказ без ступени краснеют
// с координатой; законный близнец молчит.
func TestR2ListInjection(t *testing.T) {
	src := handlerSource(t)
	positions := PathPositions()

	withPath := strings.Replace(src, "\th.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))",
		"\th.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))\n\th.mux.HandleFunc(PathProbe, h.method(http.MethodPost, h.stepUp))", 1)
	withPath = strings.Replace(withPath, "PathStepUp                  = \"/iam/v1/auth/step-up\"",
		"PathStepUp                  = \"/iam/v1/auth/step-up\"\n\tPathProbe = \"/iam/v1/auth/probe\"", 1)
	if withPath == src {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: инъекция пути не легла")
	}
	_, f := pathPositionFindings(withPath, positions)
	if !strings.Contains(strings.Join(f, "\n"), "/iam/v1/auth/probe") {
		t.Fatalf("путь без объявления не найден: %v", f)
	}

	ungated := strings.Replace(src, "\tif !h.admitted(w, r, PathPassword, humansession.TextRequestNotPerformed) {\n\t\treturn\n\t}\n", "", 1)
	if ungated == src {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: инъекция снятия ступени не легла")
	}
	_, f = pathPositionFindings(ungated, positions)
	if !strings.Contains(strings.Join(f, "\n"), PathPassword) {
		t.Fatalf("путь-отказ без ступени не найден: %v", f)
	}

	if _, f = pathPositionFindings(src, positions); len(f) != 0 {
		t.Fatalf("законный близнец дал находки: %v", f)
	}
}
