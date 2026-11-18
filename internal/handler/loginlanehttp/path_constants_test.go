// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp

import (
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// laneFileStringConstant читает строковые литералы и их константные псевдонимы
// в этом файле. Идентичность AST-объектов не даёт принять локальную переменную
// с тем же именем за константу пути. Импорты, переменные, циклы и неподдержанные
// выражения дают отказ: перепись исходника не заменяет компилятор Go.
func laneFileStringConstant(f *ast.File) func(ast.Expr) (string, bool) {
	values := map[*ast.Object]ast.Expr{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		var previous []ast.Expr
		var previousType ast.Expr
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			exprs, typ := vs.Values, vs.Type
			if len(exprs) == 0 {
				exprs, typ = previous, previousType
			} else {
				previous, previousType = exprs, typ
			}
			if typ != nil {
				id, ok := typ.(*ast.Ident)
				if !ok || id.Name != "string" || id.Obj != nil {
					continue
				}
			}
			if len(exprs) != len(vs.Names) {
				continue
			}
			for i, name := range vs.Names {
				if name.Obj != nil && name.Name != "_" {
					values[name.Obj] = exprs[i]
				}
			}
		}
	}
	return func(expr ast.Expr) (string, bool) {
		visiting := map[*ast.Object]bool{}
		var resolve func(ast.Expr) (string, bool)
		resolve = func(expr ast.Expr) (string, bool) {
			switch e := expr.(type) {
			case *ast.BasicLit:
				if e.Kind == token.STRING {
					v, err := strconv.Unquote(e.Value)
					return v, err == nil
				}
			case *ast.ParenExpr:
				return resolve(e.X)
			case *ast.Ident:
				value, ok := values[e.Obj]
				if ok && !visiting[e.Obj] {
					visiting[e.Obj] = true
					v, resolved := resolve(value)
					delete(visiting, e.Obj)
					return v, resolved
				}
			}
			return "", false
		}
		return resolve(expr)
	}
}

// TestLanePathConstantAliases — обе переписи принимают константные псевдонимы
// и сохраняют отказ для выражений, которые не подтверждают константу пути.
func TestLanePathConstantAliases(t *testing.T) {
	const path = "/iam/v1/auth/probe"
	for _, tc := range []struct {
		name  string
		decls string
		local string
		valid bool
	}{
		{name: "literal", decls: `const PathProbe = "/iam/v1/auth/probe"`, valid: true},
		{name: "forward alias chain", decls: "const PathProbe = (next)\nconst next = base\nconst base = `/iam/v1/auth/probe`", valid: true},
		{name: "typed alias", decls: "const base string = \"/iam/v1/auth/probe\"\nconst PathProbe = base", valid: true},
		{name: "repeated expression", decls: "const (base = \"/iam/v1/auth/probe\"; PathProbe)", valid: true},
		{name: "unknown", decls: "const PathProbe = missing"},
		{name: "variable", decls: "var PathProbe = \"/iam/v1/auth/probe\""},
		{name: "variable alias", decls: "var base = \"/iam/v1/auth/probe\"\nconst PathProbe = base"},
		{name: "nonstring", decls: "const base = 7\nconst PathProbe = base"},
		{name: "invalid type", decls: "const PathProbe int = \"/iam/v1/auth/probe\""},
		{name: "cycle", decls: "const PathProbe = next\nconst next = PathProbe"},
		{name: "unavailable selector", decls: "const PathProbe = elsewhere.Path"},
		{name: "shadowed variable", decls: "const PathProbe = \"/iam/v1/auth/probe\"", local: "PathProbe := \"/iam/v1/auth/probe\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package loginlanehttp\n" + tc.decls + "\nfunc routes() {\n" + tc.local + "\nh.mux.HandleFunc(PathProbe, h.method(http.MethodPost, h.probe))\n}\nfunc (h *Handler) probe() {}"
			registered, pf := registeredLanePaths(src)
			_, positions := pathPositionFindings(src, map[string]PathPosition{path: PathAvailableInVerification})
			if tc.valid {
				if !slices.Equal(registered, []string{path}) || len(pf) != 0 || len(positions) != 0 {
					t.Fatalf("legal constant rejected: paths=%v, registrations=%v, positions=%v", registered, pf, positions)
				}
			} else if len(registered) != 0 || len(pf) != 1 || !strings.Contains(pf[0], "PathProbe") || len(positions) == 0 || !strings.Contains(strings.Join(positions, "\n"), "PathProbe") {
				t.Fatalf("invalid constant escaped findings: paths=%v, registrations=%v, positions=%v", registered, pf, positions)
			}
		})
	}
}
