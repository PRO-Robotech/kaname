// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// model_catalog_agreement_wiring_test.go — провязка шага корня старта «модель
// против каталога» (kaname#865, приёмка
// `module-manifest-revision-only-moves-forward.md`, Д10, производитель P17;
// сценарии 865-34, 865-09, 865-24).
//
// Что судится в `serve.go` (узлом разбора, а не текстом: имена шагов есть и в
// комментариях корня):
//
//   - шаг зовётся ровно один раз, и его отказ останавливает пуск — вызов стоит
//     инициализатором `if`, тело которого возвращает;
//   - шаг стоит ПОСЛЕ применителя каталога и РАНЬШЕ стража паритета,
//     применителей ролей и посева: исход редакции известен только после
//     применителя, а роли и посев пишут;
//   - перечень не применённых — второй результат `applyDeliveredManifests`, а
//     отчёт композиции — первый результат `installComposedModel`, то есть ТОЙ
//     композиции, которую корень ставит, а не второй.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

const agreementStep = "assertModelAgreesWithCatalog"

// agreementCensus — объём осмотренного и находки.
type agreementCensus struct {
	calls    int
	findings []string
}

// agreementCallee — имя вызываемого: `f(...)` → f, `pkg.F(...)` → F.
func agreementCallee(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// judgeAgreementWiring судит один исходник корня.
func judgeAgreementWiring(t *testing.T, name, src string) agreementCensus {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть находка", name, err)
	}
	var c agreementCensus
	boundNotApplied := map[string]bool{}
	boundComposed := map[string]bool{}
	first := map[string]token.Pos{}
	var stepCalls []*ast.CallExpr
	checked := map[*ast.CallExpr]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Rhs) != 1 {
				return true
			}
			call, ok := x.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			switch agreementCallee(call) {
			case "applyDeliveredManifests":
				if len(x.Lhs) == 3 {
					if id, ok := x.Lhs[1].(*ast.Ident); ok && id.Name != "_" {
						boundNotApplied[id.Name] = true
					}
				}
			case "installComposedModel":
				if len(x.Lhs) == 2 {
					if id, ok := x.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
						boundComposed[id.Name] = true
					}
				}
			}
		case *ast.IfStmt:
			init, ok := x.Init.(*ast.AssignStmt)
			if !ok || len(init.Rhs) != 1 {
				return true
			}
			call, ok := init.Rhs[0].(*ast.CallExpr)
			if !ok || agreementCallee(call) != agreementStep {
				return true
			}
			for _, st := range x.Body.List {
				if _, ret := st.(*ast.ReturnStmt); ret {
					checked[call] = true
				}
			}
		case *ast.CallExpr:
			name := agreementCallee(x)
			if _, seen := first[name]; !seen {
				first[name] = x.Pos()
			}
			if name == agreementStep {
				stepCalls = append(stepCalls, x)
			}
		}
		return true
	})

	c.calls = len(stepCalls)
	if c.calls != 1 {
		c.findings = append(c.findings, "шаг "+agreementStep+" зовётся "+strconv.Itoa(c.calls)+" раз, а не ровно один")
		return c
	}
	call := stepCalls[0]
	at := fset.Position(call.Pos()).String()
	if !checked[call] {
		c.findings = append(c.findings, at+": отказ шага не останавливает пуск — вызов не стоит инициализатором if с возвратом")
	}
	if apply, ok := first["applyDeliveredManifests"]; !ok || call.Pos() < apply {
		c.findings = append(c.findings, at+": шаг стоит раньше применителя каталога — исход редакции ещё неизвестен")
	}
	for _, later := range []string{"AssertCatalogParity", "applyDeliveredModuleRoles", "applyModuleSeed"} {
		if pos, ok := first[later]; ok && pos < call.Pos() {
			c.findings = append(c.findings, at+": шаг стоит позже "+later+" — пуск дошёл бы до него на модели, которую каталог отверг")
		}
	}
	if len(call.Args) != 3 {
		c.findings = append(c.findings, at+": шаг несёт доводов "+strconv.Itoa(len(call.Args))+", а не три")
		return c
	}
	if id, ok := call.Args[1].(*ast.Ident); !ok || !boundNotApplied[id.Name] {
		c.findings = append(c.findings, at+": перечень не применённых взят не из итога applyDeliveredManifests")
	}
	if id, ok := call.Args[2].(*ast.Ident); !ok || !boundComposed[id.Name] {
		c.findings = append(c.findings, at+": отчёт композиции взят не у installComposedModel — шаг судил бы не ту модель, которую корень ставит")
	}
	return c
}

// TestServeRunsTheModelCatalogAgreementStepBeforeParityRolesAndSeed — провязка
// шага Д10 в корне.
func TestServeRunsTheModelCatalogAgreementStepBeforeParityRolesAndSeed(t *testing.T) {
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("serve.go не прочитан: %v — вердикт беспредметен", err)
	}
	for _, need := range []string{"applyDeliveredManifests", "installComposedModel", "AssertCatalogParity",
		"applyDeliveredModuleRoles", "applyModuleSeed"} {
		if !strings.Contains(string(src), need+"(") {
			t.Fatalf("serve.go не зовёт %s — предпосылка порядка не создана", need)
		}
	}
	c := judgeAgreementWiring(t, "serve.go", string(src))
	t.Logf("перепись: вызовов шага %d · находок %d", c.calls, len(c.findings))
	for _, f := range c.findings {
		t.Error(f)
	}
}

// TestAgreementWiringJudge_FindsEachDefectAndSparesTheLawfulRoot — инъекция в
// обе стороны: законный корень — молчание; каждый дефект — его находка (шаг
// после ролей стоит и после стража — находок две).
func TestAgreementWiringJudge_FindsEachDefectAndSparesTheLawfulRoot(t *testing.T) {
	const lawful = `package main
func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	composedReport, cErr := installComposedModel(logger, deliveredManifests)
	if cErr != nil {
		return cErr
	}
	appliedManifests, notApplied, aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests)
	if aErr != nil {
		return aErr
	}
	if mcErr := assertModelAgreesWithCatalog(logger, notApplied, composedReport); mcErr != nil {
		return mcErr
	}
	catalogCensus, catErr := seed.AssertCatalogParity(ctx, catalogRepo, catalogAnchor)
	if raErr := applyDeliveredModuleRoles(ctx, logger, rolesApplier, appliedManifests); raErr != nil {
		return raErr
	}
	if seErr := applyModuleSeed(ctx, logger, seedApplier, ownManifest, appliedManifests); seErr != nil {
		return seErr
	}
	return nil
}
`
	if c := judgeAgreementWiring(t, "lawful.go", lawful); c.calls != 1 || len(c.findings) != 0 {
		t.Fatalf("законный корень: вызовов %d, находки %v", c.calls, c.findings)
	}

	step := "	if mcErr := assertModelAgreesWithCatalog(logger, notApplied, composedReport); mcErr != nil {\n		return mcErr\n	}\n"
	for _, inj := range []struct {
		name  string
		apply func(string) string
		finds string
		n     int
	}{
		{"шага нет", func(s string) string { return strings.Replace(s, step, "", 1) }, "раз, а не ровно один", 1},
		{"отказ проглочен", func(s string) string {
			return strings.Replace(s, step, "	_ = assertModelAgreesWithCatalog(logger, notApplied, composedReport)\n", 1)
		}, "не останавливает пуск", 1},
		{"шаг после ролей", func(s string) string {
			s = strings.Replace(s, step, "", 1)
			return strings.Replace(s, "	if seErr :=", step+"	if seErr :=", 1)
		}, "позже applyDeliveredModuleRoles", 2},
		{"шаг после стража", func(s string) string {
			s = strings.Replace(s, step, "", 1)
			return strings.Replace(s, "	if raErr :=", step+"	if raErr :=", 1)
		}, "позже AssertCatalogParity", 1},
		{"шаг до применителя", func(s string) string {
			s = strings.Replace(s, step, "", 1)
			return strings.Replace(s, "	appliedManifests, notApplied", step+"	appliedManifests, notApplied", 1)
		}, "раньше применителя каталога", 1},
		{"перечень не из итога", func(s string) string {
			return strings.Replace(s, "(logger, notApplied, composedReport)", "(logger, deliveredManifests, composedReport)", 1)
		}, "не из итога applyDeliveredManifests", 1},
		{"отчёт второй композиции", func(s string) string {
			s = strings.Replace(s, "(logger, notApplied, composedReport)", "(logger, notApplied, otherReport)", 1)
			return strings.Replace(s, "	if mcErr", "	_, otherReport, _ := modelcompose.Compose(authzmodel.DSL, deliveredManifests)\n	if mcErr", 1)
		}, "не у installComposedModel", 1},
	} {
		src := inj.apply(lawful)
		if src == lawful {
			t.Fatalf("инъекция %q не применилась — проба судила бы законный корень", inj.name)
		}
		c := judgeAgreementWiring(t, "injected.go", src)
		hit := false
		for _, f := range c.findings {
			hit = hit || strings.Contains(f, inj.finds)
		}
		if len(c.findings) != inj.n || !hit {
			t.Errorf("инъекция %q: ждали находок %d, среди них с %q, получено %v", inj.name, inj.n, inj.finds, c.findings)
		}
	}
}
