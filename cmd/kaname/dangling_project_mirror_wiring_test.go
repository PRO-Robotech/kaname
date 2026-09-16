// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// dangling_project_mirror_wiring_test.go — у прохода по строкам зеркала с
// НЕСУЩЕСТВУЮЩИМ родителем есть БОЕВОЙ вызывающий (IAM-PNE-2-03, полоса А;
// приёмка `non-empty-project-is-not-deleted.md`, стадия S2).
//
// # Зачем гейт, если у прохода есть интеграционные пробы
//
// Обе пробы прохода зовут `RunOnce` напрямую и о вызывающем не утверждают
// ничего. Проход, написанный и не позванный, зелен обеими и не печатает
// переписи никому — предмет стадии («остаток становится ВИДИМЫМ») не наступает.
// Умение без вызывающего есть мёртвый проход — тот же класс, что
// `retention-sweep-has-a-caller.md` §8 «уборщик без вызывающего невозможен».
//
// # Что утверждается
//
//	проход построен в корне           связывание `x := seed.NewDanglingProjectMirrorSweeper(…)`
//	и позван                          вызов `x.RunOnce(…)`
//	в ТОЙ ЖЕ стартовой задаче         тот же литерал функции, что зовёт
//	                                  `RunOnce` действующего прохода зеркала
//
// # Гейт судит УЗЕЛ, а не подстроку
//
// Имя прохода стоит и в комментариях корня (в том числе в объяснении этого
// гейта); проверка по подстроке краснела бы на собственном объяснении и зеленела
// бы на файле, где вызова нет. Обход идёт по узлам связывания и вызова.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// sweepWiring — что обход прочитал о провязке.
type sweepWiring struct {
	// callsSeen — объём осмотренного; ноль означает «не прочитано ничего».
	callsSeen int
	// neighbourBound / candidateBound — имена, которыми связаны действующий
	// проход зеркала и новый проход; пусто — не построен.
	neighbourBound string
	candidateBound string
	// neighbourTask / candidateTask — литерал функции, внутри которого стоит
	// вызов `RunOnce` соответствующего прохода; nil — вызова нет.
	neighbourTask *ast.FuncLit
	candidateTask *ast.FuncLit
}

const (
	neighbourSweepCtor = "NewOrphanMirrorSweeper"
	candidateSweepCtor = "NewDanglingProjectMirrorSweeper"
)

func readSweepWiring(t *testing.T, name string, src any) sweepWiring {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть НАХОДКА, а не согласие", name, err)
	}
	var w sweepWiring
	// Связывания: `x := seed.New…Sweeper(…)`.
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case neighbourSweepCtor:
			if w.neighbourBound == "" {
				w.neighbourBound = id.Name
			}
		case candidateSweepCtor:
			if w.candidateBound == "" {
				w.candidateBound = id.Name
			}
		}
		return true
	})
	// Вызовы `x.RunOnce(…)` — с литералом функции, в котором стоят.
	var stack []*ast.FuncLit
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		if n == nil {
			return true
		}
		if fl, ok := n.(*ast.FuncLit); ok {
			stack = append(stack, fl)
			ast.Inspect(fl.Body, walk)
			stack = stack[:len(stack)-1]
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		w.callsSeen++
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RunOnce" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || len(stack) == 0 {
			return true
		}
		top := stack[len(stack)-1]
		switch recv.Name {
		case w.neighbourBound:
			if w.neighbourBound != "" && w.neighbourTask == nil {
				w.neighbourTask = top
			}
		case w.candidateBound:
			if w.candidateBound != "" && w.candidateTask == nil {
				w.candidateTask = top
			}
		}
		return true
	}
	ast.Inspect(file, walk)
	return w
}

// judgeSweepWiring — один предикат для живого гейта и инъекции.
func judgeSweepWiring(w sweepWiring) []string {
	if w.callsSeen == 0 {
		return []string{"обход не нашёл ни одного вызова — вердикт беспредметен"}
	}
	var findings []string
	if w.neighbourBound == "" || w.neighbourTask == nil {
		findings = append(findings, "предпосылка исчезла: действующий проход зеркала ("+neighbourSweepCtor+
			") не построен либо его RunOnce не позван из литерала задачи — судить «ту же задачу» не с чем")
		return findings
	}
	if w.candidateBound == "" {
		findings = append(findings, "проход по строкам с несуществующим родителем не построен в корне: "+
			"вызова "+candidateSweepCtor+" нет — перепись остатка не печатается никому")
		return findings
	}
	if w.candidateTask == nil {
		findings = append(findings, "проход построен как ["+w.candidateBound+"], а RunOnce не позван "+
			"из стартовой задачи — проход мёртв")
		return findings
	}
	if w.candidateTask != w.neighbourTask {
		findings = append(findings, "RunOnce прохода стоит НЕ в той же стартовой задаче, что у "+
			"действующего прохода зеркала ["+w.neighbourBound+"]")
	}
	return findings
}

// TestServeWiresTheDanglingProjectMirrorSweep — живой гейт над serve.go.
func TestServeWiresTheDanglingProjectMirrorSweep(t *testing.T) {
	if _, err := os.Stat("serve.go"); err != nil {
		t.Fatalf("serve.go не прочитан: %v", err)
	}
	w := readSweepWiring(t, "serve.go", nil)
	t.Logf("осмотрено: файлов корня 1 · вызовов разобрано %d; сосед связан как %q, проход как %q",
		w.callsSeen, w.neighbourBound, w.candidateBound)
	for _, f := range judgeSweepWiring(w) {
		t.Errorf("%s", f)
	}
}

// ── Инъекция ────────────────────────────────────────────────────────────────

const sweepWiringLive = `package main

func serve() error {
	orphanMirrorSweeper := seed.NewOrphanMirrorSweeper(kanamepg.NewOrphanMirrorAdapter(pool), seed.OrphanMirrorConfig{})
	danglingSweeper := seed.NewDanglingProjectMirrorSweeper(kanamepg.NewDanglingProjectMirrorAdapter(pool), seed.DanglingProjectMirrorConfig{})
	tasks = append(tasks, func() error {
		if _, err := orphanMirrorSweeper.RunOnce(ctx); err != nil {
			logger.Warn("x")
		}
		if _, err := danglingSweeper.RunOnce(ctx); err != nil {
			logger.Warn("y")
		}
		return nil
	})
	return nil
}
`

const sweepWiringNotBuilt = `package main

func serve() error {
	orphanMirrorSweeper := seed.NewOrphanMirrorSweeper(kanamepg.NewOrphanMirrorAdapter(pool), seed.OrphanMirrorConfig{})
	tasks = append(tasks, func() error {
		_, _ = orphanMirrorSweeper.RunOnce(ctx)
		return nil
	})
	return nil
}
`

const sweepWiringBuiltNotCalled = `package main

func serve() error {
	orphanMirrorSweeper := seed.NewOrphanMirrorSweeper(kanamepg.NewOrphanMirrorAdapter(pool), seed.OrphanMirrorConfig{})
	danglingSweeper := seed.NewDanglingProjectMirrorSweeper(kanamepg.NewDanglingProjectMirrorAdapter(pool), seed.DanglingProjectMirrorConfig{})
	use(danglingSweeper)
	tasks = append(tasks, func() error {
		_, _ = orphanMirrorSweeper.RunOnce(ctx)
		return nil
	})
	return nil
}
`

const sweepWiringOtherTask = `package main

func serve() error {
	orphanMirrorSweeper := seed.NewOrphanMirrorSweeper(kanamepg.NewOrphanMirrorAdapter(pool), seed.OrphanMirrorConfig{})
	danglingSweeper := seed.NewDanglingProjectMirrorSweeper(kanamepg.NewDanglingProjectMirrorAdapter(pool), seed.DanglingProjectMirrorConfig{})
	tasks = append(tasks, func() error {
		_, _ = orphanMirrorSweeper.RunOnce(ctx)
		return nil
	})
	tasks = append(tasks, func() error {
		_, _ = danglingSweeper.RunOnce(ctx)
		return nil
	})
	return nil
}
`

const sweepWiringOnlyInComments = `package main

// serve зовёт seed.NewDanglingProjectMirrorSweeper и danglingSweeper.RunOnce
// в той же задаче, что orphanMirrorSweeper.RunOnce. Здесь ничего не зовётся.
func serve() error { return nil }
`

func TestPNE203A_InjectionRedsTheSweepWiringAndKeepsQuietOnTheLiveOne(t *testing.T) {
	cases := []struct {
		name        string
		src         string
		wantFinding bool
		wantInText  string
	}{
		{name: "живая провязка — гейт молчит", src: sweepWiringLive},
		{name: "проход не построен", src: sweepWiringNotBuilt, wantFinding: true, wantInText: "не построен"},
		{name: "построен, но RunOnce не позван", src: sweepWiringBuiltNotCalled, wantFinding: true, wantInText: "не позван"},
		{name: "позван из ДРУГОЙ задачи", src: sweepWiringOtherTask, wantFinding: true, wantInText: "НЕ в той же"},
		{name: "имена только в комментариях", src: sweepWiringOnlyInComments, wantFinding: true, wantInText: "беспредметен"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := readSweepWiring(t, "synthetic.go", tc.src)
			findings := judgeSweepWiring(w)
			t.Logf("вызовов %d; сосед %q; проход %q; находок %d: %v",
				w.callsSeen, w.neighbourBound, w.candidateBound, len(findings), findings)
			if tc.wantFinding && len(findings) == 0 {
				t.Fatalf("инъекция не покраснела: гейт не способен упасть на этом входе")
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("законный близнец покраснел: %v", findings)
			}
			if tc.wantInText != "" && !strings.Contains(strings.Join(findings, " | "), tc.wantInText) {
				t.Fatalf("находка не называет %q: %v", tc.wantInText, findings)
			}
		})
	}
}
