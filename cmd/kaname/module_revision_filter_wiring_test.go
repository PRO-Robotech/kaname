// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_revision_filter_wiring_test.go — применители ролей и посева получают
// ПРИМЕНЁННУЮ часть доставки (kaname#865, приёмка
// `module-manifest-revision-only-moves-forward.md`, Д3; сценарии 865-07,
// 865-24).
//
// Модуль, пропущенный применителем каталога как младшая редакция либо
// отвергнутый конфликтом содержимого, не получает ни роли, ни посев. Перечень
// приходит значением из итога применителя каталога (`applyDeliveredManifests`),
// и этот гейт судит, что корень подаёт применителям ролей и посева именно его,
// а не перечень загрузчика доставки.
//
// Судится УЗЕЛ разбора: довод вызова — идентификатор, связанный присваиванием
// с вызовом `applyDeliveredManifests`. Имена шагов встречаются в комментариях
// корня, и проверка по тексту краснела бы на объяснении.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// appliedListCall — вызов применителя, которому положен применённый перечень,
// и позиция довода доставки в нём.
type appliedListCall struct {
	fn  string
	arg int
}

var appliedListCalls = []appliedListCall{
	{fn: "applyDeliveredModuleRoles", arg: 3},
	{fn: "applyModuleSeed", arg: 4},
}

// appliedListCensus — объём осмотренного и находки.
type appliedListCensus struct {
	calls    map[string]int
	bound    map[string]bool
	findings []string
}

// judgeAppliedListFeeds судит один исходник корня.
func judgeAppliedListFeeds(t *testing.T, name, src string) appliedListCensus {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть находка", name, err)
	}
	c := appliedListCensus{calls: map[string]int{}, bound: map[string]bool{}}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		call, isCall := assign.Rhs[0].(*ast.CallExpr)
		if !isCall {
			return true
		}
		if fn, isIdent := call.Fun.(*ast.Ident); isIdent && fn.Name == "applyDeliveredManifests" && len(assign.Lhs) > 0 {
			if lhs, isIdent := assign.Lhs[0].(*ast.Ident); isIdent {
				c.bound[lhs.Name] = true
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, isIdent := call.Fun.(*ast.Ident)
		if !isIdent {
			return true
		}
		for _, want := range appliedListCalls {
			if fn.Name != want.fn {
				continue
			}
			c.calls[want.fn]++
			at := fset.Position(call.Pos()).String()
			if len(call.Args) <= want.arg {
				c.findings = append(c.findings, at+": "+want.fn+" несёт доводов меньше позиции доставки")
				continue
			}
			arg, isIdent := call.Args[want.arg].(*ast.Ident)
			if !isIdent || !c.bound[arg.Name] {
				c.findings = append(c.findings, at+": "+want.fn+" получает доставку не из итога "+
					"applyDeliveredManifests — модуль, пропущенный применителем каталога, получил бы и это применение")
			}
		}
		return true
	})
	return c
}

// TestServeFeedsRolesAndSeedOnlyTheAppliedManifests — корень подаёт ролям и
// посеву перечень, вернувшийся из применителя каталога.
func TestServeFeedsRolesAndSeedOnlyTheAppliedManifests(t *testing.T) {
	src, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("serve.go не прочитан: %v — вердикт беспредметен", err)
	}
	c := judgeAppliedListFeeds(t, "serve.go", string(src))
	t.Logf("перепись: вызовов %v · связываний итога применителя каталога %d · находок %d",
		c.calls, len(c.bound), len(c.findings))
	for _, want := range appliedListCalls {
		if c.calls[want.fn] == 0 {
			t.Fatalf("serve.go не зовёт %s — предпосылка проверки не создана", want.fn)
		}
	}
	if len(c.bound) == 0 {
		t.Fatal("serve.go не связывает итог applyDeliveredManifests — подавать ролям и посеву нечего")
	}
	for _, f := range c.findings {
		t.Error(f)
	}
}

// TestAppliedListFeedJudge_FindsTheDeliveryAndSparesTheAppliedList — инъекция
// в обе стороны: перечень загрузчика доставки — находка, итог применителя
// каталога той же формы — молчание.
func TestAppliedListFeedJudge_FindsTheDeliveryAndSparesTheAppliedList(t *testing.T) {
	const tmpl = `package main
func serve() error {
	deliveredManifests, mErr := loadDeliveredManifests(logger, cfg.Manifests)
	if mErr != nil {
		return mErr
	}
	appliedManifests, aErr := applyDeliveredManifests(ctx, logger, catalogApplier, deliveredManifests)
	if aErr != nil {
		return aErr
	}
	if raErr := applyDeliveredModuleRoles(ctx, logger, rolesApplier, ROLES); raErr != nil {
		return raErr
	}
	if seErr := applyModuleSeed(ctx, logger, seedApplier, ownManifest, SEED); seErr != nil {
		return seErr
	}
	return nil
}
`
	lawful := strings.NewReplacer("ROLES", "appliedManifests", "SEED", "appliedManifests").Replace(tmpl)
	c := judgeAppliedListFeeds(t, "lawful.go", lawful)
	if len(c.findings) != 0 {
		t.Fatalf("законный близнец дал находки: %v", c.findings)
	}
	if c.calls["applyDeliveredModuleRoles"] != 1 || c.calls["applyModuleSeed"] != 1 {
		t.Fatalf("контроль разбора: вызовы не увидены: %v", c.calls)
	}

	for _, inj := range []struct{ roles, seed, finds string }{
		{"deliveredManifests", "appliedManifests", "applyDeliveredModuleRoles"},
		{"appliedManifests", "deliveredManifests", "applyModuleSeed"},
	} {
		src := strings.NewReplacer("ROLES", inj.roles, "SEED", inj.seed).Replace(tmpl)
		c := judgeAppliedListFeeds(t, "injected.go", src)
		if len(c.findings) != 1 || !strings.Contains(c.findings[0], inj.finds) {
			t.Errorf("инъекция (%s получает перечень загрузчика доставки) не найдена либо названа не тем: %v",
				inj.finds, c.findings)
		}
	}
}
