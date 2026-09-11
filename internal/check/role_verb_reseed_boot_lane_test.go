// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_reseed_boot_lane_test.go — IAM-RV-1-07, ЗАГРУЗОЧНАЯ ПОЛОВИНА:
// отказ пересчёта проекции роли ВИДЕН, а не проглочен.
//
// Порт с монорепо (`internal/repohygiene/roleverbreseedbootlane_test.go`,
// снят вынесением службы — `kacho#2597`). Дословно: весь разбор и гейт.
// Изменилось: пакет (`repohygiene` → `check_test`), координата
// композиционного корня (`services/iam/cmd/kaname/serve.go` →
// `cmd/kaname/serve.go` — в kaname код службы лежит от корня), обход
// (`repoRoot(t)` → `platformtree.RequireCorpus(t)`).
//
// # Почему этот гейт ОБЯЗАТЕЛЕН — цитата ЖИВА в прод-коде kaname
//
// `internal/apps/kaname/seed/role_verb_reseed_integration_test.go` дословно
// называет держателя: «internal/repohygiene/roleverbreseedbootlane_test.go».
// До этого файла держателя в дереве kaname не было ни одного.
//
// # ПОЧЕМУ ЭТО ГЕЙТ ДЕРЕВА, А НЕ ПРОБА (дословно из монорепо)
//
// У сценария две половины. Первая — поведение самого досева — проверяется
// интеграционной пробой рядом с кодом досева. Вторая — уровень, которым отказ
// сообщается ОПЕРАТОРУ, — живёт в композиционном корне, то есть в `package
// main`, и ни одна проба Go до неё не дотягивается by construction.
//
// # ЧТО ИМЕННО ТРЕБУЕТСЯ
//
//  1. у досева проекции глаголов роли есть СВОЙ вызов в композиционном корне;
//  2. ветка отказа этого вызова печатает `Error`, а НЕ `Warn`/`Info`/`Debug`;
//  3. ветка отказа печатает ХОТЬ ЧТО-ТО.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// bootCompositionRoot — композиционный корень kaname.
const bootCompositionRoot = "cmd/kaname/serve.go"

// seedPackageIdent — имя, под которым композиционный корень импортирует досев.
const seedPackageIdent = "seed"

// roleVerbReseedMarker — по чему опознаётся вызов досева проекции глаголов роли.
const roleVerbReseedMarker = "RoleVerb"

// swallowingLevels — уровни, которыми отказ пересчёта сообщать НЕЛЬЗЯ.
var swallowingLevels = map[string]bool{"Warn": true, "Info": true, "Debug": true}

// loggerLevels — все уровни, по которым узнаётся «ветка отказа что-то печатает».
var loggerLevels = map[string]bool{
	"Warn": true, "Info": true, "Debug": true, "Error": true, "Fatal": true,
}

// bootReseedReport — что гейт увидел в композиционном корне.
type bootReseedReport struct {
	SeedCalls   int
	ReseedCalls []string
	Levels      []string
	Silent      []string
}

// inspectBootRoleVerbReseed разбирает композиционный корень.
func inspectBootRoleVerbReseed(filename, src string) (bootReseedReport, error) {
	var rep bootReseedReport
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return rep, err
	}

	isReseedCall := func(n ast.Node) string {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != seedPackageIdent {
			return ""
		}
		return sel.Sel.Name
	}

	levelsInFailureBranch := func(nodes []ast.Stmt) []string {
		var out []string
		for _, n := range nodes {
			ast.Inspect(n, func(x ast.Node) bool {
				ifs, ok := x.(*ast.IfStmt)
				if !ok {
					return true
				}
				ast.Inspect(ifs.Body, func(y ast.Node) bool {
					call, ok := y.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || !loggerLevels[sel.Sel.Name] {
						return true
					}
					out = append(out, sel.Sel.Name)
					return true
				})
				return true
			})
		}
		return out
	}

	type candidate struct {
		span  int
		block *ast.BlockStmt
		index int
	}
	best := map[token.Pos]candidate{}
	names := map[token.Pos]string{}

	ast.Inspect(file, func(n ast.Node) bool {
		if name := isReseedCall(n); name != "" {
			rep.SeedCalls++
			if strings.Contains(name, roleVerbReseedMarker) {
				names[n.Pos()] = name
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i, stmt := range block.List {
			for pos := range names {
				if pos < stmt.Pos() || pos >= stmt.End() {
					continue
				}
				span := int(stmt.End() - stmt.Pos())
				if cur, seen := best[pos]; !seen || span < cur.span {
					best[pos] = candidate{span: span, block: block, index: i}
				}
			}
		}
		return true
	})

	positions := make([]token.Pos, 0, len(best))
	for pos := range best {
		positions = append(positions, pos)
	}
	sort.Slice(positions, func(a, b int) bool { return positions[a] < positions[b] })

	for _, pos := range positions {
		c := best[pos]
		rep.ReseedCalls = append(rep.ReseedCalls, names[pos])
		window := []ast.Stmt{c.block.List[c.index]}
		if c.index+1 < len(c.block.List) {
			window = append(window, c.block.List[c.index+1])
		}
		levels := levelsInFailureBranch(window)
		if len(levels) == 0 {
			rep.Silent = append(rep.Silent, names[pos])
		}
		rep.Levels = append(rep.Levels, levels...)
	}
	return rep, nil
}

// TestIAMRV107_BootReportsRoleVerbReseedFailureAtErrorLevel — сам гейт.
func TestIAMRV107_BootReportsRoleVerbReseedFailureAtErrorLevel(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	path := filepath.Join(ownDir, filepath.FromSlash(bootCompositionRoot))
	b, err := os.ReadFile(path) // #nosec G304 -- путь из этого же дерева
	if err != nil {
		t.Fatalf("чтение %s: %v — композиционный корень не прочитан, и молчание гейта "+
			"ничего не значит", bootCompositionRoot, err)
	}
	rep, perr := inspectBootRoleVerbReseed(bootCompositionRoot, string(b))
	if perr != nil {
		t.Fatalf("разбор %s: %v", bootCompositionRoot, perr)
	}

	t.Logf("осмотрен %s: вызовов пакета досева %d; из них досева проекции глаголов %d %v; "+
		"уровней в ветке отказа %v", bootCompositionRoot, rep.SeedCalls,
		len(rep.ReseedCalls), rep.ReseedCalls, rep.Levels)

	if rep.SeedCalls == 0 {
		t.Fatalf("в %s не найдено НИ ОДНОГО вызова пакета досева — предпосылка гейта неверна: "+
			"либо корень переехал, либо досев зовётся под другим именем пакета",
			bootCompositionRoot)
	}
	if len(rep.ReseedCalls) == 0 {
		t.Errorf("у досева проекции глаголов роли НЕТ собственного вызова в %s "+
			"(искали вызов `%s.*%s*`).\n"+
			"Пока пересчёт спрятан внутри чужого досева, у его отказа нет собственной полосы: "+
			"он приезжает вызывающему обёрнутым в чужую ошибку и печатается уровнем чужой "+
			"полосы. Различить «база не ответила» и «механизм не работает» на этом входе нечем.",
			bootCompositionRoot, seedPackageIdent, roleVerbReseedMarker)
	}
	for _, name := range rep.Silent {
		t.Errorf("ветка отказа `%s.%s` не печатает НИЧЕГО — отказ проглочен полнее, чем любым "+
			"`Warn`: состояние вердикта неизвестно, и об этом никто не узнает",
			seedPackageIdent, name)
	}
	for _, lvl := range rep.Levels {
		if swallowingLevels[lvl] {
			t.Errorf("отказ пересчёта проекции роли сообщается уровнем `%s` — а обязан `Error`.\n"+
				"`Warn` в этом дереве значит «ожидаемое отклонение, ретрай штатен». Проекция, "+
				"не пересеянная целиком, — не отклонение, а НЕИЗВЕСТНОЕ состояние вердикта: "+
				"цепь ответа «разрешено ли действие» собирается из строк, которых может не быть.", lvl)
		}
	}
}
