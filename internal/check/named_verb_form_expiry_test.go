// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// named_verb_form_expiry_test.go — ГЕЙТ: отсрочка `#1844` истекает САМА.
//
// Поимённая форма права роли (ключ `verbs:`) возвращается ТОЛЬКО вместе с
// проверкой её полноты. Пока форма отвергается сентинелом, шести проб
// полноты нет по построению — и это законно; в день, когда сентинел
// перестанет возвращаться, а проб по-прежнему не окажется, гейт называет
// недостающие сценарии поимённо.
//
// Порт с монорепо (`internal/repohygiene/namedverbformexpiry_test.go`, снят
// вынесением службы — `kacho#2597`). Имя функции сохранено ДОСЛОВНО — на нём
// держится валидность цитаты в `internal/manifest/roleexport/check.go:77`.
// Изменилось: обход дерева (`repoRoot(t)`/`newTrackedTree` монорепо →
// `platformtree.RequireCorpus` + `treecorpus.UnderWithSuffix` этого дерева,
// см. образец `derived_id_single_source_test.go`), путь домена
// (`services/iam/internal/manifest/` → `internal/manifest/`).
//
// Предмет, довод в пользу пары (а не любой её половины) и границы разбора —
// в шапке `named_verb_form_expiry.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `named_verb_form_expiry_injection_test.go`.
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

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// manifestPackageDir — пакет, где живёт пред-разборная проверка снятого
	// ключа. Прямые дети только: `roleexport/` — соседний домен со своей
	// осью полноты (namedverbs.go), а не носитель сентинела.
	manifestPackageDir = "internal/manifest/"
	// manifestCensusFloor — не-тестовых файлов пакета, ниже которого обход
	// беспредметен: пакет переехал либо снят, и гейт стережёт каталог,
	// которого больше нет.
	manifestCensusFloor = 5
)

// scenarioProbeNames — имена проб сценариев, найденные по ВСЕМУ дереву
// СОБСТВЕННОГО МОДУЛЯ.
//
// По всему модулю, а не по одному пакету: приёмка не назначает шести пробам
// дома, и гейт, ищущий их в одном каталоге, объявил бы отсутствующими те, что
// заведут рядом (ровно так и произошло: `rolenamedverbs_test.go` несёт три
// сценария, `roleexport/namedverbs_test.go` — другие три).
func scenarioProbeNames(t *testing.T, root string) ([]string, int) {
	t.Helper()
	files, err := treecorpus.UnderWithSuffix(root, "_test.go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав тестового дерева не прочитан: %v", err)
	}

	var (
		names  []string
		parsed int
	)
	for _, abs := range files {
		src, rerr := os.ReadFile(abs)
		if rerr != nil {
			continue
		}
		if !strings.Contains(string(src), "TestMODRL") {
			parsed++
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, abs, src, 0)
		if perr != nil {
			t.Fatalf("разбор %s: %v", abs, perr)
		}
		parsed++
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if strings.HasPrefix(fn.Name.Name, "TestMODRL") {
				names = append(names, fn.Name.Name)
			}
		}
	}
	sort.Strings(names)
	return names, parsed
}

// TestNamedVerbFormReturnsOnlyWithItsCompletenessCheck — сам гейт.
func TestNamedVerbFormReturnsOnlyWithItsCompletenessCheck(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	manifestDir := filepath.Join(ownDir, filepath.FromSlash(manifestPackageDir))

	goFiles, err := treecorpus.UnderWithSuffix(manifestDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав %s не прочитан: %v", manifestPackageDir, err)
	}

	var (
		manifestFiles int
		lits, idents  int
		returns       int
	)
	for _, abs := range goFiles {
		rel, rerr := filepath.Rel(manifestDir, abs)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") || strings.Contains(rel, "/") {
			continue // прямые дети только; `roleexport/` судится не здесь
		}
		src, rerr := os.ReadFile(abs)
		if rerr != nil {
			continue
		}
		c, cerr := check.ScanVerbFormSentinel(rel, src)
		if cerr != nil {
			t.Fatalf("разбор %s: %v", rel, cerr)
		}
		manifestFiles++
		lits += c.CompositeLits
		idents += c.Idents
		returns += c.SentinelReturns
	}

	probeNames, testFiles := scenarioProbeNames(t, ownDir)
	missing := check.MissingScenarioProbes(probeNames)
	finding := check.NamedVerbFormFinding(returns, probeNames)

	t.Logf("перепись: не-тестовых файлов %s разобрано %d (литералов %d, идентификаторов %d) · "+
		"возвратов сентинела %s — %d · тестовых файлов дерева осмотрено %d · "+
		"проб MOD-RL найдено %d %v · сценариев отсрочки %d, из них без пробы %d %v",
		manifestPackageDir, manifestFiles, lits, idents,
		check.RoleRuleVerbsSentinel, returns, testFiles,
		len(probeNames), probeNames, len(check.NamedVerbScenarios), len(missing), missing)

	// ── ПРЕДПОСЫЛКИ ОБХОДА ───────────────────────────────────────────────────
	if manifestFiles < manifestCensusFloor {
		t.Fatalf("перепись обвалилась: не-тестовых файлов %s разобрано %d при пороге %d — "+
			"пакет переехал либо снят, и гейт стережёт каталог, которого больше нет",
			manifestPackageDir, manifestFiles, manifestCensusFloor)
	}
	if lits == 0 {
		t.Fatalf("в пакете %s не прочитано ни одного составного литерала — ось разбора "+
			"беспредметна, и «возвратов ноль» получено даром", manifestPackageDir)
	}
	if testFiles == 0 {
		t.Fatal("обход тестовых файлов дерева пуст — перепись проб беспредметна, и " +
			"«проб нет» неотличимо от «ничего не прочитано»")
	}
	if len(check.NamedVerbScenarios) == 0 {
		t.Fatal("перечень сценариев отсрочки пуст — требовать нечего, и молчание гейта " +
			"было бы сказано ни о чём")
	}

	// ── НАХОДКА — ПАРА, а не половина ────────────────────────────────────────
	//
	// Решение принимает `NamedVerbFormFinding` — ТА ЖЕ функция, которую гоняет
	// инъекция. Молчание у неё две законные причины: форма отвергается либо
	// вернулась вместе со своей проверкой.
	if len(finding) == 0 {
		return
	}
	t.Fatalf("ключ `verbs:` правила роли больше не отвергается сентинелом %s (возвратов в %s — "+
		"ноль), а проб полноты по-прежнему нет у %d сценариев из %d: %v\n\n"+
		"Поимённый перечень действий возвращается ТОЛЬКО вместе с проверкой его полноты по "+
		"классу (#1844). Принять перечень имён, не умея проверить полноту, значит свести его "+
		"к классу МОЛЧА — то есть выдать право ШИРЕ просимого: замер приёмки называет 55 "+
		"вхождений из 92 в черновике vpc, совпадающих с именем класса.\n"+
		"Исходов два: завести пробы названных сценариев ЛИБО вернуть отказ сентинелом. "+
		"Третьего — «принять форму и доделать проверку позже» — нет.\n"+
		"Найдено проб MOD-RL: %v",
		check.RoleRuleVerbsSentinel, manifestPackageDir, len(missing), len(check.NamedVerbScenarios),
		finding, probeNames)
}
