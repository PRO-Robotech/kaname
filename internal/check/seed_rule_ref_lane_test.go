// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// seed_rule_ref_lane_test.go — досев на старте пересчитывает проекцию ОБЪЯВЛЕННЫХ
// СЕГМЕНТОВ правила, а не только проекцию глаголов (kacho#1821).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Правило роли читают с ТРЁХ сторон: селекторы отвечают «подходит ли объект»,
// проекция глаголов — «разрешено ли действие», проекция объявленных сегментов
// (`kacho_iam.role_rule_ref`) держит РЕФЕРЕНТ — ключами в каталог ресурсов и в
// каталог глаголов. Первые две пересчитываются на старте
// (`SyncAllSystemRoleSelectors`, `ReseedSystemRoleVerbs`); третью до этой работы
// не писал никто, кроме пути ПОЛЬЗОВАТЕЛЬСКОЙ роли и однократного обратного
// заполнения миграции.
//
// Системная роль заводится сырым SQL миграции и путём пользовательской роли не
// проходит НИКОГДА. Значит у роли, заведённой БУДУЩЕЙ миграцией, строк проекции
// сегментов не появится вовсе: ключи `role_rule_ref_res_fk` /
// `role_rule_ref_verb_fk` окажутся ни при чём, и молчаливый пропуск, ради
// которого референт заводился, вернётся для системной половины. Тихий близнец
// переживает громкого — тот же класс, что уже закрывался для селекторов и для
// проекции глаголов.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО СУДИТСЯ, И ПОЧЕМУ ПО УЗЛУ РАЗБОРА, А НЕ ПО СЛОВУ
//
// Имя `ReplaceRuleRefs` встречается в этом дереве в комментариях, в приёмках и в
// именах дублёров. Проверка по подстроке зеленела бы на СОБСТВЕННОМ объяснении:
// абзац, рассказывающий, что досев обязан звать писателя, содержит его имя
// дословно. Поэтому обе оси судят УЗЕЛ синтаксического дерева — выражение
// вызова, — а комментарий и строковый литерал предметом не являются by
// construction. Это же и есть законный близнец в инъекции.
//
// Ось 1 — досев дотягивается до единственного писателя проекции сегментов:
// в непробных файлах пакета досева есть ВЫЗОВ с селектором `ReplaceRuleRefs`.
// Ось 2 — полосу кто-то зовёт: пакет досева ОБЪЯВЛЯЕТ экспортированную точку
// входа, чьё имя несёт `RuleRef`, и композиционный корень её ВЫЗЫВАЕТ. Без
// второй оси писатель мог бы быть провязан в функцию, которую не зовёт никто, —
// и гейт остался бы зелёным при неработающем досеве.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Гейт судит ИМЯ, а не смысл: пересчёт, переехавший под имя без `RuleRef`, из
// предмета выпадет, и гейт замолчит, оставаясь зелёным (`testing.md` §«Гейт на
// класс», п. 9). Исход тогда один из двух — снять гейт вместе с предметом либо
// перевести на новый признак и доказать заново.
//
// Гейт НЕ утверждает, что после старта строки проекции совпадают с
// `domain.RuleRefsOf(rules)`: это свойство БАЗЫ, и его держит интеграционная
// проба пакета досева. Здесь — свойство ДЕРЕВА: полоса существует и её зовут.
//
// Обе оси печатают объём осмотренного: «ноль находок» обязано быть отличимо от
// «ноль прочитанного», поэтому пустой обход — ОТКАЗ, а не молчание.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

const (
	// ruleRefWriterSelector — единственный писатель проекции объявленных
	// сегментов, объявленный портом записи роли.
	ruleRefWriterSelector = "ReplaceRuleRefs"

	// ruleRefEntryPointMark — признак точки входа полосы среди экспортированных
	// функций пакета досева.
	ruleRefEntryPointMark = "RuleRef"

	// seedPackageDir — каталог досева от корня монорепо.
	seedPackageDir = "services/iam/internal/apps/kacho/seed"

	// compositionRootDir — каталог композиционного корня службы.
	compositionRootDir = "services/iam/cmd/kacho-iam"
)

// goSourcesOfDir — непробные файлы Go каталога, взятые ПО ИНДЕКСУ git.
//
// Единица счёта — отслеживаемый файл: неотслеживаемый мусор рабочей копии в
// вердикт не попадает, а файл, пропавший из индекса, не остаётся осмотренным.
func goSourcesOfDir(t *testing.T, root, dir string) map[string]string {
	t.Helper()
	out, err := gitenv.Command(root, "ls-files", "-z", "--", dir+"/*.go").Output()
	if err != nil {
		t.Fatalf("git ls-files %s: %v — состав каталога не установлен, "+
			"и «ноль находок» здесь означало бы «ноль прочитанного»", dir, err)
	}
	sources := make(map[string]string)
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- путь из индекса git
		require.NoErrorf(t, rerr, "прочитать %s", rel)
		sources[rel] = string(body)
	}
	return sources
}

// callSitesOf — места ВЫЗОВА с названным селектором, по узлам разбора.
//
// Комментарий и строковый литерал сюда не попадают: разбор их узлами вызова не
// делает. Это и есть то свойство, ради которого гейт не написан подстрокой.
func callSitesOf(t *testing.T, sources map[string]string, selector string) []string {
	t.Helper()
	var sites []string
	fset := token.NewFileSet()
	for rel, src := range sources {
		file, err := parser.ParseFile(fset, rel, src, 0)
		require.NoErrorf(t, err, "разобрать %s", rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != selector {
				return true
			}
			sites = append(sites, rel+":"+fset.Position(call.Pos()).String()[len(rel)+1:])
			return true
		})
	}
	sort.Strings(sites)
	return sites
}

// exportedFuncsMarked — экспортированные функции пакета, чьё имя несёт признак.
func exportedFuncsMarked(t *testing.T, sources map[string]string, mark string) []string {
	t.Helper()
	var names []string
	fset := token.NewFileSet()
	for rel, src := range sources {
		file, err := parser.ParseFile(fset, rel, src, 0)
		require.NoErrorf(t, err, "разобрать %s", rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			if strings.Contains(fn.Name.Name, mark) {
				names = append(names, fn.Name.Name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// TestSeedCallsTheSoleWriterOfRuleRefs — ось 1: досев дотягивается до писателя
// проекции объявленных сегментов.
func TestSeedCallsTheSoleWriterOfRuleRefs(t *testing.T) {
	root := monorepoRoot(t)
	sources := goSourcesOfDir(t, root, seedPackageDir)
	require.NotZerof(t, len(sources),
		"обход каталога досева %s пуст — вердикт беспредметен", seedPackageDir)

	sites := callSitesOf(t, sources, ruleRefWriterSelector)
	t.Logf("перепись оси 1: прочитано непробных файлов досева %d · мест вызова %s %d",
		len(sources), ruleRefWriterSelector, len(sites))

	require.NotEmptyf(t, sites,
		"досев на старте НЕ зовёт %s: проекция объявленных сегментов правила "+
			"(kacho_iam.role_rule_ref) у системной роли, заведённой будущей миграцией, "+
			"не появится ни одной строкой, и ключи референта окажутся ни при чём "+
			"(kacho#1821). Осмотрено файлов: %d", ruleRefWriterSelector, len(sources))
}

// TestCompositionRootCallsTheRuleRefReseedLane — ось 2: полосу кто-то зовёт.
//
// Отдельная ось, а не следствие первой: писатель, провязанный в функцию, которую
// не зовёт никто, оставил бы ось 1 зелёной при неработающем досеве.
func TestCompositionRootCallsTheRuleRefReseedLane(t *testing.T) {
	root := monorepoRoot(t)

	seedSources := goSourcesOfDir(t, root, seedPackageDir)
	require.NotZerof(t, len(seedSources),
		"обход каталога досева %s пуст — вердикт беспредметен", seedPackageDir)
	entryPoints := exportedFuncsMarked(t, seedSources, ruleRefEntryPointMark)

	rootSources := goSourcesOfDir(t, root, compositionRootDir)
	require.NotZerof(t, len(rootSources),
		"обход композиционного корня %s пуст — вердикт беспредметен", compositionRootDir)

	called := make([]string, 0, len(entryPoints))
	for _, name := range entryPoints {
		if len(callSitesOf(t, rootSources, name)) > 0 {
			called = append(called, name)
		}
	}
	t.Logf("перепись оси 2: файлов досева %d · точек входа с признаком %q %d (%s) · "+
		"файлов корня %d · позвано корнем %d",
		len(seedSources), ruleRefEntryPointMark, len(entryPoints),
		strings.Join(entryPoints, ", "), len(rootSources), len(called))

	require.NotEmptyf(t, called,
		"композиционный корень не зовёт ни одной точки входа досева с признаком %q: "+
			"объявленные %v. Полоса, которую никто не зовёт, на старте не исполняется, "+
			"и её отсутствие неотличимо от исправной работы (kacho#1821)",
		ruleRefEntryPointMark, entryPoints)
}
