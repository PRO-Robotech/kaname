// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// poisoned_queue_is_scanned_test.go — очередь, чьё ТРАВЛЕНИЕ ведёт собственный
// оператор сервиса, обязана иметь скан состояния (#2050, предикат 3).
//
// # ПРЕДМЕТ
//
// Дренаж сообщает о СОБЫТИЯХ и делает это в лог: строка применилась, строка
// отравилась. «В очереди лежит N строк, старейшей M секунд, из них K
// отравлено» — это СОСТОЯНИЕ, и его не производит никто, кроме периодического
// скана таблицы. Без скана застрявшая очередь неотличима от пустой: обе молчат
// одинаково.
//
// Отсечка без наблюдаемости хуже её отсутствия: она делает отказ ТИХИМ. Строка,
// перешагнувшая порог, из клейма выпадает и повторяться перестаёт — то есть
// перестаёт и жаловаться. Величина `poisoned` — единственное, что об этом
// говорит.
//
// # ПОЧЕМУ КЛАСС ИМЕННО ТАКОЙ
//
// Ключ — не «есть очередь», а «сервис ведёт её счётчик попыток СВОИМ
// оператором». У очередей, чьё травление ведёт общая оснастка дренажа, вопрос
// уже задан её собственными гейтами; здесь речь о тех, где отсечку сервис
// написал сам, — и ровно там её наблюдаемость забывают, потому что общая
// оснастка её не приносит.
//
// # ЧТО ГЕЙТ СУДИТ, А ЧТО НЕТ
//
// Судит РАЗОБРАННЫЙ исходник: оператор травления ищется внутри СТРОКОВЫХ
// ЛИТЕРАЛОВ, а не в тексте файла — иначе комментарий, объясняющий этот же
// оператор (а он есть, и не один), читался бы как его наличие.
//
// Имя таблицы у скана резолвится по константам композиционного корня. Значение,
// которое разбором не восстанавливается (константа чужого пакета), СЧИТАЕТСЯ
// отдельной величиной и НЕ считается сканом: «ноль находок» обязано быть
// отличимо от «ноль разобранного».
//
// Гейт не судит, ЧТО именно скан публикует и с каким порогом: это утверждение
// о содержании, и его держит паритет величин с самой очередью (`MaxAttempts`
// берётся её константой, а не переписывается).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// rePoisonWriter — собственный оператор травления: учёт попытки по строке
// очереди. Ищется ВНУТРИ строкового литерала.
var rePoisonWriter = regexp.MustCompile(
	`(?is)UPDATE\s+([\w.]+)\s.{0,400}?attempt_count\s*=\s*attempt_count\s*\+\s*1`)

// poisonScanCensus — объём осмотренного.
type poisonScanCensus struct {
	repoFiles  int // прод-файлов хранилища прочитано
	rootFiles  int // прод-файлов композиционного корня прочитано
	literals   int // строковых литералов осмотрено
	poisoners  int // очередей с собственным оператором травления
	scanned    int // очередей, над которыми поднят скан состояния
	unresolved int // сканов, чьё имя таблицы разбором не восстановлено
}

// auditPoisonedQueuesAreScanned — чистое ядро обеих проб.
//
// repo — исходники хранилища (имя файла → текст), root — исходники
// композиционного корня.
func auditPoisonedQueuesAreScanned(repo, root map[string]string) ([]string, poisonScanCensus) {
	var findings []string
	c := poisonScanCensus{repoFiles: len(repo), rootFiles: len(root)}

	poisoned := map[string][]string{} // таблица → где найден оператор
	for _, name := range sortedNames(repo) {
		file, err := parser.ParseFile(token.NewFileSet(), name, repo[name], parser.SkipObjectResolution)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: исходник не разобран: %v", name, err))
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			c.literals++
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				text = lit.Value // сырой backquote-литерал `…` Unquote берёт, но подстрахуемся
			}
			for _, m := range rePoisonWriter.FindAllStringSubmatch(text, -1) {
				poisoned[m[1]] = append(poisoned[m[1]], name)
			}
			return true
		})
	}
	c.poisoners = len(poisoned)

	scanned, unresolved := scannedQueueTables(root)
	c.scanned, c.unresolved = len(scanned), len(unresolved)

	for _, table := range sortedKeysOf(poisoned) {
		if scanned[table] {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"очередь %s ведёт собственный счётчик попыток (%s), а скана состояния над ней "+
				"нет: отсечённая строка выпадает из клейма и перестаёт жаловаться, поэтому "+
				"застрявшая очередь молчит так же, как пустая. Подними "+
				"outboxmetrics.NewCollector над этой таблицей в композиционном корне",
			table, strings.Join(poisoned[table], ", ")))
	}
	// Скан, чьё имя таблицы разбором не восстановлено, находкой НЕ объявляется:
	// негодного в нём ничего нет — это граница РАСПОЗНАВАТЕЛЯ (константа живёт в
	// чужом пакете). Он лишь не засчитывается покрытием, то есть решает в сторону
	// осторожности, и СЧИТАЕТСЯ отдельной величиной переписи: «ноль находок»
	// обязано быть отличимо от «ноль разобранного».
	_ = unresolved
	return findings, c
}

// scannedQueueTables — таблицы, над которыми в композиционном корне поднят скан
// состояния, плюс координаты сканов с неразрешимым именем таблицы.
func scannedQueueTables(root map[string]string) (map[string]bool, []string) {
	consts := map[string]string{}
	files := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, name := range sortedNames(root) {
		file, err := parser.ParseFile(fset, name, root[name], parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		files[name] = file
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != len(spec.Values) {
				return true
			}
			for i, id := range spec.Names {
				lit, isLit := spec.Values[i].(*ast.BasicLit)
				if isLit && lit.Kind == token.STRING {
					if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
						consts[id.Name] = v
					}
				}
			}
			return true
		})
	}

	scanned, unresolved := map[string]bool{}, []string(nil)
	for _, name := range sortedNames(root) {
		file, ok := files[name]
		if !ok {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			comp, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := comp.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "CollectorConfig" {
				return true
			}
			for _, elt := range comp.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Table" {
					continue
				}
				switch v := kv.Value.(type) {
				case *ast.BasicLit:
					if v.Kind == token.STRING {
						if s, uerr := strconv.Unquote(v.Value); uerr == nil {
							scanned[s] = true
							continue
						}
					}
					unresolved = append(unresolved, fset.Position(kv.Pos()).String())
				case *ast.Ident:
					if s, known := consts[v.Name]; known {
						scanned[s] = true
						continue
					}
					unresolved = append(unresolved, fset.Position(kv.Pos()).String())
				default:
					unresolved = append(unresolved, fset.Position(kv.Pos()).String())
				}
			}
			return true
		})
	}
	return scanned, unresolved
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readTrackedGo — отслеживаемые непроверочные исходники Go под каталогом.
func readTrackedGo(t *testing.T, dir string) map[string]string {
	t.Helper()
	paths, err := treecorpus.UnderWithSuffix(dir, ".go")
	require.NoError(t, err)
	out := map[string]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		raw, rerr := os.ReadFile(p) // #nosec G304 -- путь пришёл из индекса git
		require.NoError(t, rerr)
		out[filepath.Base(p)] = string(raw)
	}
	return out
}

// TestEveryQueueWithItsOwnPoisonCounterIsScanned — несущее утверждение.
func TestEveryQueueWithItsOwnPoisonCounterIsScanned(t *testing.T) {
	repo := readTrackedGo(t, "../../internal/repo")
	root := readTrackedGo(t, ".")

	findings, c := auditPoisonedQueuesAreScanned(repo, root)

	t.Logf("перепись: прод-файлов хранилища %d · композиционного корня %d · строковых "+
		"литералов %d · очередей с собственным травлением %d · со сканом состояния %d · "+
		"сканов с неразрешённым именем таблицы %d · находок %d",
		c.repoFiles, c.rootFiles, c.literals, c.poisoners, c.scanned, c.unresolved, len(findings))

	require.NotZero(t, c.repoFiles, "обход хранилища пуст — вердикт беспредметен")
	require.NotZero(t, c.rootFiles, "обход композиционного корня пуст — вердикт беспредметен")
	require.NotZero(t, c.poisoners,
		"ни одной очереди с собственным оператором травления не найдено. Это НЕ «класс "+
			"закрыт»: оператор в дереве есть, значит разбор перестал его узнавать — "+
			"отрицание стало вакуумным")

	require.Emptyf(t, findings, "очередь травит строки и молчит об этом:\n%s",
		strings.Join(findings, "\n"))
}
