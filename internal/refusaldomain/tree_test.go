// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package refusaldomain_test

// tree_test.go — гейт дерева: домен отказа берётся у ОБЪЯВЛЕНИЯ, а не пишется
// по месту (задача продукта #2099, предмет ПР-3 приёмки WIRE-1).
//
// # Почему гейт, а не «мы договорились»
//
// До объявления суффикс стоял тремя литералами в трёх производителях, и каждый
// нёс комментарий «совпадает с доменом соседних полос: сервис один». Совпадение
// держалось комментарием, то есть ничем: три места об одном предмете расходятся
// на первой же правке, и различию их покраснеть нечем — оно нигде не выражено.
//
// # Что здесь считается ПРОИЗВОДИТЕЛЕМ
//
// Составной литерал `errdetails.ErrorInfo` — то место, где домен уезжает
// клиенту. Судится ВЫРАЖЕНИЕ поля `Domain`: вызов означает «величина берётся»,
// голое имя — «величина зашита» (в этом дереве такие имена суть строковые
// константы уровня пакета).
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. домен, собранный присваиванием в переменную и уехавший ею;
//  2. отказ, собранный не составным литералом (`proto.Merge`, конструктор);
//  3. производитель ВНЕ дерева службы — их два, и оба названы ведомостью ниже.
//
// # Ведомость самоистекает
//
// Запись, которой больше нечего прощать, — находка: она унаследует следующую
// слепую зону. Поэтому у каждой записи назван владелец и предикат снятия.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// errorInfoType — тип производителя, как он пишется в составном литерале.
const errorInfoType = "errdetails.ErrorInfo"

// censusFloor — порог переписи: ниже него обход считается обвалившимся.
const censusFloor = 400

// ledgerEntry — производитель, чей домен ещё не взят у объявления.
type ledgerEntry struct {
	// File — путь производителя относительно корня службы.
	File string
	// Why — почему домен здесь ещё свой.
	Why string
	// Until — предикат снятия: наблюдаемое условие, при котором записи здесь
	// больше не место.
	Until string
	// Owner — чья это работа. Без владельца запись есть отсрочка без ответчика.
	Owner string
}

// ledger — ведомость производителей, ещё не взявших домен у объявления.
//
// Обе записи — о ЧУЖОЙ работе, и это не отсрочка: у каждой назван владелец,
// предмет которого шире домена отказа, и правка здесь столкнулась бы с ним.
var ledger = []ledgerEntry{
	{
		File:  "internal/apps/kaname/shared/quota.go",
		Why:   "модуль учёта величин выпиливается из службы целиком вместе со своим производителем отказа",
		Until: "файла нет в дереве",
		Owner: "PRO-Robotech/kacho#2117",
	},
	{
		File: "internal/authzguard/deny_details.go",
		Why: "домен здесь — ИМЯ ПАКЕТА КОНТРАКТА, а не суффикс продукта, и он намеренно совпадает " +
			"с тем, что ставит край: вызывающий не обязан знать, какой слой сказал «нет». " +
			"Взять его у объявления продукта значило бы развести две стороны одного контракта",
		Until: "имя пакета контракта переехало вслед за продуктом (решение Р14)",
		Owner: "PRO-Robotech/kacho#2133",
	},
}

// scanResult — что обход увидел.
type scanResult struct {
	// Parsed — не-тестовых файлов Go разобрано.
	Parsed int
	// Producers — составных литералов производителя найдено.
	Producers int
	// Wired — из них берут домен вызовом.
	Wired int
	// Hardcoded — файлы, где домен зашит по месту, по возрастанию.
	Hardcoded []string
	// Nameless — файлы, где производитель не называет домена вовсе.
	Nameless []string
}

// scanTree — обход дерева. Вынесен отдельно от гейта затем, чтобы инъекция
// гоняла ТУ ЖЕ функцию на синтетическом дереве: проверка, доказанная на своей
// копии разбора, доказывает свойство копии.
func scanTree(root string) (scanResult, error) {
	var out scanResult
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || name == "docs" || name == "tests" ||
				name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		out.Parsed++

		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || typeName(cl.Type) != errorInfoType {
				return true
			}
			out.Producers++
			expr := fieldValue(cl, "Domain")
			switch {
			case expr == nil:
				out.Nameless = append(out.Nameless, rel)
			case isCall(expr):
				out.Wired++
			default:
				out.Hardcoded = append(out.Hardcoded, rel)
			}
			return true
		})
		return nil
	})
	sort.Strings(out.Hardcoded)
	sort.Strings(out.Nameless)
	return out, err
}

// TestRefusalDomainComesFromTheDeclaration — сам гейт.
func TestRefusalDomainComesFromTheDeclaration(t *testing.T) {
	scan, err := scanTree(serviceRoot(t))
	if err != nil {
		t.Fatalf("обход дерева службы: %v", err)
	}

	forgiven := map[string]ledgerEntry{}
	for _, e := range ledger {
		forgiven[e.File] = e
	}
	hit := map[string]bool{}
	var findings []string
	for _, rel := range scan.Hardcoded {
		if e, listed := forgiven[rel]; listed {
			hit[rel] = true
			t.Logf("прощено: %s — %s (снимает %s, когда %s)", rel, e.Why, e.Owner, e.Until)
			continue
		}
		findings = append(findings,
			rel+": домен зашит по месту, а не взят у объявления (refusaldomain.For)")
	}
	for _, rel := range scan.Nameless {
		findings = append(findings, rel+": производитель не называет домена вовсе")
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, производителей `%s` найдено %d "+
		"(берут у объявления %d), ведомость прощений: %d записей, из них сработало %d, находок %d",
		scan.Parsed, errorInfoType, scan.Producers, scan.Wired, len(ledger), len(hit), len(findings))

	if scan.Parsed < censusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", scan.Parsed, censusFloor)
	}
	if scan.Producers == 0 {
		t.Fatalf("на %d файлах не найдено НИ ОДНОГО производителя `%s` — разбор перестал видеть "+
			"предмет, и его молчание сказано ни о чём", scan.Parsed, errorInfoType)
	}
	for _, e := range ledger {
		if !hit[e.File] {
			t.Errorf("ведомости нечего прощать в %s: записи здесь больше не место — %s (владелец %s)",
				e.File, e.Until, e.Owner)
		}
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

// isCall — выражение есть вызов, то есть величина БЕРЁТСЯ, а не зашита.
func isCall(e ast.Expr) bool {
	_, ok := e.(*ast.CallExpr)
	return ok
}

// typeName — имя типа составного литерала в форме `pkg.Type`.
func typeName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return ident.Name + "." + sel.Sel.Name
}

// fieldValue — выражение названного поля составного литерала.
func fieldValue(cl *ast.CompositeLit, field string) ast.Expr {
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if ok && key.Name == field {
			return kv.Value
		}
	}
	return nil
}

// serviceRoot — корень дерева службы: два уровня вверх от этого пакета.
func serviceRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	return filepath.Dir(filepath.Dir(wd))
}
