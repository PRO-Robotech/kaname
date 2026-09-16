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
// клиенту. Судится ВЫРАЖЕНИЕ поля `Domain`, и «берётся» значит ОДНО из двух:
//
//	Domain: refusaldomain.For(…)   — вызов по месту;
//	Domain: denyDomain             — имя уровня ПАКЕТА, чей инициализатор вызов.
//
// Вторая форма добавлена задачей kaname#126, и добавлена потому, что посылка
// прежнего разбора была ЛОЖНА: он считал всякое голое имя строковой константой,
// тогда как `denyDomain` берётся вызовом `contractnaming.OwnContractPackage()`.
// Производитель, бравший домен у объявления, числился зашитым и держался
// записью ведомости — то есть послабление прощало ИСПОЛНЕННЫЙ предикат, а
// форма записи «величину вычислили один раз при старте» оставалась вне
// наблюдения.
//
// Имя резолвится по ВСЕМУ ПАКЕТУ (каталогу), а не по файлу: объявление и
// производитель законно лежат в разных файлах одного пакета, и резолюция в
// пределах файла давала бы ЛОЖНУЮ находку.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. домен, собранный присваиванием в переменную ВНУТРИ функции;
//  2. имя, чей инициализатор — не вызов, а другое имя (цепочка длиннее одного
//     звена);
//  3. отказ, собранный не составным литералом (`proto.Merge`, конструктор);
//  4. производитель, чей домен ещё не взят у объявления. Записей было три, и
//     все три сняты вместе со своим предметом — ведомость сегодня ПУСТА.
//     Запись ступени S0a о `pkg/subjectchange`: производитель приехал в это
//     дерево из модуля платформы, и до переезда его не видел ни один прогон
//     этого репозитория — слепая зона была не «разбор не умеет», а «файла в
//     дереве нет»; снята kaname#48. Запись об отказе учёта
//     (`internal/apps/kaname/shared/quota.go`): её довод — «производитель уходит
//     вместе с модулем учёта» — опроверг сам уход модуля (kacho#2117): ушёл
//     авторитет величин, а счётчик и его отказ остались; снята kacho#2076, домен
//     там берётся у объявления. Третья — о `internal/authzguard/deny_details.go`:
//     её предикат («имя пакета контракта переехало вслед за продуктом») был
//     ИСПОЛНЕН закрытием kacho#2133, а запись продолжала прощать; снята
//     kaname#126 вместе с починкой посылки разбора.
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
// Все записи — о ЧУЖОЙ работе, и это не отсрочка: у каждой назван владелец,
// предмет которого шире домена отказа, и правка здесь столкнулась бы с ним.
// ПУСТА, и это цель механизма, а не его простой: гейт проходит на пустой
// ведомости и падает на записи, которой нечего прощать (см. ветвь `hit` ниже).
var ledger = []ledgerEntry{}

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
	// computed — по каталогу: имена уровня пакета, чья величина ВЫЧИСЛЕНА вызовом.
	computed := map[string]map[string]bool{}
	type parsedFile struct {
		rel, pkg string
		file     *ast.File
	}
	var files []parsedFile
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
		// ПЕРВЫЙ проход по файлу: имена уровня пакета, чей инициализатор — вызов.
		// Собираются по КАТАЛОГУ: объявление и производитель законно лежат в
		// разных файлах одного пакета.
		pkg := filepath.Dir(rel)
		for _, name := range callInitialisedNames(file) {
			if computed[pkg] == nil {
				computed[pkg] = map[string]bool{}
			}
			computed[pkg][name] = true
		}
		files = append(files, parsedFile{rel: rel, pkg: pkg, file: file})
		return nil
	})
	// ВТОРОЙ проход: классификация. Отдельным проходом потому, что имя может
	// объявляться в файле, который обход прочитает ПОЗЖЕ производителя.
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || typeName(cl.Type) != errorInfoType {
				return true
			}
			out.Producers++
			expr := fieldValue(cl, "Domain")
			switch {
			case expr == nil:
				out.Nameless = append(out.Nameless, pf.rel)
			case isTaken(expr, computed[pf.pkg]):
				out.Wired++
			default:
				out.Hardcoded = append(out.Hardcoded, pf.rel)
			}
			return true
		})
	}
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

// isTaken — величина БЕРЁТСЯ, а не зашита. Две законные формы, и обе названы:
// вызов по месту либо имя уровня пакета, чей инициализатор — вызов.
//
// Второй формы разбор не знал, и это делало его посылку («голое имя = строковая
// константа») ложной: производитель, бравший домен у объявления, числился
// зашитым (kaname#126).
func isTaken(e ast.Expr, computed map[string]bool) bool {
	if _, ok := e.(*ast.CallExpr); ok {
		return true
	}
	ident, ok := e.(*ast.Ident)
	return ok && computed[ident.Name]
}

// callInitialisedNames — имена уровня ПАКЕТА, чей инициализатор есть вызов.
//
// Судится узел объявления, а не текст: имя, названное в комментарии, сюда не
// попадает by construction. Читаются `var` и `const` верхнего уровня; имя внутри
// функции именем уровня пакета не является и резолюции не подлежит — иначе
// локальная переменная с тем же именем прощала бы зашитый домен в соседнем
// файле.
func callInitialisedNames(file *ast.File) []string {
	var out []string
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if _, isCall := vs.Values[i].(*ast.CallExpr); isCall {
					out = append(out, name.Name)
				}
			}
		}
	}
	return out
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
