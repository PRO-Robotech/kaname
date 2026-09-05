// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// delete_hint_test.go — гейт: метод репозитория, СНИМАЮЩИЙ строку, обязан
// назвать себя подсказкой отображения ошибок.
//
// ЗАЧЕМ. Отказ по внешнему ключу имеет две противоположные стороны — ссылаемого
// ресурса нет и ресурс ещё используется (см. `reference_direction_test.go`).
// Различает их глагол подсказки `<Ресурс>.<Глагол>`, которую репозиторий
// передаёт в `mapErr`. Метод, снимающий строку и подсказку НЕ передавший,
// получит текст стороны ссылки — то есть отправит клиента создавать то, что на
// деле надо освободить. Без этого гейта различение остаётся объявлением: оно
// исполнимо ровно настолько, насколько подсказка доезжает.
//
// ЧЕМ СУДИТ. Разбором, а не подстрокой: имя метода берётся у объявления
// функции, аргумент — у выражения вызова. Глагол читается ТОЙ ЖЕ функцией
// `IsDeletingVerb`, которой судит рантайм, — собственная копия перечня глаголов
// разошлась бы с нею молча и ровно там, где расхождение не видно.
//
// ГРАНИЦА, названная честно: гейт судит имя МЕТОДА, а не тело. Метод, который
// снимает строку и назван иначе (`Revoke`, `Expire`), под него не подпадает —
// его подсказка остаётся на внимании автора. Расширять перечень глаголов
// «на всякий случай» нельзя: глагол, которого в дереве нет, даёт запись,
// которой нечего проверять.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// deletingMethodPrefixes — имена методов, чья работа есть снятие строки.
// Держатся ЗДЕСЬ, а не выводятся из `IsDeletingVerb`: глагол подсказки и
// префикс имени метода — разные словари, и совпадение их сегодня не свойство
// дерева, а совпадение.
var deletingMethodPrefixes = []string{"Delete", "Remove", "Purge", "Drop"}

func isDeletingMethodName(name string) bool {
	for _, p := range deletingMethodPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func TestDeletingRepoMethodNamesItsKindHint(t *testing.T) {
	out, err := gitenv.Command("", "ls-files", ".").Output()
	if err != nil {
		t.Fatalf("перечень файлов пакета не получен: %v", err)
	}
	var files []string
	for _, f := range strings.Fields(string(out)) {
		if strings.HasSuffix(f, ".go") && !strings.HasSuffix(f, "_test.go") {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatal("прод-файлов пакета прочитано 0 — вердикт беспредметен")
	}

	fset := token.NewFileSet()
	calls, deleting := 0, 0
	var findings []string

	for _, file := range files {
		f, perr := parser.ParseFile(fset, file, nil, 0)
		if perr != nil {
			t.Fatalf("%s не разобран: %v", file, perr)
		}
		c, d, found := auditDeleteHints(fset, f)
		calls += c
		deleting += d
		findings = append(findings, found...)
	}
	bare := len(findings)

	if calls == 0 {
		t.Fatal("вызовов mapErr прочитано 0 — разбор разошёлся с пакетом")
	}
	if deleting == 0 {
		t.Fatal("снимающих методов, зовущих mapErr, прочитано 0 — предпосылка гейта не выполняется")
	}
	sort.Strings(findings)
	t.Logf("перепись: прод-файлов %d · вызовов mapErr %d · из них в снимающих методах %d · без глагола снятия %d",
		len(files), calls, deleting, bare)

	if len(findings) > 0 {
		t.Fatalf("подсказка не доезжает у %d снимающих методов:\n  %s\n"+
			"Такой отказ по внешнему ключу получит текст стороны ССЫЛКИ и отправит клиента создавать то, "+
			"что надо освободить.", len(findings), strings.Join(findings, "\n  "))
	}
}

// auditDeleteHints — ЧИСТЫЙ предикат гейта над одним разобранным файлом.
// Выделен ради инъекции: доказывать способность падать на живом дефекте
// нельзя — такая проба исчезает вместе с ним, то есть ровно тогда, когда дерево
// починено.
//
// Возвращает: вызовов `mapErr` · из них в снимающих методах · находки.
func auditDeleteHints(fset *token.FileSet, f *ast.File) (int, int, []string) {
	calls, deleting := 0, 0
	var findings []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		method := fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != "mapErr" || len(call.Args) < 2 {
				return true
			}
			calls++
			if !isDeletingMethodName(method) {
				return true
			}
			deleting++
			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				// Подсказка вычисляется — снятия смысла в этом нет, автор её
				// осознанно передаёт.
				return true
			}
			hint, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			_, verb, cut := strings.Cut(hint, ".")
			if hint == "" || !cut || !IsDeletingVerb(verb) {
				findings = append(findings, fset.Position(call.Pos()).String()+
					" — метод "+method+" снимает строку, а подсказка "+strconv.Quote(hint)+
					" не называет глагола снятия")
			}
			return true
		})
	}
	return calls, deleting, findings
}
