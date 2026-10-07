// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// address_in_refusal_text.go — ЯДРО гейта класса: адрес почты участника не
// попадает ни в текст отказа, ни в запись журнала (задача kaname#641).
//
// # Предмет
//
// Текст отказа уезжает вызывающему, а через край — и дальше: в журналы
// соседей, в отчёты клиентов, в чужие трассировки. Запись журнала живёт срок
// хранения журнала. Адрес почты — личные данные и изменяемое значение;
// корреляцию отказа несёт неизменяемый идентификатор (`usr…`), а не адрес.
// Внутренний метод поиска субъекта отвечал «subject not found by email=<адрес>»,
// а репозиторий — «User with email <адрес> not found»: адрес, присланный
// вызывающим, возвращался ему и уезжал во все журналы по пути.
//
// # Почему гейт ДЕРЕВА, а не правка четырёх мест
//
// Мест построения отказа и записи журнала в дереве сотни, и ни одно не видит
// соседей. Автор следующего, скопировав соседнее, внесёт адрес незамеченным:
// отказа нет, красного нет, наблюдаемо это только у получателя текста.
//
// # Что такое «место» — закрытый перечень приёмников
//
// Приёмник — вызов, чьи аргументы становятся текстом отказа либо записью
// журнала. Перечень закрыт и разрешается по ПУТИ импорта, а не по написанию:
// псевдоним (`iamerr`, `c "…/status"`) — форма столь же законная.
//
//	отказ:   fmt.Errorf · errors.New · status.Error/Errorf/New/Newf ·
//	         internal/errors.Wrapf
//	журнал:  slog.<уровень>[Context] · slog.Log/LogAttrs · slog.String/Any/Group ·
//	         log.Print*/Fatal*/Panic* · метод <уровень>[Context]/Log/LogAttrs/With
//	         на любом получателе (журнал службы передаётся значением)
//	подсказка переводчика: mapErr / wrapPgErr — их подсказка уезжает и в текст
//	         отказа, и в журнал полос последнего рубежа
//
// # Что такое «адрес» — формы записи, измеренные по дереву
//
// Распознаватель, не знающий одной из законных форм, МОЛЧИТ. Формы взяты
// обходом дерева, а не по памяти:
//
//	FormAddressIdent    имя переменной/параметра, оканчивающееся на `email`
//	                    либо `recipient` (`email`, `newEmail`, `recipient`);
//	FormAddressField    поле/геттер с именем на `Email`/`Recipient` либо `To`
//	                    (`u.Email`, `req.GetEmail()`, `ev.To`), в том числе
//	                    приведение `domain.Email(x)`.
//
// Имя пакетной КОНСТАНТЫ под эту форму не подпадает (`TextEmailInUse` — текст
// отказа, а не адрес): константы корпуса индексируются, и имя константы
// находкой не бывает.
//
// # Сквозь что разбор смотрит и где он СЛЕП
//
// Разбор спускается сквозь скобки, склейку, приведения и закрытый перечень
// прозрачных функций (`string`, `strings.ToLower/ToUpper/TrimSpace`,
// `fmt.Sprint*`). Прочий вызов, принявший адрес, НЕПРОЗРАЧЕН: что он вернёт,
// разбор без типов не знает (маскирующий построитель `BootstrapAddressAttr`
// возвращает «set/unset», а не адрес). Такие места не находка, но и не
// молчание: перепись печатает их числом и поимённо — иначе «ноль находок»
// было бы неотличимо от «не смотрели».
//
// Вторая слепая зона — значение СТРУКТУРЫ целиком (`"user", u`): адрес в нём
// есть, но поле не названо. Её разбор не судит; она названа здесь, чтобы
// утверждение гейта не было шире его предмета.
//
// Внешний идентификатор субъекта (`external_id`) предметом гейта НЕ является:
// его текст пинится сценарием F4d-30, и решение по нему принято отдельно
// (комментарий задачи kaname#641).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
)

// Формы записи адреса. Имена уезжают в перепись.
const (
	FormAddressIdent = "имя-переменной"
	FormAddressField = "поле-или-геттер"
)

// addressSinkFuncs — приёмники-функции пакетов: путь импорта → имена.
var addressSinkFuncs = map[string]map[string]string{
	"fmt":    {"Errorf": "отказ"},
	"errors": {"New": "отказ"},
	"google.golang.org/grpc/status": {
		"Error": "отказ", "Errorf": "отказ", "New": "отказ", "Newf": "отказ",
	},
	"github.com/PRO-Robotech/kaname/internal/errors": {"Wrapf": "отказ"},
	"log/slog": {
		"Debug": "журнал", "Info": "журнал", "Warn": "журнал", "Error": "журнал",
		"DebugContext": "журнал", "InfoContext": "журнал", "WarnContext": "журнал",
		"ErrorContext": "журнал", "Log": "журнал", "LogAttrs": "журнал",
		"String": "журнал", "Any": "журнал", "Group": "журнал",
	},
	"log": {
		"Print": "журнал", "Printf": "журнал", "Println": "журнал",
		"Fatal": "журнал", "Fatalf": "журнал", "Fatalln": "журнал",
		"Panic": "журнал", "Panicf": "журнал", "Panicln": "журнал",
	},
}

// addressSinkMethods — приёмники-методы на получателе-значении (журнал службы).
var addressSinkMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true, "With": true,
}

// addressHintTranslators — переводчики отказа хранилища, чья подсказка уезжает
// в текст и в журнал (`internal/repo/kaname/pg/pgmaperr.go`).
var addressHintTranslators = map[string]bool{"mapErr": true, "wrapPgErr": true}

// addressTransparentFuncs — функции, сквозь которые адрес проходит как есть.
var addressTransparentFuncs = map[string]map[string]bool{
	"strings": {"ToLower": true, "ToUpper": true, "TrimSpace": true, "Trim": true, "Join": true},
	"fmt":     {"Sprintf": true, "Sprint": true, "Sprintln": true},
}

// AddressCensus — перепись одного обхода. Печатается ВСЕГДА.
type AddressCensus struct {
	Files     int            // не-тестовых файлов Go разобрано
	Sinks     map[string]int // приёмников по виду (отказ / журнал / подсказка)
	Constants int            // пакетных констант проиндексировано
	ByForm    map[string]int // находок по форме адреса
	Opaque    []string       // непрозрачные вызовы, принявшие адрес: «файл:строка вызов»
}

func (c AddressCensus) String() string {
	kinds := make([]string, 0, len(c.Sinks))
	for k, n := range c.Sinks {
		kinds = append(kinds, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(kinds)
	forms := make([]string, 0, len(c.ByForm))
	for k, n := range c.ByForm {
		forms = append(forms, fmt.Sprintf("%s %d", k, n))
	}
	sort.Strings(forms)
	return fmt.Sprintf(
		"перепись: файлов Go %d · приёмников [%s] · констант проиндексировано %d · "+
			"находок по форме [%s] · непрозрачных вызовов с адресом %d %v",
		c.Files, strings.Join(kinds, ", "), c.Constants, strings.Join(forms, ", "),
		len(c.Opaque), c.Opaque)
}

// AddressFinding — один приёмник, получивший адрес.
type AddressFinding struct {
	File string // путь относительно корня
	Line int
	Sink string // имя приёмника, как оно записано
	Kind string // отказ / журнал / подсказка
	Form string // форма адреса
	Expr string // выражение-носитель
}

func (f AddressFinding) String() string {
	return fmt.Sprintf("%s:%d — %s (%s) получает адрес почты [%s]: %s",
		f.File, f.Line, f.Sink, f.Kind, f.Form, f.Expr)
}

// ScanAddressInRefusalText разбирает названные файлы и называет приёмники
// отказа и журнала, получившие адрес почты. Пустоту обхода судит вызывающий.
func ScanAddressInRefusalText(root string, files []string) (AddressCensus, []AddressFinding, error) {
	census := AddressCensus{Sinks: map[string]int{}, ByForm: map[string]int{}}
	fset := token.NewFileSet()
	type parsed struct {
		path string
		file *ast.File
	}
	var all []parsed
	for _, p := range files {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return census, nil, fmt.Errorf("разбор %s: %w", p, err)
		}
		census.Files++
		all = append(all, parsed{path: p, file: f})
	}

	consts := map[string]bool{}
	for _, p := range all {
		indexConstNames(p.file, consts)
	}
	census.Constants = len(consts)

	var findings []AddressFinding
	for _, p := range all {
		rel := p.path
		if r, err := filepath.Rel(root, p.path); err == nil {
			rel = filepath.ToSlash(r)
		}
		aliases := importAliases(p.file)
		ast.Inspect(p.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			kind, args := addressSinkOf(call, aliases)
			if kind == "" {
				return true
			}
			census.Sinks[kind]++
			for _, a := range args {
				form, carrier, opaque := addressIn(a, aliases, consts)
				for _, o := range opaque {
					census.Opaque = append(census.Opaque,
						fmt.Sprintf("%s:%d %s", rel, fset.Position(o.Pos()).Line, briefExpr(o.Fun)))
				}
				if form == "" {
					continue
				}
				census.ByForm[form]++
				findings = append(findings, AddressFinding{
					File: rel, Line: fset.Position(call.Pos()).Line,
					Sink: briefExpr(call.Fun), Kind: kind, Form: form, Expr: briefExpr(carrier),
				})
			}
			return true
		})
	}
	sort.Strings(census.Opaque)
	return census, findings, nil
}

// addressSinkOf — вид приёмника и аргументы, которые он делает текстом.
func addressSinkOf(call *ast.CallExpr, aliases map[string]string) (kind string, args []ast.Expr) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if addressHintTranslators[fn.Name] {
			return "подсказка", call.Args
		}
	case *ast.SelectorExpr:
		if x, ok := fn.X.(*ast.Ident); ok {
			if path, isPkg := aliases[x.Name]; isPkg {
				if k := addressSinkFuncs[path][fn.Sel.Name]; k != "" {
					return k, call.Args
				}
				return "", nil
			}
		}
		if addressSinkMethods[fn.Sel.Name] && len(call.Args) > 0 {
			return "журнал", call.Args
		}
	}
	return "", nil
}

// addressIn — форма адреса в выражении (пусто — адреса нет) и непрозрачные
// вызовы, принявшие адрес.
func addressIn(e ast.Expr, aliases map[string]string, consts map[string]bool) (string, ast.Expr, []*ast.CallExpr) {
	var (
		form    string
		carrier ast.Expr
		opaque  []*ast.CallExpr
	)
	var walk func(ast.Expr)
	walk = func(x ast.Expr) {
		if form != "" || x == nil {
			return
		}
		switch v := x.(type) {
		case *ast.Ident:
			if isAddressName(v.Name, false) && !consts[v.Name] {
				form, carrier = FormAddressIdent, v
			}
		case *ast.SelectorExpr:
			if isAddressName(v.Sel.Name, true) && !consts[v.Sel.Name] {
				form, carrier = FormAddressField, v
				return
			}
			walk(v.X)
		case *ast.ParenExpr:
			walk(v.X)
		case *ast.StarExpr:
			walk(v.X)
		case *ast.UnaryExpr:
			walk(v.X)
		case *ast.BinaryExpr:
			walk(v.X)
			walk(v.Y)
		case *ast.IndexExpr:
			walk(v.X)
		case *ast.CompositeLit:
			for _, el := range v.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					walk(kv.Value)
					continue
				}
				walk(el)
			}
		case *ast.CallExpr:
			if addressTransparent(v, aliases) {
				// Геттер и приведение судятся по своему имени.
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && isAddressName(sel.Sel.Name, true) {
					form, carrier = FormAddressField, v
					return
				}
				for _, a := range v.Args {
					walk(a)
				}
				return
			}
			// Непрозрачный вызов: адрес, принятый им, печатается переписью.
			for _, a := range v.Args {
				if f, _, _ := addressIn(a, aliases, consts); f != "" {
					opaque = append(opaque, v)
					break
				}
			}
		}
	}
	walk(e)
	return form, carrier, opaque
}

// addressTransparent — вызов, сквозь который адрес проходит как есть:
// приведение к строке, геттер/приведение с именем адреса, прозрачная функция.
func addressTransparent(call *ast.CallExpr, aliases map[string]string) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "string"
	case *ast.SelectorExpr:
		if isAddressName(fn.Sel.Name, true) {
			return true
		}
		if x, ok := fn.X.(*ast.Ident); ok {
			if path, isPkg := aliases[x.Name]; isPkg {
				return addressTransparentFuncs[path][fn.Sel.Name]
			}
		}
	}
	return false
}

// isAddressName — несёт ли имя адрес. Для поля и геттера законна заглавная
// форма (`Email`, `GetEmail`, `To`), для переменной — любая с хвостом `email`
// либо `recipient`.
func isAddressName(name string, field bool) bool {
	low := strings.ToLower(name)
	if strings.HasSuffix(low, "email") || strings.HasSuffix(low, "recipient") {
		return true
	}
	return field && name == "To"
}

// indexConstNames — имена пакетных и локальных констант файла.
func indexConstNames(f *ast.File, out map[string]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			return true
		}
		for _, s := range gd.Specs {
			if vs, ok := s.(*ast.ValueSpec); ok {
				for _, id := range vs.Names {
					out[id.Name] = true
				}
			}
		}
		return true
	})
}
