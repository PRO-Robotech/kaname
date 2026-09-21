// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_answer.go — ОТВЕТ О ПОСАДКЕ, КОТОРЫЙ НЕЛЬЗЯ
// ПРОИГНОРИРОВАТЬ (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Строитель административной дороги отдаёт потребителю клиента и на посадке, у
// которой внешнего поставщика нет вовсе: там это клиент БЕЗ АДРЕСА, и всякий
// его вызов получает терминальный отказ. Пока строитель возвращал ОДНО
// значение, «дорога есть» и «дороги нет» приходили потребителю одинаково — и
// потребитель, не спросивший посадку, уносил отставленную дорогу МОЛЧА, а
// отказывала она потом, на пути запроса, у чужого глагола.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРЕДИКАТ — «ОТВЕТ СВЯЗАН С ИМЕНЕМ», А НЕ «ПОСАДКА СПРОШЕНА В ТЕЛЕ»
//
// Первый предикат был бы УДОВЛЕТВОРИМ КОСМЕТИЧЕСКИ: достаточно позвать
// предикат посадки где-нибудь выше по телу, ничего с его ответом не делая, — и
// гейт зеленеет, а отставленная дорога уходит потребителю ровно как прежде.
//
// Здесь судится другое: связан ли ВТОРОЙ возвращаемый значением ответ с именем.
// Это несущее свойство, потому что вторую половину доказывает САМ КОМПИЛЯТОР:
// связанное и неиспользованное имя — ошибка сборки. Значит «связан» влечёт
// «прочитан», и обойти предикат, не приняв решения о посадке, нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. решение, принятое по ответу и тут же отброшенное (`if !built { }`);
//
//  2. вызов строителя через переменную-функцию либо метод — разбор судит
//     ВЫЗОВ ПО ИМЕНИ функции, как и соседний гейт адреса;
//
//  3. второй строитель, заведённый рядом под другим именем: предмет назван
//     именем, и имя это подаётся гейтом, а не выводится;
//
//  4. ПОТРЕБИТЕЛЬ, КОТОРЫЙ СТРОИТЕЛЯ НЕ ЗОВЁТ, А ПОЛУЧАЕТ УЖЕ ПОСТРОЕННОГО
//     КЛИЕНТА ДОВОДОМ. Такой путь под этот предикат не подпадает by
//     construction, и это НЕ мелочь: класс шире того, что здесь судится.
//
//     Измерено: таких потребителей сегодня двое, и оба — варианты использования
//     ключей служебных учёток, принимающие клиента ИНТЕРФЕЙСОМ. Дальше их
//     решение о посадке принимает не они, а тот, кто их собирает, — и оно
//     принято (см. `buildSAKeysHandler`), но принято ОДИН раз на обоих, а не
//     каждым.
//
//     ПРЕДИКАТ СНЯТИЯ ОСТАТКА: у каждого потребителя административной дороги —
//     и зовущего строителя, и принимающего клиента доводом — есть СВОЁ решение
//     о посадке. Закрывается это не здесь: судить довод по типу значит
//     разбирать типы, а не имена, и цена такого разбора решается отдельно.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

// ProviderRoadCall — вызов строителя административной дороги.
type ProviderRoadCall struct {
	File string
	Line int
	Func string
	// AnswerBound — связан ли ОТВЕТ о посадке с непустым именем.
	AnswerBound bool
	// Form — как записан вызов; идёт в текст находки, чтобы она называла
	// ПРИЧИНУ, а не только координату.
	Form string
}

// ProviderRoadCallCensus — объём осмотренного.
type ProviderRoadCallCensus struct {
	// Funcs — функций с телом осмотрено.
	Funcs int
	// Calls — вызовов строителя найдено.
	Calls int
	// Bound — из них связавших ответ с именем.
	Bound int
}

// Формы записи вызова, которые разбор различает.
const (
	formBound     = "ответ связан с именем"
	formDiscarded = "ответ отброшен в `_`"
	formSingle    = "ответ не берётся вовсе — вызов на одно значение"
	formInExpr    = "вызов стоит внутри выражения: ответу негде быть связанным"
)

// ScanProviderRoadCalls разбирает ОДИН файл.
//
// builder — имя функции-строителя; предмет подаётся именем, а не выводится:
// выведенный предмет молча сменился бы вместе с деревом.
func ScanProviderRoadCalls(path string, src []byte, builder string) (
	[]ProviderRoadCall, ProviderRoadCallCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ProviderRoadCallCensus{}, err
	}

	var (
		out    []ProviderRoadCall
		census ProviderRoadCallCensus
	)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		census.Funcs++

		// Сперва — вызовы, стоящие в позиции, где ответу ЕСТЬ где быть
		// связанным: присваивание и объявление переменных. Признак кладётся на
		// сам узел вызова, поэтому второй проход судит каждый вызов один раз и
		// независимо от того, сколько их в теле.
		bound := map[ast.Node]string{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Rhs) != 1 {
					return true
				}
				if call, is := s.Rhs[0].(*ast.CallExpr); is && callsIdent(call, builder) {
					bound[call] = classifyAnswerTargets(s.Lhs)
				}
			case *ast.ValueSpec:
				if len(s.Values) != 1 {
					return true
				}
				if call, is := s.Values[0].(*ast.CallExpr); is && callsIdent(call, builder) {
					targets := make([]ast.Expr, 0, len(s.Names))
					for _, nm := range s.Names {
						targets = append(targets, nm)
					}
					bound[call] = classifyAnswerTargets(targets)
				}
			}
			return true
		})

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !callsIdent(call, builder) {
				return true
			}
			census.Calls++
			form, seen := bound[call]
			if !seen {
				form = formInExpr
			}
			if form == formBound {
				census.Bound++
			}
			out = append(out, ProviderRoadCall{
				File:        path,
				Line:        fset.Position(call.Pos()).Line,
				Func:        fn.Name.Name,
				AnswerBound: form == formBound,
				Form:        form,
			})
			return true
		})
	}
	return out, census, nil
}

// callsIdent — вызов ИМЕНОВАННОЙ функции пакета (не метода и не значения).
func callsIdent(call *ast.CallExpr, name string) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == name
}

// classifyAnswerTargets — что стоит слева от вызова.
func classifyAnswerTargets(lhs []ast.Expr) string {
	if len(lhs) < 2 {
		return formSingle
	}
	id, ok := lhs[1].(*ast.Ident)
	if !ok || id.Name == "_" {
		return formDiscarded
	}
	return formBound
}

// ProviderRoadCallsIgnoringTheAnswer — вызовы, не связавшие ответ.
func ProviderRoadCallsIgnoringTheAnswer(calls []ProviderRoadCall) []ProviderRoadCall {
	var out []ProviderRoadCall
	for _, c := range calls {
		if !c.AnswerBound {
			out = append(out, c)
		}
	}
	return out
}

// ProviderRoadCallPremise — предпосылка вердикта.
//
// Обход, не нашедший НИ ОДНОГО вызова строителя, вердикта не выносит: «находок
// ноль» у него означало бы «прочитано ноль». Порог файлов отделяет это от
// обхода, не добравшегося до дерева вовсе.
func ProviderRoadCallPremise(parsed, floor int, census ProviderRoadCallCensus, builder string) error {
	if parsed < floor {
		return fmt.Errorf("прод-файлов Go разобрано %d при пороге %d — обход не добрался до дерева",
			parsed, floor)
	}
	if census.Funcs == 0 {
		return fmt.Errorf("функций с телом осмотрено 0 — разбор ничего не читал")
	}
	if census.Calls == 0 {
		return fmt.Errorf("вызовов строителя %s не найдено ни одного: предмета в дереве нет, "+
			"и «находок ноль» здесь означает «прочитано ноль». Строитель переименован либо снят — "+
			"гейт обязан сменить имя предмета вместе с ним либо уйти вместе с ним",
			builder)
	}
	return nil
}
