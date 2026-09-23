// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_verdict_single_reader.go — «отозвано ли семейство выпуска» решает
// ОДИН читатель, и каждая поверхность предъявления спрашивает его через ОДНО
// правило (задача PRO-Robotech/kaname#319, решение К10 вариант А).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ И ПОЧЕМУ ОН ГЕЙТ, А НЕ ВНИМАНИЕ
//
// Решение о доступе по семейству принимают три поверхности: `IsRevoked`
// службы отзыва, авторитет отзыва на внутреннем слушателе и читатель
// предъявленного на публичном. Одно решение держится одним читателем только
// тогда, когда второго написания нет нигде:
//
//   - оператор, читающий запись выпуска, — ОДИН литерал в дереве. Второй
//     литерал (свой запрос у одной из поверхностей) разошёлся бы с первым молча
//     — например, забыв, что снятое семейство оставляет у записи ПУСТУЮ
//     живость, — и обе копии были бы зелены на своих пробах;
//   - порт чтения семейства зовёт ТОЛЬКО правило (`internal/tokenrevocation`).
//     Поверхность, позвавшая порт мимо правила, завела бы свою политику на
//     пустой идентификатор и на неответ хранилища;
//   - каждая поверхность ЗАКРЫТОГО перечня зовёт правило. Поверхность, правила
//     не зовущая, семейства не спрашивает вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ УЗЕЛ РАЗОБРАННОГО ДЕРЕВА, А НЕ ТЕКСТ ФАЙЛА
//
// Литерал — узел `BasicLit`, вызов — узел `CallExpr`. Упоминание в комментарии
// (в том числе в этом) находкой не является.
//
// Читающим считается литерал, который ОТКРЫВАЕТСЯ словом `SELECT` либо `WITH`
// и называет таблицу выпусков. Вставка и уборка открываются иначе и читателями
// не считаются: у них другой предмет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО
//
//  1. оператор, собранный из кусков во время исполнения: разбор читает
//     литерал, а не результат конкатенации. Довод держать оператор ОДНОЙ
//     константой, каким он и написан;
//  2. чтение таблицы выпусков ПОДЗАПРОСОМ внутри вставки, правки или удаления:
//     такой литерал открывается не словом чтения. В дереве таких нет;
//  3. вызов порта через переменную функционального типа (`f := r.FamilyRevoked`
//     без вызова на месте): узел вызова здесь другой. В дереве таких нет.
//
// Перечень границ, названный не полностью, хуже отсутствующего: он создаёт
// уверенность.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// FamilyVerdictRulePackage — каталог правила отзыва, единственного вправе
// звать порт чтения семейства.
const FamilyVerdictRulePackage = "internal/tokenrevocation"

// familyVerdictRuleImport — путь импорта правила.
const familyVerdictRuleImport = "github.com/PRO-Robotech/kaname/internal/tokenrevocation"

// familyVerdictPortMethod — имя метода порта чтения семейства.
const familyVerdictPortMethod = "FamilyRevoked"

// familyVerdictRuleFuncs — функции правила, через которые поверхность
// спрашивает о семействе: общее правило отзыва и его половина по семейству.
var familyVerdictRuleFuncs = map[string]bool{"Revoked": true, "FamilyRevoked": true}

// accessTokenTableMarkers — признаки таблицы выпусков в литерале. Имя
// принимается и со схемой, и без неё.
var accessTokenTableMarkers = []string{"kaname.access_tokens", " access_tokens"}

// FamilyVerdictSite — координата находки или узла переписи.
type FamilyVerdictSite struct {
	File string
	Line int
}

// FamilyVerdictCensus — перепись обхода. Объём осмотренного печатается:
// «находок ноль» без него неотличимо от «не смотрели».
type FamilyVerdictCensus struct {
	FilesParsed  int
	LiteralsSeen int
	CallsSeen    int
	// Readers — литералы, читающие таблицу выпусков.
	Readers []FamilyVerdictSite
	// Bypasses — вызовы порта чтения семейства вне правила.
	Bypasses []FamilyVerdictSite
	// RuleCallers — каталоги, чьи файлы зовут правило.
	RuleCallers map[string]bool
}

// FamilyVerdict разбирает названные непроверочные файлы (путь относительно
// корня модуля → исходник) и переписывает читателей семейства.
func FamilyVerdict(files map[string]string) (FamilyVerdictCensus, error) {
	out := FamilyVerdictCensus{RuleCallers: map[string]bool{}}
	fset := token.NewFileSet()

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		f, err := parser.ParseFile(fset, name, files[name], 0)
		if err != nil {
			return out, fmt.Errorf("разбор %s: %w", name, err)
		}
		out.FilesParsed++
		inRule := dirOf(name) == FamilyVerdictRulePackage
		ruleName := localImportName(f, familyVerdictRuleImport, "tokenrevocation")

		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				out.LiteralsSeen++
				text, uerr := strconv.Unquote(node.Value)
				if uerr != nil {
					text = node.Value
				}
				if readsAccessTokens(text) {
					out.Readers = append(out.Readers, FamilyVerdictSite{
						File: name, Line: fset.Position(node.Pos()).Line,
					})
				}
			case *ast.CallExpr:
				out.CallsSeen++
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkg, isIdent := sel.X.(*ast.Ident); isIdent && ruleName != "" && pkg.Name == ruleName {
					if familyVerdictRuleFuncs[sel.Sel.Name] {
						out.RuleCallers[dirOf(name)] = true
					}
					return true
				}
				if sel.Sel.Name == familyVerdictPortMethod && !inRule {
					out.Bypasses = append(out.Bypasses, FamilyVerdictSite{
						File: name, Line: fset.Position(node.Pos()).Line,
					})
				}
			}
			return true
		})
	}
	return out, nil
}

// FamilyVerdictFindings судит перепись против ЗАКРЫТОГО перечня поверхностей.
// Пусто — норма.
func FamilyVerdictFindings(c FamilyVerdictCensus, surfaces []string) []string {
	var found []string
	if c.FilesParsed == 0 {
		return []string{"обход дал ноль файлов: судить нечего — это «не смотрели», а не «чисто»"}
	}
	switch len(c.Readers) {
	case 0:
		found = append(found, "читателей записи выпуска НОЛЬ: ответа о семействе не из чего "+
			"взяться, либо оператор переименован или собран из кусков — гейт потерял предмет")
	case 1:
	default:
		var at []string
		for _, r := range c.Readers {
			at = append(at, fmt.Sprintf("%s:%d", r.File, r.Line))
		}
		found = append(found, fmt.Sprintf("читателей записи выпуска %d, а решение о семействе обязано "+
			"читаться ОДНИМ оператором — второе написание разойдётся с первым молча: %s",
			len(c.Readers), strings.Join(at, ", ")))
	}
	for _, b := range c.Bypasses {
		found = append(found, fmt.Sprintf("%s:%d: порт чтения семейства позван мимо правила %s — "+
			"у поверхности своя политика на пустой идентификатор и на неответ хранилища",
			b.File, b.Line, FamilyVerdictRulePackage))
	}
	for _, s := range surfaces {
		if !c.RuleCallers[s] {
			found = append(found, fmt.Sprintf("поверхность %s не зовёт правило отзыва: о семействе "+
				"выпуска она не спрашивает вовсе", s))
		}
	}
	return found
}

// readsAccessTokens — открывается ли литерал словом чтения и называет ли он
// таблицу выпусков.
func readsAccessTokens(lit string) bool {
	head := strings.ToUpper(strings.TrimSpace(lit))
	if !strings.HasPrefix(head, "SELECT") && !strings.HasPrefix(head, "WITH") {
		return false
	}
	for _, m := range accessTokenTableMarkers {
		if strings.Contains(lit, m) {
			return true
		}
	}
	return false
}

// dirOf — каталог файла в косой записи.
func dirOf(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[:i]
	}
	return "."
}
