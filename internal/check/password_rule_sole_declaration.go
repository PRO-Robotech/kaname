// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_rule_sole_declaration.go — ГЕЙТ КЛАССА: правило пароля объявлено в
// дереве ОДИН раз, и всякая полоса, меняющая материал, зовёт его, а не несёт
// своего (приёмка Ф3, сценарий Ф3-32; Ф1-38; задача kacho#1269).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Три полосы меняют материал пароля: смена пароля (Ф3), регистрация (Ф4),
// восстановление (Ф5). Правило — минимальная длина, сходство с почтой, база
// утечек — у них ОДНО. Второе объявление правила разошлось бы с первым молча,
// и человек, чей пароль принят на регистрации, получил бы отказ на смене — либо
// наоборот, и второе хуже: правило, которое строже на входе и мягче на смене,
// есть правило только на бумаге.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА — ОБЪЯВЛЕНИЕ ПРАВИЛА, УЗНАННОЕ РАЗБОРОМ, А НЕ ПОДСТРОКОЙ
//
// Объявлением правила считается КАЖДАЯ из трёх форм, и распознаватель знает их
// все, потому что дубликат приходит не копией имени, а копией существа:
//
//   - конструктор `NewPasswordRule` и тип `PasswordRule` — форма по имени;
//   - метод `Judge` с параметром, названным `password` — форма по глаголу:
//     второе правило в другом пакете завело бы свой тип со своим именем, но
//     судить пароль оно стало бы тем же словом;
//   - сравнение ДЛИНЫ В РУНАХ параметра `password` — форма по существу:
//     `len([]rune(password)) < n` и `utf8.RuneCountInString(password) < n`.
//     Байтовая длина (`len(password)`) правилом НЕ считается намеренно: она
//     судит МАТЕРИАЛ, а не пароль (у bcrypt потолок 72 байта, PWV-19), и
//     живёт у проверяющего законно.
//
// Вызывающим считается вызов метода `Judge` с тремя доводами — контекст, почта,
// пароль — вне дома правила. Перепись печатает «объявлений 1 · вызывающих M»,
// и M сегодня равно 1: регистрация и восстановление — Ф4 и Ф5, их вызовы
// появятся вместе с ними, и рост M — перепись, а не находка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он не судит, ВСЕ ЛИ полосы, меняющие материал, зовут правило: полоса, которая
// пишет материал и правила не спрашивает, тремя формами выше не узнаётся. Эту
// половину держит запрет на замещение материала мимо `Writer` (гейт локализации
// проверяющего) и приёмки самих полос.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// PasswordRuleHomeRel — дом правила: единственный файл, где объявления законны.
const PasswordRuleHomeRel = "internal/apps/kaname/api/humansession/password_rule.go"

// PasswordRuleForm — форма, в которой найдено объявление.
type PasswordRuleForm string

// #nosec G101 -- ИМЕНА ФОРМ ОБЪЯВЛЕНИЯ для текста находки гейта: слово «пароль»
// здесь — предмет проверки, а не значение удостоверения.
const (
	// PasswordRuleFormName — конструктор либо тип по имени.
	PasswordRuleFormName PasswordRuleForm = "объявление по имени"
	// PasswordRuleFormVerb — метод `Judge` над паролем.
	PasswordRuleFormVerb PasswordRuleForm = "метод Judge над паролем"
	// PasswordRuleFormLength — сравнение длины пароля в рунах.
	PasswordRuleFormLength PasswordRuleForm = "сравнение длины пароля в рунах"
)

// PasswordRuleSite — найденное объявление либо вызов.
type PasswordRuleSite struct {
	Rel  string
	Line int
	Form PasswordRuleForm
	What string
}

func (s PasswordRuleSite) String() string {
	return fmt.Sprintf("%s:%d — %s (%s)", s.Rel, s.Line, s.Form, s.What)
}

// PasswordRuleCensus — объём осмотренного и найденное.
type PasswordRuleCensus struct {
	Files        int
	Declarations []PasswordRuleSite
	Callers      []PasswordRuleSite
}

// Add — сложение переписей.
func (c *PasswordRuleCensus) Add(o PasswordRuleCensus) {
	c.Files += o.Files
	c.Declarations = append(c.Declarations, o.Declarations...)
	c.Callers = append(c.Callers, o.Callers...)
}

// Foreign — объявления вне дома правила: находки.
func (c PasswordRuleCensus) Foreign(homeRel string) []PasswordRuleSite {
	var out []PasswordRuleSite
	for _, d := range c.Declarations {
		if d.Rel != homeRel {
			out = append(out, d)
		}
	}
	return out
}

// HomeFiles — сколько разных файлов несут объявления: «одно объявление» значит
// ровно один файл, и он — дом.
func (c PasswordRuleCensus) HomeFiles() []string {
	seen := map[string]bool{}
	for _, d := range c.Declarations {
		seen[d.Rel] = true
	}
	out := make([]string, 0, len(seen))
	for rel := range seen {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// ScanPasswordRule — объявления и вызовы правила пароля в одном файле.
func ScanPasswordRule(rel string, src []byte) (PasswordRuleCensus, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return PasswordRuleCensus{}, fmt.Errorf("разбор %s: %w", rel, err)
	}
	c := PasswordRuleCensus{Files: 1}
	line := func(n ast.Node) int { return fset.Position(n.Pos()).Line }

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if ok && ts.Name.Name == "PasswordRule" {
					c.Declarations = append(c.Declarations, PasswordRuleSite{
						Rel: rel, Line: line(ts), Form: PasswordRuleFormName, What: "type " + ts.Name.Name})
				}
			}
		case *ast.FuncDecl:
			switch {
			case d.Recv == nil && d.Name.Name == "NewPasswordRule":
				c.Declarations = append(c.Declarations, PasswordRuleSite{
					Rel: rel, Line: line(d), Form: PasswordRuleFormName, What: "func " + d.Name.Name})
			case d.Recv != nil && d.Name.Name == "Judge" && hasParamNamed(d.Type, "password"):
				c.Declarations = append(c.Declarations, PasswordRuleSite{
					Rel: rel, Line: line(d), Form: PasswordRuleFormVerb, What: "method Judge"})
			}
			if d.Body != nil && hasParamNamed(d.Type, "password") {
				ast.Inspect(d.Body, func(n ast.Node) bool {
					be, ok := n.(*ast.BinaryExpr)
					if !ok || !isComparison(be.Op) {
						return true
					}
					if isRuneLengthOf(be.X, "password") || isRuneLengthOf(be.Y, "password") {
						c.Declarations = append(c.Declarations, PasswordRuleSite{
							Rel: rel, Line: line(be), Form: PasswordRuleFormLength,
							What: "в " + d.Name.Name})
					}
					return true
				})
			}
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Judge" || len(call.Args) != 3 {
			return true
		}
		c.Callers = append(c.Callers, PasswordRuleSite{
			Rel: rel, Line: line(call), Form: PasswordRuleFormVerb, What: "вызов " + exprString(sel.X) + ".Judge"})
		return true
	})
	return c, nil
}

func hasParamNamed(ft *ast.FuncType, name string) bool {
	if ft == nil || ft.Params == nil {
		return false
	}
	for _, f := range ft.Params.List {
		for _, id := range f.Names {
			if id.Name == name {
				return true
			}
		}
	}
	return false
}

func isComparison(op token.Token) bool {
	switch op {
	case token.LSS, token.LEQ, token.GTR, token.GEQ:
		return true
	}
	return false
}

// isRuneLengthOf — `len([]rune(name))` либо `utf8.RuneCountInString(name)`.
func isRuneLengthOf(e ast.Expr, name string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name != "len" {
			return false
		}
		conv, ok := call.Args[0].(*ast.CallExpr)
		if !ok || len(conv.Args) != 1 {
			return false
		}
		at, ok := conv.Fun.(*ast.ArrayType)
		if !ok {
			return false
		}
		if elem, ok := at.Elt.(*ast.Ident); !ok || elem.Name != "rune" {
			return false
		}
		return isIdent(conv.Args[0], name)
	case *ast.SelectorExpr:
		return fn.Sel.Name == "RuneCountInString" && isIdent(fn.X, "utf8") && isIdent(call.Args[0], name)
	}
	return false
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	}
	return strings.TrimSpace(fmt.Sprintf("%T", e))
}
