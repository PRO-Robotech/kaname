// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_level_sole_writer.go — разбор «кто производит уровень уверенности
// и где он лежит как состояние» (приёмка Ф11, Р1, §7 инв. 4; гейт §8 «правило
// одно»).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Уровень сессии производит ОДНО правило — `assurance.LevelOf` — и как
// состояние он лежит только в записи сессии. Второй писатель (константа оси,
// употреблённая как значение; строка, преобразованная в уровень мимо правила)
// даёт уровень, которого правило не выводило, и делает его молча: оба пути
// компилируются, оба типизированы осью. Второе место хранения (поле уровня в
// строке способа входа) было бы неверно для каждого утверждения ключа без
// проверки пользователя и без срока жило бы вечно.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ТИП ОСИ, А НЕ ИМЯ ПОЛЯ
//
// Разбор ищет обращения к типу `assurance.Level` и его константам через
// импорт дома правила — под любым псевдонимом импорта — и классифицирует
// каждое ПО РОДИТЕЛЬСКОМУ УЗЛУ:
//
//	l == assurance.Level2 · l != … · case assurance.Level3:   ЧТЕНИЕ — молчит
//	assurance.LevelOf(…) · assurance.PresentableLevels(…)     ВЫЗОВ ПРАВИЛА — молчит
//	x = assurance.Level2 · T{Level: assurance.Level1} ·
//	return assurance.Level3 · f(assurance.Level2)             ПРОИЗВОДСТВО — находка
//	assurance.Level(s)                                        ПРЕОБРАЗОВАНИЕ — находка
//	type T struct { … assurance.Level … }                     ДЕРЖАТЕЛЬ — судит ведомость
//
// Поле уровня в структуре — не находка само по себе: запись сессии и четыре её
// чтения (ответ краю, ответ церемонии, запись журнала, токен) законны и названы
// поимённо ведомостью в пробе. Разбор лишь ДОКЛАДЫВАЕТ держателя с координатой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОВИНА ПО МИГРАЦИЯМ
//
// Объявление оси уровня в схеме — перечень значений ровно «1», «2», «3»
// (`IN (…)` либо `= ANY (ARRAY[…])`) — читается вместе с именем столбца и
// таблицей, при которой он объявлен. Нужна потому, что колонку с умолчанием
// пишет база, и писателя в коде у неё нет: половина по коду её не видит.
// Законных мест два вида: таблица сессии (дом состояния) и названная ведомостью
// СНИМКОВ таблица, где уровень лежит неподвижной копией события
// (JudgeAssuranceAxisColumns).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Разбор по узлам, без вывода типов: уровень, пронесённый через переменную
// типа оси (`l := assurance.Level2; rec.level = l`), находится на первом шаге
// (константа как значение), а не на втором. Уровень, собранный строкой без
// типа оси, невидим — это довод держать значение типом. Голый текстовый
// столбец без объявления оси половина по миграциям не видит.
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

// LevelUseKind — род обращения к оси уровня.
type LevelUseKind string

const (
	// LevelUseComparison — сравнение с константой оси либо перечень case: чтение.
	LevelUseComparison LevelUseKind = "сравнение"
	// LevelUseRuleCall — вызов правила: единственное законное производство.
	LevelUseRuleCall LevelUseKind = "вызов правила"
	// LevelUseProduction — константа оси, употреблённая как значение: второй писатель.
	LevelUseProduction LevelUseKind = "производство мимо правила"
	// LevelUseConversion — преобразование в тип оси мимо правила.
	LevelUseConversion LevelUseKind = "преобразование в уровень"
	// LevelUseStructField — поле типа оси в объявлении структуры: держатель состояния.
	LevelUseStructField LevelUseKind = "поле уровня в структуре"
)

// LevelUse — одно обращение к оси уровня с координатой.
type LevelUse struct {
	File string
	Line int
	Kind LevelUseKind
	// Holder — имя структуры (для LevelUseStructField).
	Holder string
	// Text — что именно стояло в узле (для читателя находки).
	Text string
}

func (u LevelUse) String() string {
	if u.Holder != "" {
		return fmt.Sprintf("%s:%d %s: %s (%s)", u.File, u.Line, u.Kind, u.Holder, u.Text)
	}
	return fmt.Sprintf("%s:%d %s: %s", u.File, u.Line, u.Kind, u.Text)
}

// LevelUseCensus — объём осмотренного.
type LevelUseCensus struct {
	Files          int
	ImportingHome  int
	AxisReferences int
	Comparisons    int
	RuleCalls      int
	Productions    int
	Conversions    int
	StructFields   int
}

// Add — сложение переписей по файлам.
func (c *LevelUseCensus) Add(o LevelUseCensus) {
	c.Files += o.Files
	c.ImportingHome += o.ImportingHome
	c.AxisReferences += o.AxisReferences
	c.Comparisons += o.Comparisons
	c.RuleCalls += o.RuleCalls
	c.Productions += o.Productions
	c.Conversions += o.Conversions
	c.StructFields += o.StructFields
}

// axisConstants — константы оси, объявленные домом правила.
var axisConstants = map[string]bool{"Level1": true, "Level2": true, "Level3": true}

// ruleProducers — функции дома, которым производить уровень положено.
var ruleProducers = map[string]bool{"LevelOf": true, "PresentableLevels": true}

// ScanAssuranceLevelUses разбирает один Go-файл и классифицирует обращения к
// оси уровня по родительскому узлу. homeImport — путь пакета дома правила.
func ScanAssuranceLevelUses(path string, src []byte, homeImport string) ([]LevelUse, LevelUseCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, LevelUseCensus{}, err
	}
	census := LevelUseCensus{Files: 1}

	alias := ""
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != homeImport {
			continue
		}
		alias = "assurance"
		if imp.Name != nil {
			alias = imp.Name.Name
		}
	}
	if alias == "" || alias == "_" || alias == "." {
		// Точечный импорт дома не распознаётся by construction: у него нет
		// селектора. В этом дереве его нет; появится — разбор увидит ноль
		// обращений, и перепись «импортирующих дом 0» это покажет.
		return nil, census, nil
	}
	census.ImportingHome = 1

	isHome := func(e ast.Expr) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != alias {
			return "", false
		}
		return sel.Sel.Name, true
	}

	var uses []LevelUse
	at := func(n ast.Node, kind LevelUseKind, holder, text string) {
		uses = append(uses, LevelUse{
			File: path, Line: fset.Position(n.Pos()).Line, Kind: kind, Holder: holder, Text: text,
		})
	}

	// Держатели: структуры с полем типа оси — по одному докладу на тип.
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			for _, fld := range st.Fields.List {
				ft := fld.Type
				if star, ok := ft.(*ast.StarExpr); ok {
					ft = star.X
				}
				if name, ok := isHome(ft); ok && name == "Level" {
					census.StructFields++
					census.AxisReferences++
					at(fld, LevelUseStructField, ts.Name.Name, alias+".Level")
					break
				}
			}
		}
	}

	// Обращения к константам и преобразования — с родителем.
	w := &parentWalker{}
	w.visit = func(n ast.Node, parents []ast.Node) {
		if call, ok := n.(*ast.CallExpr); ok {
			if name, ok := isHome(call.Fun); ok {
				switch {
				case name == "Level":
					census.AxisReferences++
					census.Conversions++
					at(call, LevelUseConversion, "", alias+".Level(…)")
				case ruleProducers[name]:
					census.AxisReferences++
					census.RuleCalls++
					at(call, LevelUseRuleCall, "", alias+"."+name+"(…)")
				}
			}
			return
		}
		expr, ok := n.(ast.Expr)
		if !ok {
			return
		}
		name, ok := isHome(expr)
		if !ok || !axisConstants[name] {
			return
		}
		census.AxisReferences++
		text := alias + "." + name
		if isReadContext(n, parents) {
			census.Comparisons++
			at(n, LevelUseComparison, "", text)
			return
		}
		census.Productions++
		at(n, LevelUseProduction, "", text)
	}
	ast.Walk(w, f)
	return uses, census, nil
}

// isReadContext — стоит ли узел операндом сравнения либо в перечне ветви case.
func isReadContext(n ast.Node, parents []ast.Node) bool {
	if len(parents) == 0 {
		return false
	}
	switch p := parents[len(parents)-1].(type) {
	case *ast.BinaryExpr:
		return p.Op == token.EQL || p.Op == token.NEQ
	case *ast.CaseClause:
		for _, e := range p.List {
			if e == n {
				return true
			}
		}
	}
	return false
}

// parentWalker — обход с дорожкой родителей: род обращения решает родитель, а
// ast.Inspect его не даёт.
type parentWalker struct {
	stack []ast.Node
	visit func(n ast.Node, parents []ast.Node)
}

func (w *parentWalker) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		w.stack = w.stack[:len(w.stack)-1]
		return nil
	}
	w.visit(n, w.stack)
	w.stack = append(w.stack, n)
	return w
}

// AxisColumnSite — столбец схемы, чей перечень значений — ровно ось уровня.
type AxisColumnSite struct {
	File   string
	Line   int
	Table  string
	Column string
}

func (s AxisColumnSite) String() string {
	return fmt.Sprintf("%s:%d %s.%s IN ('1','2','3')", s.File, s.Line, s.Table, s.Column)
}

// JudgeAssuranceAxisColumns судит объявления оси уровня в схеме.
//
// Объявление при таблице сессии (home) — дом состояния уровня. Объявление при
// таблице ведомости копий (copies: таблица → основание) — СНИМОК уровня,
// сделанный чтением записи сессии и дальше неподвижный: у гранта церемонии это
// уровень на выдаче кода, который обмен и оборот не пересчитывают (приёмка
// LINE-A-1 Р5/Р6, `oauthceremony.SessionRecord`). Объявление при любой иной
// таблице — находка: второе место хранения. Ведомость самоистекает: таблица
// копий без объявления оси в схеме — находка, как и дом без объявления.
func JudgeAssuranceAxisColumns(columns []AxisColumnSite, home string, copies map[string]string) []string {
	var findings []string
	homeSeen := false
	copySeen := map[string]bool{}
	for _, c := range columns {
		switch _, isCopy := copies[c.Table]; {
		case home != "" && c.Table == home:
			homeSeen = true
		case isCopy:
			copySeen[c.Table] = true
		default:
			findings = append(findings, fmt.Sprintf("%s — объявление оси уровня вне таблицы сессии (%q) и вне ведомости "+
				"копий: уровень как состояние лежит только в записи сессии, снимок — только в названной копии", c, home))
		}
	}
	if home != "" && !homeSeen {
		findings = append(findings, fmt.Sprintf("ведомость называет таблицу оси %q, а объявления оси при ней в схеме нет", home))
	}
	tables := make([]string, 0, len(copies))
	for table := range copies {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	for _, table := range tables {
		if !copySeen[table] {
			findings = append(findings, fmt.Sprintf("ведомость копий называет таблицу %q (%s), а объявления оси при ней "+
				"в схеме нет: записи больше нечего исключать", table, copies[table]))
		}
	}
	return findings
}

// ScanAssuranceAxisColumns — объявления оси уровня в накате миграции.
//
// Осью считается перечень значений ровно {'1','2','3'}; перечень уже или шире —
// не ось. Таблица — ближайшее слева `CREATE TABLE` либо `ALTER TABLE`.
func ScanAssuranceAxisColumns(path, upSection string) []AxisColumnSite {
	lower := strings.ToLower(upSection)
	var out []AxisColumnSite
	for idx := 0; idx < len(lower); {
		open, next, ok := nextValueListOpen(lower, idx)
		if !ok {
			break
		}
		idx = next
		values, end := sqlQuotedListAt(upSection, open)
		if end < 0 || !isAxisValueSet(values) {
			continue
		}
		out = append(out, AxisColumnSite{
			File:   path,
			Line:   1 + strings.Count(upSection[:open], "\n"),
			Table:  sqlTableBefore(upSection, open),
			Column: sqlColumnBeforeList(lower, open),
		})
		idx = end
	}
	return out
}

func isAxisValueSet(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if v != "1" && v != "2" && v != "3" {
			return false
		}
		seen[v] = true
	}
	return len(seen) == 3
}

// sqlTableBefore — ближайшее слева объявление таблицы.
func sqlTableBefore(s string, at int) string {
	lower := strings.ToLower(s[:at])
	i := strings.LastIndex(lower, "create table")
	j := strings.LastIndex(lower, "alter table")
	if j > i {
		i = j + len("alter table")
	} else if i >= 0 {
		i += len("create table")
	} else {
		return ""
	}
	k := sqlSkipSpace(lower, i)
	if strings.HasPrefix(lower[k:], "if not exists") {
		k = sqlSkipSpace(lower, k+len("if not exists"))
	}
	return sqlIdentifierAtPos(s, k)
}

// sqlColumnBeforeList — идентификатор столбца перед `in (` либо `= any (`.
func sqlColumnBeforeList(lower string, open int) string {
	i := open - 1
	for i >= 0 && (lower[i] == ' ' || lower[i] == '\t' || lower[i] == '\n' || lower[i] == '\r') {
		i--
	}
	// Снимаем ключевое слово `in` либо `any` и, если есть, знак `=`.
	if i >= 1 && lower[i-1:i+1] == "in" {
		i -= 2
	} else if i >= 2 && lower[i-2:i+1] == "any" {
		i -= 3
		for i >= 0 && (lower[i] == ' ' || lower[i] == '\t' || lower[i] == '\n') {
			i--
		}
		if i >= 0 && lower[i] == '=' {
			i--
		}
	}
	for i >= 0 && (lower[i] == ' ' || lower[i] == '\t' || lower[i] == '\n' || lower[i] == '\r') {
		i--
	}
	end := i + 1
	for i >= 0 && (lower[i] == '_' || lower[i] == '.' || (lower[i] >= 'a' && lower[i] <= 'z') || (lower[i] >= '0' && lower[i] <= '9')) {
		i--
	}
	return lower[i+1 : end]
}
