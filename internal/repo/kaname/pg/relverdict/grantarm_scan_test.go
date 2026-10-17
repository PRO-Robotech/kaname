// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// grantarm_scan_test.go — распознаватель гейта единственного дома предиката
// ветви выдач (grantarm_home_gate_test.go). Что он читает и где его граница —
// в шапке гейта; здесь — как.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// exprMark — подстановка на место выражения, значение которого не выводится
// статически (параметр функции, вызов, константа другого пакета). Для лексера
// это отдельная лексема, а не идентификатор: она не склеивается с соседями.
const exprMark = "\x00"

// selectorColumns — столбцы селектора правила роли: сравнение любого из них и
// есть решение «достаёт ли выдача до объекта».
var selectorColumns = map[string]bool{"arm": true, "resource_names": true, "match_labels": true}

// silencedCalls — вызовы, чьи строки уходят в текст ошибки или в журнал, а не
// в запрос. Их аргументы не читаются.
var silencedCalls = map[string]bool{
	"fmt.Errorf": true, "errors.New": true,
	"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true,
	"fmt.Fprint": true, "fmt.Fprintf": true, "fmt.Fprintln": true,
}

// silencedPkgs — пакеты журнала: любые их вызовы молчат.
var silencedPkgs = map[string]bool{"log": true, "slog": true}

type grantArmHome struct {
	pos  string // файл:строка объявления
	decl string // имя объявления
}

type grantArmCensus struct {
	files    int // прочитано непробных .go
	literals int // прочитано строковых литералов
	texts    int // выведено текстов (склеек выражений)
}

// grantArmUnit — единица счёта: функция либо одно имя в объявлении
// константы/переменной.
type grantArmUnit struct {
	pos, name string
	body      ast.Node // тело функции либо значение имени; nil — значения нет
	value     ast.Expr // значение имени (для подстановки); у функции nil
	isValue   bool
	hit       bool
}

func callName(c *ast.CallExpr) (pkg, full string) {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", ""
	}
	return id.Name, id.Name + "." + sel.Sel.Name
}

// scanGrantArmHomes обходит непробные .go каталога и называет единицы, в чьих
// выведенных текстах столбец селектора стоит в решающей позиции.
func scanGrantArmHomes(dir string) (grantArmCensus, []grantArmHome, error) {
	var c grantArmCensus
	entries, err := os.ReadDir(dir)
	if err != nil {
		return c, nil, err
	}
	fset := token.NewFileSet()
	var units []*grantArmUnit
	values := map[string]*grantArmUnit{} // имя константы/переменной пакета → единица
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return c, nil, fmt.Errorf("разбор %s: %w", name, err)
		}
		c.files++
		ast.Inspect(f, func(n ast.Node) bool {
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				c.literals++
			}
			return true
		})
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				units = append(units, &grantArmUnit{
					pos:  fmt.Sprintf("%s:%d", name, fset.Position(d.Pos()).Line),
					name: d.Name.Name, body: d.Body,
				})
			case *ast.GenDecl:
				for _, s := range d.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, id := range vs.Names {
						u := &grantArmUnit{
							pos:  fmt.Sprintf("%s:%d", name, fset.Position(id.Pos()).Line),
							name: id.Name, isValue: true,
						}
						if i < len(vs.Values) {
							u.body, u.value = vs.Values[i], vs.Values[i]
						}
						units = append(units, u)
						values[id.Name] = u
					}
				}
			}
		}
	}

	referenced := map[string]bool{}
	for _, u := range units {
		ev := &grantArmEval{values: values, self: u.name, refs: referenced}
		if u.body == nil {
			continue
		}
		for _, text := range ev.texts(u.body) {
			c.texts++
			if decidingUse(text) {
				u.hit = true
			}
		}
	}

	var homes []grantArmHome
	for _, u := range units {
		// Константа либо переменная, которую подставляет другая единица, —
		// ОСКОЛОК: её текст уже засчитан у той, что её употребляет.
		if !u.hit || (u.isValue && referenced[u.name]) {
			continue
		}
		homes = append(homes, grantArmHome{pos: u.pos, decl: u.name})
	}
	sort.Slice(homes, func(i, j int) bool { return homes[i].pos < homes[j].pos })
	return c, homes, nil
}

// grantArmEval выводит тексты строковых выражений единицы.
type grantArmEval struct {
	values map[string]*grantArmUnit
	self   string
	refs   map[string]bool
	depth  int
}

// texts — тексты всех МАКСИМАЛЬНЫХ строковых выражений под x: литерал, склейка
// оператором «+», fmt.Sprintf, имя строковой константы пакета. Аргументы
// вызовов из silencedCalls не читаются.
func (ev *grantArmEval) texts(x ast.Node) []string {
	var out []string
	ast.Inspect(x, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			pkg, full := callName(n)
			if silencedCalls[full] || silencedPkgs[pkg] {
				return false
			}
			if full == "fmt.Sprintf" {
				out = append(out, ev.eval(n))
				return false
			}
		case *ast.BasicLit:
			if n.Kind == token.STRING {
				out = append(out, ev.eval(n))
			}
			return false
		case *ast.BinaryExpr:
			if n.Op == token.ADD {
				out = append(out, ev.eval(n))
				return false
			}
		case *ast.Ident:
			if _, ok := ev.values[n.Name]; ok && n.Name != ev.self {
				out = append(out, ev.eval(n))
			}
		}
		return true
	})
	return out
}

// eval — значение строкового выражения; невыводимое — exprMark.
func (ev *grantArmEval) eval(x ast.Expr) string {
	if ev.depth > 16 {
		return exprMark
	}
	ev.depth++
	defer func() { ev.depth-- }()
	switch x := x.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return x.Value
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return exprMark
		}
		return s
	case *ast.ParenExpr:
		return ev.eval(x.X)
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return ev.eval(x.X) + ev.eval(x.Y)
		}
	case *ast.Ident:
		if u, ok := ev.values[x.Name]; ok && x.Name != ev.self && u.value != nil {
			ev.refs[x.Name] = true
			return ev.eval(u.value)
		}
	case *ast.CallExpr:
		if _, full := callName(x); full == "fmt.Sprintf" && len(x.Args) > 0 {
			args := make([]string, 0, len(x.Args)-1)
			for _, a := range x.Args[1:] {
				args = append(args, ev.eval(a))
			}
			return sprintfLike(ev.eval(x.Args[0]), args)
		}
	}
	return exprMark
}

// sprintfLike подставляет %s %v %q %d по порядку; индексированные и прочие
// глаголы — exprMark.
func sprintfLike(format string, args []string) string {
	var b strings.Builder
	next := 0
	for i := 0; i < len(format); i++ {
		ch := format[i]
		if ch != '%' {
			b.WriteByte(ch)
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("+-# 0123456789.*[]", format[j]) >= 0 {
			j++
		}
		if j >= len(format) {
			b.WriteString(exprMark)
			break
		}
		verb, indexed := format[j], strings.Contains(format[i:j], "[")
		i = j
		switch {
		case verb == '%':
			b.WriteByte('%')
		case !indexed && strings.IndexByte("svqd", verb) >= 0 && next < len(args):
			a := args[next]
			if verb == 'q' {
				a = strconv.Quote(a)
			}
			b.WriteString(a)
			next++
		default:
			b.WriteString(exprMark)
			next++
		}
	}
	return b.String()
}

// sqlTok — лексема SQL-текста.
type sqlTok struct {
	kind byte // 'i' идентификатор, 'o' оператор/пунктуация, 's' строка, 'n' прочее
	text string
}

// lexSQL — лексемы текста без комментариев («--» до конца строки и «/* */» с
// вложенностью); строки в одинарных кавычках, имена в двойных и тела в
// долларовых кавычках комментариев внутри себя не содержат.
func lexSQL(s string) []sqlTok {
	var out []sqlTok
	isIdent := func(c byte) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			depth := 0
			for i < len(s) {
				if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
					depth++
					i += 2
				} else if i+1 < len(s) && s[i] == '*' && s[i+1] == '/' {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '\'':
			j := i + 1
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			out = append(out, sqlTok{'s', s[i:min(j+1, len(s))]})
			i = j + 1
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				j = len(s) - i - 1
			}
			out = append(out, sqlTok{'i', strings.ToLower(s[i+1 : i+1+j])})
			i += j + 2
		case c == '$' && i+1 < len(s) && !(s[i+1] >= '0' && s[i+1] <= '9'):
			k := strings.IndexByte(s[i+1:], '$')
			if k < 0 {
				out = append(out, sqlTok{'o', "$"})
				i++
				continue
			}
			tag := s[i : i+k+2]
			end := strings.Index(s[i+len(tag):], tag)
			if end < 0 {
				i = len(s)
				continue
			}
			out = append(out, sqlTok{'s', tag})
			i += len(tag) + end + len(tag)
		case c == 0:
			out = append(out, sqlTok{'n', exprMark})
			i++
		case isIdent(c):
			j := i
			for j < len(s) && isIdent(s[j]) {
				j++
			}
			out = append(out, sqlTok{'i', strings.ToLower(s[i:j])})
			i = j
		case c == ':' && i+1 < len(s) && s[i+1] == ':':
			out = append(out, sqlTok{'o', "::"})
			i += 2
		case strings.IndexByte("=<>!~+-*/%^&|@#?", c) >= 0:
			j := i
			for j < len(s) && strings.IndexByte("=<>!~+-*/%^&|@#?", s[j]) >= 0 {
				j++
			}
			out = append(out, sqlTok{'o', s[i:j]})
			i = j
		default:
			out = append(out, sqlTok{'o', string(c)})
			i++
		}
	}
	return out
}

// sqlLeadKeywords — слова SQL, после которых может стоять ссылка на столбец.
// Идентификатор ВНЕ этого перечня перед словом `arm` делает его не ссылкой:
// это псевдоним без AS либо проза («unknown arm =»).
var sqlLeadKeywords = map[string]bool{
	"select": true, "where": true, "and": true, "or": true, "not": true, "on": true,
	"when": true, "case": true, "then": true, "else": true, "by": true, "in": true,
	"is": true, "between": true, "like": true, "ilike": true, "similar": true,
	"set": true, "distinct": true, "returning": true, "using": true, "having": true,
	"any": true, "all": true, "some": true, "array": true, "values": true,
	"exists": true, "lateral": true, "row": true, "filter": true,
}

// decidingUse — стоит ли в тексте столбец селектора в РЕШАЮЩЕЙ позиции.
//
// Не решает ровно три положения: определение псевдонима (после AS), проза либо
// псевдоним без AS (перед ним идентификатор вне sqlLeadKeywords) и НАБЛЮДЕНИЕ —
// столбец стоит в перечне вывода: слева SELECT, DISTINCT, «,» или «||», справа
// (за приведением типа) AS, FROM, «,», «||» либо конец текста. Всё прочее —
// сравнение, выбор CASE, перечень значений, диапазон — решение.
func decidingUse(text string) bool {
	toks := lexSQL(text)
	at := func(i int) sqlTok {
		if i < 0 || i >= len(toks) {
			return sqlTok{}
		}
		return toks[i]
	}
	for i, t := range toks {
		if t.kind != 'i' || !selectorColumns[t.text] {
			continue
		}
		p := i - 1
		if at(p).kind == 'o' && at(p).text == "." && at(p-1).kind == 'i' {
			p -= 2 // квалификатор таблицы: смотрим на то, что перед ним
		}
		prev := at(p)
		if prev.kind == 'i' && prev.text == "as" {
			continue
		}
		if (prev.kind == 'i' && !sqlLeadKeywords[prev.text]) || prev.kind == 's' {
			continue
		}
		n := i + 1
		for at(n).kind == 'o' && at(n).text == "::" {
			n += 2 // приведение типа: «::имя»
		}
		next := at(n)
		lawfulPrev := (prev.kind == 'i' && (prev.text == "select" || prev.text == "distinct")) ||
			(prev.kind == 'o' && (prev.text == "," || prev.text == "||"))
		lawfulNext := next.kind == 0 ||
			(next.kind == 'i' && (next.text == "as" || next.text == "from")) ||
			(next.kind == 'o' && (next.text == "," || next.text == "||"))
		if lawfulPrev && lawfulNext {
			continue
		}
		return true
	}
	return false
}
