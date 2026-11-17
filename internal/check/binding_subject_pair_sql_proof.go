// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// Константные склейки раскрываются с происхождением каждого байта. Литерал
// можно признать чужой таблицей только во ВСЕХ конечных употреблениях его
// константы. Неизвестное употребление, экспорт и неподдержанная форма не дают
// освобождения. Имя файла/константы не участвует в разрешении таблицы.
type bindingPairSQLOrigins map[token.Pos]map[int]string

type bindingPairSQLPiece struct {
	pos  token.Pos
	text string
}

func bindingPairSQLConstantOrigins(files []*ast.File, info *types.Info) bindingPairSQLOrigins {
	out := bindingPairSQLOrigins{}
	definitions := map[*types.Const]ast.Expr{}
	definitionRoots := map[ast.Expr]*types.Const{}
	parents := map[ast.Node]ast.Node{}
	consumers := map[types.Object]bool{}
	used := map[*types.Const]bool{}
	for _, obj := range info.Uses {
		if c, ok := obj.(*types.Const); ok {
			used[c] = true
		}
	}
	for _, f := range files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil && len(fn.Body.List) == 2 &&
				bindingPairGoShape(fn.Body.List[0], "after := \"\"") && bindingPairGoShape(fn.Body, bindingPairCompleteScanBody) && bindingPairHasTypedQuery(fn.Body, info) {
				consumers[info.Defs[fn.Name]] = true
			}
			if v, ok := n.(*ast.ValueSpec); ok && len(v.Names) == len(v.Values) {
				for i, name := range v.Names {
					if c, ok := info.Defs[name].(*types.Const); ok {
						definitions[c] = v.Values[i]
						definitionRoots[v.Values[i]] = c
					}
				}
			}
			return true
		})
	}
	stringValue := func(e ast.Expr) (string, bool) {
		tv := info.Types[e]
		if tv.Value == nil || tv.Value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(tv.Value), true
	}
	merge := func(pos token.Pos, at int, table string) {
		if out[pos] == nil {
			out[pos] = map[int]string{}
		}
		old, seen := out[pos][at]
		switch {
		case !seen:
			out[pos][at] = table
		case old == sqlUnresolved || table == sqlUnresolved:
			out[pos][at] = sqlUnresolved
		case old == BindingPairTable || table == BindingPairTable:
			out[pos][at] = BindingPairTable
		case old != table:
			out[pos][at] = "<чужие таблицы>"
		}
	}
	var expand func(ast.Expr, int) ([]bindingPairSQLPiece, bool)
	expand = func(e ast.Expr, depth int) ([]bindingPairSQLPiece, bool) {
		if depth > 64 {
			return nil, false
		}
		value, ok := stringValue(e)
		if !ok {
			return nil, false
		}
		switch x := e.(type) {
		case *ast.BasicLit:
			return []bindingPairSQLPiece{{pos: x.Pos(), text: value}}, true
		case *ast.ParenExpr:
			return expand(x.X, depth+1)
		case *ast.BinaryExpr:
			if x.Op != token.ADD {
				return nil, false
			}
			a, aok := expand(x.X, depth+1)
			b, bok := expand(x.Y, depth+1)
			return append(a, b...), aok && bok
		case *ast.Ident:
			if c, ok := info.Uses[x].(*types.Const); ok {
				if def := definitions[c]; def != nil {
					return expand(def, depth+1)
				}
			}
		case *ast.SelectorExpr:
			// Чужая константа даёт текст, но не освобождает ни один свой литерал.
			return []bindingPairSQLPiece{{text: value}}, true
		}
		return nil, false
	}
	var unknown func(ast.Expr, map[ast.Expr]bool)
	unknown = func(e ast.Expr, seen map[ast.Expr]bool) {
		if seen[e] {
			return
		}
		seen[e] = true
		ast.Inspect(e, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if value, ok := stringValue(x); ok {
					for _, ref := range bindingPairColRefs(asciiLower(value)) {
						merge(x.Pos(), ref.at, sqlUnresolved)
					}
				}
			case *ast.Ident:
				if c, ok := info.Uses[x].(*types.Const); ok && definitions[c] != nil {
					unknown(definitions[c], seen)
				}
			}
			return true
		})
	}
	for n, parent := range parents {
		e, ok := n.(ast.Expr)
		if !ok {
			continue
		}
		if _, ok := stringValue(e); !ok {
			continue
		}
		if p, ok := parent.(ast.Expr); ok {
			if _, constantParent := stringValue(p); constantParent {
				continue
			}
		}
		if c := definitionRoots[e]; c != nil && used[c] && !c.Exported() {
			continue
		}
		pieces, ok := expand(e, 0)
		if !ok {
			unknown(e, map[ast.Expr]bool{})
			continue
		}
		var text strings.Builder
		for _, piece := range pieces {
			text.WriteString(piece.text)
		}
		terminal := bindingPairReceiptTerminal(e, parent, parents, consumers, info)
		receipt := terminal && bindingPairReceiptAliasOnly(text.String())
		complete := terminal && bindingPairCompleteSQL(text.String())
		for _, piece := range pieces {
			if piece.pos.IsValid() {
				for _, ref := range bindingPairColRefs(asciiLower(piece.text)) {
					table := sqlUnresolved
					if receipt && ref.qualifier == "r" {
						table = "producer_source_receipt"
					}
					if complete {
						table = "<complete-set>"
					}
					merge(piece.pos, ref.at, table)
				}
			}
		}
	}
	return out
}

// Позиция прежнего literal census переводится обратно до удаления --comments.
// Сам SQL proof использует sqlTokens исходного текста, включая quoted names.
func bindingPairSQLRawOffset(raw string, offset int) int {
	base := 0
	for _, line := range strings.Split(raw, "\n") {
		prefix := line
		if i := strings.Index(prefix, "--"); i >= 0 {
			prefix = prefix[:i]
		}
		if offset < len(prefix) {
			return base + offset
		}
		offset -= len(prefix) + 1
		base += len(line) + 1
	}
	return -1
}

// Узкое доказательство receipt-key: только семь полей реальной таблицы,
// причём оба чтения пары принадлежат одному qualified JSON key. Никакие
// произвольные SQL-фрагменты или другие одинаково названные колонки сюда не входят.
func bindingPairReceiptFragment(raw string) bool {
	refs := bindingPairColRefs(asciiLower(stripSQLComments(raw)))
	if len(refs) != 2 || refs[0].qualifier != "r" || refs[1].qualifier != "r" {
		return false
	}
	want := sqlTokens("jsonb_build_array(r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)")
	tokens := sqlTokens(raw)
	for i := 0; i+len(want) <= len(tokens); i++ {
		if bindingPairSQLTokensEqual(tokens[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

func bindingPairSQLTokensEqual(a, b []sqlTok) bool {
	if len(a) != len(b) {
		return false
	}
	for i, t := range a {
		u := b[i]
		if t.kind != u.kind || t.name != u.name || t.form != u.form || t.op != u.op || len(t.readings) != len(u.readings) {
			return false
		}
		for j := range t.readings {
			if t.readings[j] != u.readings[j] {
				return false
			}
		}
	}
	return true
}

// Это не общий SQL resolver. Допущены только qualified physical receipt r
// и одна прямая CTE-проекция page AS (SELECT r.* FROM ...receipt r ...).
// Каждое вхождение имени r обязано быть qualified чтением, целой строкой
// в to_jsonb(r) либо одним из этих двух FROM bindings. Переопределение r через
// JOIN/CTE/function/derived table, иной source page, quoted alias и mixed
// AccessBinding query остаются отказом.
func bindingPairReceiptAliasOnly(raw string) bool {
	tokens := sqlTokens(raw)
	bare := func(i int, name string) bool {
		return i >= 0 && i < len(tokens) && tokens[i].kind == sqlTokName && tokens[i].form == SQLFormBare && tokens[i].name == name
	}
	dot := func(i int) bool { return i >= 0 && i < len(tokens) && tokens[i].op == '.' }
	allowed := map[int]bool{}
	pageStart := -1
	pageSource := -1
	physical := false
	for i := range tokens {
		if bare(i, BindingPairTable) || bare(i, "recursive") || bare(i, "materialized") || tokens[i].op == ';' {
			return false
		}
		if bare(i, "r") && bare(i-1, "producer_source_receipt") && dot(i-2) && bare(i-3, "kaname") && bare(i-4, "from") {
			allowed[i] = true
			physical = true
		}
		if bare(i, "page") && bare(i+1, "as") && i+11 < len(tokens) && tokens[i+2].op == '(' &&
			bare(i+3, "select") && bare(i+4, "r") && dot(i+5) && tokens[i+6].op == '*' && bare(i+7, "from") &&
			bare(i+8, "kaname") && dot(i+9) && bare(i+10, "producer_source_receipt") && bare(i+11, "r") {
			if pageStart != -1 {
				return false
			}
			pageStart, pageSource = i, i+11
		}
	}
	for i, t := range tokens {
		if t.kind != sqlTokName {
			continue
		}
		if t.name == "page" {
			// Единственное объявление page выше и только FROM page r. Иной CTE
			// с тем же именем либо column-list меняет этот закрытый proof.
			if t.form != SQLFormBare || pageStart < 0 || (i != pageStart && (!bare(i-1, "from") || !bare(i+1, "r") || i <= pageSource)) {
				return false
			}
			if i != pageStart {
				allowed[i+1] = true
			}
		}
	}
	for i, t := range tokens {
		// Снимок состояния включает to_jsonb(r). Это чтение той же строки,
		// а не новое объявление alias; иная функция/qualified имя не разрешены.
		wholeRowJSON := i >= 2 && i+1 < len(tokens) && bare(i-2, "to_jsonb") && !dot(i-3) &&
			tokens[i-1].op == '(' && tokens[i+1].op == ')'
		if t.kind == sqlTokName && t.name == "r" && (t.form != SQLFormBare || (!allowed[i] && !dot(i+1) && !wholeRowJSON)) {
			return false
		}
	}
	return physical
}

// Константа не доказывает динамически достроенную строку. Конечный потребитель
// здесь — typed pgx Query; допускается локальная переменная, все чтения которой
// идут в этот SQL argument, а присваивания имеют целиком constant RHS.
func bindingPairReceiptTerminal(e ast.Expr, parent ast.Node, parents map[ast.Node]ast.Node, consumers map[types.Object]bool, info *types.Info) bool {
	queryArg := func(id ast.Expr, node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return false
		}
		// Ровно один closed local consumer: весь AST body complete paging,
		// typed pgx Query, SQL parameter без модификации. Имя не разрешает вызов.
		if len(call.Args) >= 3 && call.Args[2] == id {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && info.Selections[selector] != nil {
				if consumers[info.Selections[selector].Obj()] {
					return true
				}
			}
		}
		if call.Args[1] != id {
			return false
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selection := info.Selections[selector]
		if selection == nil {
			return false
		}
		fn, ok := selection.Obj().(*types.Func)
		return ok && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/jackc/pgx/v5" && fn.Name() == "Query"
	}
	if queryArg(e, parent) {
		return true
	}
	assignment, ok := parent.(*ast.AssignStmt)
	if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 || assignment.Rhs[0] != e ||
		(assignment.Tok != token.DEFINE && assignment.Tok != token.ASSIGN) {
		return false
	}
	name, ok := assignment.Lhs[0].(*ast.Ident)
	if !ok {
		return false
	}
	object := info.ObjectOf(name)
	if _, ok := object.(*types.Var); !ok {
		return false
	}
	reads := 0
	for id, obj := range info.Uses {
		if obj != object {
			continue
		}
		p := parents[id]
		if queryArg(id, p) {
			reads++
			continue
		}
		set, ok := p.(*ast.AssignStmt)
		if !ok || set.Tok != token.ASSIGN || len(set.Lhs) != 1 || set.Lhs[0] != id || len(set.Rhs) != 1 {
			return false
		}
		value := info.Types[set.Rhs[0]].Value
		if value == nil || value.Kind() != constant.String {
			return false
		}
	}
	return reads > 0
}
