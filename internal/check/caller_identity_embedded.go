// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
)

type callerFieldKey struct {
	resolve callerResolveKey
	field   *types.Var
}

// embeddedCallerSources раскрывает запись конкретного встроенного поля.
// Метод интерфейса нельзя заменить всеми реализациями одинаковой подписи.
func callerNil(sp *surfaceSrcPkg, expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	_, ok = sp.info.Uses[id].(*types.Nil)
	return ok
}

type callerFieldQuery struct {
	source  callerResolveKey
	fields  []*types.Var
	refs    []valueSrc
	unknown bool

	previousSourceQuery int // Предыдущий активный кадр того же точного source, с единицы.
}

// Весь запрос поля остаётся в стеке рекурсии. Цикл исходных источников также
// отсекает фазы мутаций, контейнеров и времени жизни; иначе эти фазы могут
// снова запустить тот же граф после возврата защиты исходных источников.
func (g *callerGraph) enterCallerFieldQuery(src valueSrc, fields []*types.Var) (int, bool) {
	key := callerResolveKeyFor(src, true)
	if len(g.fieldQueries) == 0 {
		clear(g.fieldQueryHeads)
		g.fieldQueryIndexedDepth = 0
	} else if g.fieldQueryIndexedDepth != len(g.fieldQueries) {
		// Прямые изменения синтетического стека требуют старого поиска до полного снятия стека.
		g.fieldQueryIndexedDepth = -1
	}
	indexed := g.fieldQueryIndexedDepth >= 0
	first := 0
	if indexed {
		first = g.fieldQueryHeads[key] - 1
	}
	for i := first; i >= 0 && i < len(g.fieldQueries); {
		query := g.fieldQueries[i]
		g.work.FieldQueryCandidates++
		next := i + 1
		if indexed {
			next = query.previousSourceQuery - 1
		}
		if query.source == key && len(query.fields) == len(fields) {
			same := true
			for j, field := range fields {
				same = same && field.Origin() == query.fields[j].Origin()
			}
			if same {
				g.addCallerSemantic(1, 0, 0, 0)
				return i, false
			}
		}
		i = next
	}
	i := len(g.fieldQueries)
	query := callerFieldQuery{source: key, fields: fields}
	if indexed {
		if g.fieldQueryHeads == nil {
			g.fieldQueryHeads = map[callerResolveKey]int{}
		}
		query.previousSourceQuery = g.fieldQueryHeads[key]
		g.fieldQueryHeads[key] = i + 1
	}
	g.fieldQueries = append(g.fieldQueries, query)
	if indexed {
		g.fieldQueryIndexedDepth = len(g.fieldQueries)
	}
	return i, true
}

// Кадр снимает только его владелец в прежней позиции defer, включая отмену и UNKNOWN.
func (g *callerGraph) leaveCallerFieldQuery(index int) {
	if g.fieldQueryIndexedDepth != len(g.fieldQueries) {
		g.fieldQueryIndexedDepth = -1
	}
	if g.fieldQueryIndexedDepth >= 0 {
		query := g.fieldQueries[index]
		if query.previousSourceQuery == 0 {
			delete(g.fieldQueryHeads, query.source)
		} else {
			g.fieldQueryHeads[query.source] = query.previousSourceQuery
		}
	}
	g.fieldQueries = g.fieldQueries[:index]
	if len(g.fieldQueries) == 0 {
		clear(g.fieldQueryHeads)
		g.fieldQueryIndexedDepth = 0
	} else if g.fieldQueryIndexedDepth >= 0 {
		g.fieldQueryIndexedDepth = len(g.fieldQueries)
	}
}

func (g *callerGraph) embeddedCallerSources(src valueSrc, fields []*types.Var, seen map[callerFieldKey]bool) (refs []valueSrc, unknown bool) {
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	query := -1
	if len(fields) > 0 && src.pkg != nil && src.expr != nil {
		var entered bool
		query, entered = g.enterCallerFieldQuery(src, fields)
		if !entered {
			if g.semanticOverflow {
				return nil, true
			}
			// Значение, прочитанное при доказательстве времени жизни этого запроса, сохраняет
			// начальные источники и явные записи, уже найденные владельцем.
			active := g.fieldQueries[query]
			return active.refs, active.unknown
		}
		defer g.leaveCallerFieldQuery(query)
	}
	remember := func() {
		if query >= 0 && !g.semanticOverflow && (g.ctx == nil || g.ctx.Err() == nil) {
			g.fieldQueries[query].refs, g.fieldQueries[query].unknown = refs, unknown
		}
	}
	defer func() {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			refs, unknown = nil, true
			return
		}
		refs = callerDistinctSources(refs)
		remember()
		if len(fields) > 0 {
			unknown = g.callerLifetimeUnknown(src, fields...) || unknown
		}
	}()
	refs, unknown = g.embeddedCallerSourcesRaw(src, fields, seen)
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	remember()
	if len(fields) > 0 {
		more, u := g.callerContainerSources(src, fields, seen)
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		refs = append(refs, more...)
		unknown = unknown || u
	}
	remember()
	if len(fields) == 0 || src.pkg == nil || src.expr == nil || len(g.mutations[fields[0].Origin()]) == 0 {
		return refs, unknown
	}
	key := callerFieldKey{callerResolveKeyFor(src, true), fields[0].Origin()}
	if g.mutationScanning[key] {
		g.addCallerSemantic(1, 0, 0, 0)
		// Записи этого же получателя уже обходит внешний кадр. Повтор
		// не добавляет источник; непрослеженные владельцы остаются unknown.
		return refs, unknown
	}
	if g.mutationScanning == nil {
		g.mutationScanning = map[callerFieldKey]bool{}
	}
	g.mutationScanning[key] = true
	defer delete(g.mutationScanning, key)
	writes, u := g.callerMutations(src, fields[0])
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	unknown = unknown || u
	for _, write := range writes {
		values, u := g.embeddedCallerSources(write, fields[1:], seen)
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		refs = append(refs, values...)
		unknown = unknown || u
		remember()
	}
	return refs, unknown
}

func (g *callerGraph) embeddedCallerSourcesRaw(src valueSrc, fields []*types.Var, seen map[callerFieldKey]bool) (refs []valueSrc, unknown bool) {
	if len(fields) == 0 {
		return []valueSrc{src}, false
	}
	if src.pkg == nil || src.expr == nil {
		return nil, true
	}
	if src.rangeKey {
		// Поле ключа map не является полем значения контейнера.
		return nil, true
	}
	sp, expr := src.pkg, ast.Unparen(src.expr)
	if callerNil(sp, expr) {
		// Нулевой возврат конструктора не является неизвестной записью.
		return nil, false
	}
	key := callerFieldKey{callerResolveKeyFor(src, true), fields[0].Origin()}
	if seen[key] {
		g.addCallerSemantic(1, 0, 0, 0)
		return nil, g.semanticOverflow
	}
	seen[key] = true
	defer delete(seen, key)
	through := func(next valueSrc) {
		values, u := g.embeddedCallerSources(next, fields, seen)
		refs = append(refs, values...)
		unknown = unknown || u
	}
	switch x := expr.(type) {
	case *ast.UnaryExpr:
		src.expr = x.X
		through(src)
	case *ast.StarExpr:
		src.expr = x.X
		through(src)
	case *ast.TypeAssertExpr:
		src.expr = x.X
		through(src)
	case *ast.IndexExpr:
		src.expr, src.tuple = x.X, -1
		through(src)
	case *ast.SliceExpr:
		src.expr, src.tuple = x.X, -1
		through(src)
	case *ast.SelectorExpr:
		if sel := sp.info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
			src.expr = x.X
			path := append(fieldPath(sel), fields...)
			return g.embeddedCallerSources(src, path, seen)
		}
		return nil, true
	case *ast.CompositeLit:
		if values, indexed := g.embeddedLiterals.values[callerEmbeddedLiteralKey{sp, x}]; indexed && fields[0] != nil {
			g.work.EmbeddedLiteralHits++
			if value, present := values[fields[0].Origin()]; present {
				src.expr, src.tuple = value, -1
				return g.embeddedCallerSources(src, fields[1:], seen)
			}
			return nil, false // Пропущенный zero сохраняет lifetime-барьер внешнего кадра.
		}
		typ := types.Unalias(sp.info.TypeOf(x))
		if ptr, ok := typ.(*types.Pointer); ok {
			typ = types.Unalias(ptr.Elem())
		}
		st, ok := typ.Underlying().(*types.Struct)
		if !ok {
			switch typ.Underlying().(type) {
			case *types.Slice, *types.Array:
				for _, elt := range x.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						elt = kv.Value
					}
					value := src
					value.expr, value.tuple = elt, -1
					through(value)
				}
				return refs, unknown
			}
			return nil, true
		}
		for i, elt := range x.Elts {
			var field *types.Var
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				id, ok := kv.Key.(*ast.Ident)
				if !ok {
					return nil, true
				}
				field, _ = sp.info.Uses[id].(*types.Var)
				value = kv.Value
			} else if i < st.NumFields() {
				field = st.Field(i)
			}
			if field != nil && field.Origin() == fields[0].Origin() {
				src.expr, src.tuple = value, -1
				return g.embeddedCallerSources(src, fields[1:], seen)
			}
		}
		// Начальный zero допустим только вместе с общим lifetime-барьером
		// обёртки; он проверяет также явно заданные поля.
		return nil, false
	case *ast.CallExpr:
		if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok {
			if builtin, ok := sp.info.Uses[id].(*types.Builtin); ok {
				switch builtin.Name() {
				case "new", "make":
					return nil, false
				case "append":
					for _, arg := range x.Args {
						value := src
						value.expr, value.tuple = arg, -1
						through(value)
					}
					return refs, unknown
				}
			}
		}
		if tv := sp.info.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
			src.expr = x.Args[0]
			through(src)
			break
		}
		targets, u := g.resolve(valueSrc{pkg: sp, fk: src.fk, expr: x.Fun, tuple: -1}, false, map[callerResolveKey]bool{})
		unknown = u
		for _, target := range targets {
			if target.node == (callerNode{}) {
				unknown = true
				continue
			}
			g.bindCaller(sp, callerNode{fn: src.fk.fn, lit: src.fk.lit}, x, target.node)
			i := src.tuple
			if i < 0 {
				i = 0
			}
			results := g.index.returns[callerKey(target.node)]
			if i >= len(results) {
				unknown = true
				continue
			}
			for _, value := range results[i] {
				through(value)
			}
		}
	default:
		v := callerVariable(sp, expr)
		if v == nil {
			return nil, true
		}
		sources := g.sources(v)
		if len(sources) == 0 {
			// Zero — начальное состояние, сохранность проверяет обёртка.
			if _, zero := g.zeroVars[v.Origin()]; zero || g.emptyVariadic[v.Origin()] {
				return nil, false
			}
			g.observeUnboundCallback(v)
			return nil, true
		}
		for _, value := range sources {
			through(value)
		}
	}
	return refs, unknown
}
