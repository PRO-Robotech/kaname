// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"time"
)

// callerOrigin описывает значение из настоящей записи/возврата. Совпадение
// подписи само по себе происхождением значения не является.
type callerOrigin struct {
	typ               types.Type
	source            valueSrc
	node              callerNode
	foreign, nilValue bool
}

// У короткого объединения сам упорядоченный результат служит индексом.
// После четырёх различных значений первая новая запись строит точную карту.
const callerOriginLinearLimit = 4

type callerOriginUnion struct {
	values []callerOrigin
	seen   map[callerOrigin]bool
}

func (u *callerOriginUnion) add(value callerOrigin) {
	if u.seen == nil {
		for i := range u.values {
			if u.values[i] == value {
				return
			}
		}
		if len(u.values) == callerOriginLinearLimit {
			u.seen = make(map[callerOrigin]bool)
			for i := range u.values {
				u.seen[u.values[i]] = true
			}
		}
	} else if u.seen[value] {
		return
	}
	if u.seen != nil {
		u.seen[value] = true
	}
	u.values = append(u.values, value)
}

func (u *callerOriginUnion) addAll(values []callerOrigin) {
	if u.values == nil && len(values) > 1 {
		// Первый ответ заимствован. Для короткого результата достаточно одного выделения.
		u.values = make([]callerOrigin, 0, min(len(values), callerOriginLinearLimit))
	}
	for i := range values {
		u.add(values[i])
	}
}

type callerResolveKey struct {
	source   valueSrc
	receiver bool
}

func callerResolveKeyFor(src valueSrc, receiver bool) callerResolveKey {
	src.expr = ast.Unparen(src.expr)
	return callerResolveKey{src, receiver}
}

func callerKey(k callerNode) fkey { return fkey{fn: k.fn, lit: k.lit} }

func (g *callerGraph) addCallerLive(v *types.Var, ref valueSrc) {
	v = v.Origin()
	for _, old := range g.live[v] {
		if old == ref {
			return
		}
	}
	g.live[v] = append(g.live[v], ref)
	g.bindingEpoch++
}

// Ограничения касаются только удержания синтаксических списков, а не обхода.
const callerSourceMemoEntryLimit = 4096
const callerSourceMemoValueLimit = 16384

// Ответ содержит все исходные valueSrc в прежнем порядке, без proof/UNKNOWN.
// assignments, parameters и index.calls неизменяемы после newCallerGraph;
// live и emptyVariadic меняются с bindingEpoch. Сброс корня/factory обнуляет memo
// отдельно, поэтому повторное значение эпохи не возвращает чужие bindings.
// Срез доступен только для чтения; все потребители обходят его по значениям.
func (g *callerGraph) sources(v *types.Var) []valueSrc {
	v = v.Origin()
	if g.sourceMemo == nil || g.sourceMemoEpoch != g.bindingEpoch {
		g.sourceMemo = map[*types.Var][]valueSrc{}
		g.sourceMemoEpoch, g.sourceMemoWeight = g.bindingEpoch, 0
	}
	if refs, ok := g.sourceMemo[v]; ok {
		return refs
	}
	refs := g.sourcesRaw(v)
	if len(g.sourceMemo) >= callerSourceMemoEntryLimit || len(refs) > callerSourceMemoValueLimit-g.sourceMemoWeight {
		return refs
	}
	// Raw dedup может оставить большой cap при малом len. Удерживаем только
	// компактную копию, включая точное различие nil/пустого non-nil среза.
	var stored []valueSrc
	if refs != nil {
		stored = make([]valueSrc, len(refs))
		copy(stored, refs)
	}
	g.sourceMemo[v] = stored
	g.sourceMemoWeight += len(stored)
	return stored
}

func (g *callerGraph) sourcesRaw(v *types.Var) []valueSrc {
	v = v.Origin()
	var refs []valueSrc
	refs = append(refs, g.assignments[v]...)
	if incoming := g.live[v]; len(incoming) > 0 {
		return callerDistinctSources(append(refs, incoming...))
	}
	if g.emptyVariadic[v] {
		return callerDistinctSources(refs)
	}
	if p, ok := g.parameters[v]; ok {
		for _, call := range g.index.calls[p.fk.fn] {
			if p.recv {
				if sel, ok := ast.Unparen(call.call.Fun).(*ast.SelectorExpr); ok {
					refs = append(refs, valueSrc{pkg: call.pkg, fk: call.fk, expr: sel.X, tuple: -1})
				}
			} else if p.index < len(call.call.Args) {
				end := p.index + 1
				if p.fk.fn != nil {
					sig := p.fk.fn.Type().(*types.Signature)
					if sig.Variadic() && p.index == sig.Params().Len()-1 {
						end = len(call.call.Args)
					}
				}
				for _, arg := range call.call.Args[p.index:end] {
					refs = append(refs, valueSrc{pkg: call.pkg, fk: call.fk, expr: arg, tuple: -1})
				}
			}
		}
	}
	return callerDistinctSources(refs)
}

func callerDistinctSources(refs []valueSrc) []valueSrc {
	if len(refs) < 2 {
		return refs
	}
	seen := make(map[valueSrc]bool, len(refs))
	out := make([]valueSrc, 0, len(refs))
	for _, ref := range refs {
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
	}
	return out
}

func (g *callerGraph) markCallerCalled(node callerNode) {
	if g.called == nil {
		g.called = map[callerNode]bool{}
	}
	if !g.called[node] {
		g.called[node] = true
		g.bindingEpoch++
	}
}

func (g *callerGraph) bindCaller(sp *surfaceSrcPkg, owner callerNode, call *ast.CallExpr, target callerNode) {
	g.markCallerCalled(target)
	var sig *types.Signature
	if target.fn != nil {
		sig = target.fn.Type().(*types.Signature)
	} else if target.lit != nil {
		sig, _ = g.bodies[target].sp.info.TypeOf(target.lit).(*types.Signature)
	}
	if sig == nil {
		return
	}
	args := call.Args
	if sig.Recv() != nil {
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			selection := sp.info.Selections[sel]
			if selection != nil && selection.Kind() == types.MethodExpr && len(args) > 0 {
				g.addCallerLive(sig.Recv(), valueSrc{pkg: sp, fk: callerKey(owner), expr: args[0], tuple: -1})
				args = args[1:]
			} else {
				// Динамический и promoted receiver уже связан с точным значением
				// в boundMethod; исходная обёртка не является этим receiver.
				bound := false
				if selection != nil {
					method, _ := selection.Obj().(*types.Func)
					bound = method != nil && (isIfaceMethod(method) || len(selection.Index()) > 1)
				}
				if !bound && !g.capturedCallerField(sp, sel, selection, target.fn, sig) {
					g.addCallerLive(sig.Recv(), valueSrc{pkg: sp, fk: callerKey(owner), expr: sel.X, tuple: -1})
				}
			}
		}
	}
	for i, arg := range args {
		index := i
		if sig.Variadic() && index >= sig.Params().Len()-1 {
			index = sig.Params().Len() - 1
		}
		if index >= sig.Params().Len() || index < 0 {
			break
		}
		v := sig.Params().At(index)
		g.addCallerLive(v, valueSrc{pkg: sp, fk: callerKey(owner), expr: arg, tuple: -1})
	}
	if sig.Variadic() && len(args) < sig.Params().Len() {
		v := sig.Params().At(sig.Params().Len() - 1).Origin()
		if g.emptyVariadic == nil {
			g.emptyVariadic = map[*types.Var]bool{}
		}
		if !g.emptyVariadic[v] {
			g.emptyVariadic[v] = true
			g.bindingEpoch++
		}
	}
}

type callerResolveAnswer struct {
	values  []callerOrigin
	unknown bool
}

// Только завершённый обход без рекурсивного cut и без новых live bindings
// даёт повторно используемый ответ. При смене bindings весь memo истекает.
func (g *callerGraph) resolve(src valueSrc, receiver bool, seen map[callerResolveKey]bool) ([]callerOrigin, bool) {
	// Полный обычный memo не требует owner или снимка. Сам исходный resolve
	// сохраняет порядок Err/seen/initial-boundary checks перед возвратом ответа.
	if src.pkg != nil && src.expr != nil && g.lifetimeScanning && g.resolveMemo != nil && g.resolveMemoEpoch == g.bindingEpoch {
		if _, complete := g.initialResolveMemo[callerResolveKeyFor(src, receiver)]; complete {
			return g.resolveOwned(src, receiver, seen, nil)
		}
	}
	owner := g.beginCallerOrigin(seen)
	defer g.endCallerOrigin(owner)
	return g.resolveOwned(src, receiver, seen, owner)
}

func (g *callerGraph) resolveOwned(src valueSrc, receiver bool, seen map[callerResolveKey]bool, owner *callerOriginOwner) (values []callerOrigin, unknown bool) {
	return g.resolveOwnedSibling(src, receiver, seen, owner, nil)
}

// distinctPrefix принадлежит одному циклу sources(v). Пока он жив, верхний
// frame содержит только seed и чтения предыдущих различных исходников цикла.
func (g *callerGraph) resolveOwnedSibling(src valueSrc, receiver bool, seen map[callerResolveKey]bool, owner *callerOriginOwner, distinctPrefix *bool) (values []callerOrigin, unknown bool) {
	skipSiblings := distinctPrefix != nil && *distinctPrefix
	if skipSiblings {
		// Только непосредственный initial-hit может продолжить тот же префикс.
		*distinctPrefix = false
	}
	g.work.ResolveQueries++
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	if src.pkg == nil || src.expr == nil {
		return nil, true
	}
	key := callerResolveKeyFor(src, receiver)
	wasSeen := seen[key]
	// sources дедуплицирует valueSrc до Unparen. Скобки могут скрывать
	// повтор того же ключа; с первого такого ref используем полный поиск.
	skipSiblings = skipSiblings && !wasSeen && src.expr == key.source.expr
	entryRead := g.callerOriginEntryRead(owner, key, wasSeen, skipSiblings)
	if wasSeen {
		g.addCallerSemantic(1, 0, 0, 0)
		g.work.ResolveCycleCuts++
		return nil, g.semanticOverflow
	}
	if g.resolveMemo == nil || g.resolveMemoEpoch != g.bindingEpoch {
		g.work.ResolveInvalidations++
		g.resolveMemo = map[callerResolveKey]callerResolveAnswer{}
		g.initialResolveMemo = map[callerResolveKey]callerResolveAnswer{}
		g.resolveMemoGeneration++
		g.resolveMemoEpoch = g.bindingEpoch
		g.resolveWeight, g.initialResolveWeight = 0, 0
		g.work.ResolveMemoEntries, g.work.ResolveMemoValues = 0, 0
	}
	initial := g.lifetimeScanning
	memo := g.resolveMemo
	if initial {
		g.work.ResolveInitialQueries++
		memo = g.initialResolveMemo
	}
	if answer, ok := memo[key]; ok {
		g.work.ResolveHits++
		if initial {
			g.work.ResolveInitialHits++
			// Начальные значения никогда не становятся полным ответом о времени жизни,
			// даже если внутренний обход обслуживается этим кешем.
			g.noteCallerInitialBoundary()
		}
		if g.semanticOverflow {
			return nil, true
		}
		if skipSiblings && initial && entryRead && !owner.top.bad {
			*distinctPrefix = true
		}
		return answer.values, answer.unknown
	}
	if answer, ok := g.callerOriginHitWithEntryRead(owner, key, entryRead); ok {
		return answer.values, answer.unknown
	}
	frame := g.beginCallerOriginFrame(owner, key)
	defer func() { g.endCallerOriginFrame(owner, frame, values, unknown) }()
	g.work.ResolveEvaluations++
	start := time.Now()
	epoch, cuts := g.bindingEpoch, g.resolveCuts
	completed := g.completedInitialSkips
	initialCuts := g.resolveCuts - g.initialSkips
	raw := -1
	values, unknown = g.resolveRawOwned(src, receiver, seen, owner, frame, entryRead, &raw)
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	if raw < 0 {
		raw = len(values)
		values = callerDistinctOrigins(values)
	}
	g.observeCallerResolve(src, time.Since(start), raw, len(values))
	complete := g.resolveCuts-cuts == g.completedInitialSkips-completed
	if initial {
		// Пропуск внешнего доказательства времени жизни — явный начальный режим,
		// а не частичный ответ графа. Реальные отсечения рекурсии и снимков сохраняются.
		complete = initialCuts == g.resolveCuts-g.initialSkips
	}
	if epoch == g.bindingEpoch && complete && !g.semanticOverflow && (g.ctx == nil || g.ctx.Err() == nil) {
		g.retainCallerAnswer(key, callerResolveAnswer{values, unknown}, initial)
	}
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	return values, unknown
}

func (g *callerGraph) resolveRaw(src valueSrc, receiver bool, seen map[callerResolveKey]bool) ([]callerOrigin, bool) {
	// Прямой старый raw-вход не имеет записываемого родителя.
	return g.resolveRawOwned(src, receiver, seen, nil, nil, false, nil)
}

func (g *callerGraph) resolveRawOwned(src valueSrc, receiver bool, seen map[callerResolveKey]bool, owner *callerOriginOwner, frame *callerOriginRecord, entryRead bool, distinctRawCount *int) (values []callerOrigin, unknown bool) {
	if src.pkg == nil || src.expr == nil {
		return nil, true
	}
	sp, e := src.pkg, ast.Unparen(src.expr)
	key := callerResolveKeyFor(src, receiver)
	wasSeen := seen[key]
	g.callerOriginRawEntryRead(owner, frame, key, wasSeen, entryRead)
	if wasSeen {
		return nil, false
	}
	if frame != nil {
		frame.pushed = true
	}
	seen[key] = true
	defer delete(seen, key)
	if callerNil(sp, e) {
		return []callerOrigin{{nilValue: true}}, false
	}
	if receiver {
		t := sp.info.TypeOf(e)
		if tuple, ok := t.(*types.Tuple); ok {
			i := src.tuple
			if i < 0 {
				i = 0
			}
			if i < tuple.Len() {
				t = tuple.At(i).Type()
			}
		}
		if t != nil {
			if _, iface := t.Underlying().(*types.Interface); !iface {
				if n := namedOf(t); n != nil {
					foreign := n.Obj().Pkg() != nil && g.safeExternal[n.Obj().Pkg().Path()]
					return []callerOrigin{{typ: t, source: src, foreign: foreign}}, false
				}
			}
		}
	}
	if fn := callerFunction(sp, e); fn != nil {
		fn = fn.Origin()
		if fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] && (!isIfaceMethod(fn) || g.may != nil && !g.unresolvedCallerRelevant(sp, e)) {
			g.taintCallerOrigins()
			g.identityFree[pPosition(g.p, e)] = true
			return []callerOrigin{{foreign: true}}, false
		}
		promoted := false
		if sel, ok := e.(*ast.SelectorExpr); ok {
			if selection := sp.info.Selections[sel]; selection != nil {
				promoted = len(selection.Index()) > 1
			}
		}
		if isIfaceMethod(fn) || promoted {
			if sel, ok := e.(*ast.SelectorExpr); ok {
				nodes, u := g.boundMethodOwned(sp, sel.X, fn, seen, owner)
				for _, node := range nodes {
					values = append(values, callerOrigin{node: node})
				}
				if len(nodes) == 0 && !u {
					// boundMethod проследил receiver до доказанного foreign
					// leaf (либо nil). Сохраняем факт завершённого разрешения:
					// пустой MAY-кандидат сам такого разрешения не даёт.
					values = append(values, callerOrigin{foreign: true})
				}
				return values, u
			}
			return nil, true
		}
		if _, ok := g.bodies[callerNode{fn: fn}]; ok {
			return []callerOrigin{{node: callerNode{fn: fn}}}, false
		}
		if fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] {
			return []callerOrigin{{foreign: true}}, false
		}
		return nil, true
	}
	if lit, ok := e.(*ast.FuncLit); ok {
		return []callerOrigin{{node: callerNode{lit: lit}}}, false
	}
	if sel, ok := e.(*ast.SelectorExpr); ok {
		if selection := sp.info.Selections[sel]; selection != nil && selection.Kind() == types.FieldVal {
			base := src
			base.expr, base.tuple = sel.X, -1
			refs, u := g.embeddedCallerSources(base, fieldPath(selection), map[callerFieldKey]bool{})
			g.restoreCallerOriginScope(owner)
			unknown = u
			for _, ref := range refs {
				vs, u := g.resolveOwned(ref, receiver, seen, owner)
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return nil, true
				}
				values = append(values, vs...)
				unknown = unknown || u
			}
			if len(refs) == 0 && !unknown {
				return []callerOrigin{{nilValue: true}}, false
			}
			return values, unknown
		}
	}
	if v := callerVariable(sp, e); v != nil {
		refs := g.sources(v)
		if len(refs) == 0 {
			if _, zero := g.zeroVars[v.Origin()]; zero || g.emptyVariadic[v.Origin()] {
				return []callerOrigin{{nilValue: true}}, g.callerVariableLifetimeUnknown(src, v)
			}
			g.observeUnboundCallback(v)
			return nil, true
		}
		unknown = g.callerVariableLifetimeUnknown(src, v)
		// Прямой raw-вход сохраняет повторы. Для обычного разрешения объединяем
		// результаты нескольких источников сразу, сохраняя число всех вхождений.
		mergeOrigins := distinctRawCount != nil && len(refs) > 1
		rawCount := 0
		var origins callerOriginUnion
		distinctPrefix := mergeOrigins && frame != nil && owner != nil && owner.top == frame && frame.count == 1 && !frame.bad
		for _, ref := range refs {
			vs, u := g.resolveOwnedSibling(ref, receiver, seen, owner, &distinctPrefix)
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true
			}
			for _, value := range vs {
				if !g.callerValueCompatible(value, v.Type()) {
					continue
				}
				if mergeOrigins {
					rawCount++
					origins.add(value)
				} else {
					values = append(values, value)
				}
			}
			unknown = unknown || u
		}
		if mergeOrigins {
			*distinctRawCount = rawCount
			return origins.values, unknown
		}
		return values, unknown
	}
	switch x := e.(type) {
	case *ast.CallExpr:
		if tv, ok := sp.info.Types[x.Fun]; ok && tv.IsType() && len(x.Args) == 1 {
			src.expr = x.Args[0]
			src.tuple = -1
			return g.resolveOwned(src, receiver, seen, owner)
		}
		if id, ok := x.Fun.(*ast.Ident); ok {
			if builtin, ok := sp.info.Uses[id].(*types.Builtin); ok {
				switch builtin.Name() {
				case "make", "new":
					return []callerOrigin{{nilValue: true}}, g.callerLifetimeUnknown(src)
				case "append":
					for _, arg := range x.Args {
						ref := src
						ref.expr = arg
						ref.tuple = -1
						vs, u := g.resolveOwned(ref, receiver, seen, owner)
						if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
							return nil, true
						}
						values = append(values, vs...)
						unknown = unknown || u
					}
					return values, unknown
				}
			}
		}
		if fn := callerFunction(sp, x.Fun); fn != nil && fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] {
			sig := fn.Type().(*types.Signature)
			i := src.tuple
			if i < 0 {
				i = 0
			}
			if i < sig.Results().Len() {
				if iface, ok := sig.Results().At(i).Type().Underlying().(*types.Interface); ok && iface.NumMethods() == 0 {
					return nil, true
				}
			}
			return []callerOrigin{{foreign: true}}, false
		}
		targets, u := g.resolveOwned(valueSrc{pkg: sp, fk: src.fk, expr: x.Fun, tuple: -1}, false, seen, owner)
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		unknown = u
		// Прямой raw-вход сохраняет исходные повторы. Обычный resolve считает
		// каждое вхождение, включая foreign, и возвращает первое по порядку.
		var origins callerOriginUnion
		rawCount := 0
		for _, target := range targets {
			if target.foreign {
				if distinctRawCount != nil {
					rawCount++
					origins.add(target)
				} else {
					values = append(values, target)
				}
				continue
			}
			if target.nilValue {
				continue
			}
			g.bindCaller(sp, callerNode{fn: src.fk.fn, lit: src.fk.lit}, x, target.node)
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true
			}
			index := src.tuple
			if index < 0 {
				index = 0
			}
			rs := g.index.returns[callerKey(target.node)]
			if index >= len(rs) {
				unknown = true
				continue
			}
			refs := rs[index]
			if len(refs) == 0 && target.node.fn != nil {
				sig := target.node.fn.Type().(*types.Signature)
				if index < sig.Results().Len() && sig.Results().At(index).Name() != "" {
					refs = g.sources(sig.Results().At(index))
				}
			}
			for _, ref := range refs {
				vs, u := g.resolveOwned(ref, receiver, seen, owner)
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return nil, true
				}
				if distinctRawCount != nil {
					rawCount += len(vs)
					origins.addAll(vs)
				} else {
					values = append(values, vs...)
				}
				unknown = unknown || u
			}
		}
		if distinctRawCount != nil {
			*distinctRawCount = rawCount
			return origins.values, unknown
		}
	case *ast.UnaryExpr:
		src.expr = x.X
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.StarExpr:
		src.expr = x.X
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.TypeAssertExpr:
		src.expr = x.X
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.IndexExpr:
		src.expr = x.X
		src.elem = true
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.SliceExpr:
		src.expr = x.X
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.IndexListExpr:
		src.expr = x.X
		return g.resolveOwned(src, receiver, seen, owner)
	case *ast.CompositeLit:
		for _, elt := range x.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				elt = kv.Value
			}
			ref := src
			ref.expr = elt
			vs, u := g.resolveOwned(ref, receiver, seen, owner)
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true
			}
			values = append(values, vs...)
			unknown = unknown || u
		}
	default:
		return nil, true
	}
	return values, unknown
}

func (g *callerGraph) boundMethod(sp *surfaceSrcPkg, receiver ast.Expr, method *types.Func, seen map[callerResolveKey]bool) ([]callerNode, bool) {
	owner := g.beginCallerOrigin(seen)
	defer g.endCallerOrigin(owner)
	return g.boundMethodOwned(sp, receiver, method, seen, owner)
}

func (g *callerGraph) boundMethodOwned(sp *surfaceSrcPkg, receiver ast.Expr, method *types.Func, seen map[callerResolveKey]bool, owner *callerOriginOwner) (nodes []callerNode, unknown bool) {
	origins, u := g.resolveOwned(valueSrc{pkg: sp, expr: receiver, tuple: -1}, true, seen, owner)
	unknown = u
	for _, origin := range origins {
		if origin.foreign || origin.nilValue {
			continue
		}
		if origin.typ == nil {
			unknown = true
			continue
		}
		obj, index, _ := types.LookupFieldOrMethod(origin.typ, true, method.Pkg(), method.Name())
		fn, ok := obj.(*types.Func)
		if !ok {
			unknown = true
			continue
		}
		path := embedPath(origin.typ, index)
		if len(path) > 0 {
			refs, unresolved := g.embeddedCallerSources(origin.source, path, map[callerFieldKey]bool{})
			g.restoreCallerOriginScope(owner)
			unknown = unknown || unresolved
			for _, ref := range refs {
				targets, unresolved := g.boundMethodOwned(ref.pkg, ref.expr, fn, seen, owner)
				nodes = append(nodes, targets...)
				unknown = unknown || unresolved
			}
			continue
		}
		if isIfaceMethod(fn) {
			unknown = true
			continue
		}
		fn = fn.Origin()
		if _, ok := g.bodies[callerNode{fn: fn}]; ok {
			if recv := fn.Type().(*types.Signature).Recv(); recv != nil {
				g.addCallerLive(recv, origin.source)
			}
			nodes = append(nodes, callerNode{fn: fn})
		} else if fn.Pkg() == nil || !g.safeExternal[fn.Pkg().Path()] {
			unknown = true
		}
	}
	if len(origins) == 0 {
		unknown = true
	}
	return nodes, unknown
}

// potentialCallerTargets применяется ТОЛЬКО для доказательства отсутствия
// identity-кода у неразрешённого вызова. Эти функции не становятся достижимыми
// и не порождают READ. Фактические цели выше получаются из записей/возвратов.
func (g *callerGraph) potentialCallerTargetsRaw(sp *surfaceSrcPkg, expr ast.Expr) []callerNode {
	if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
		return []callerNode{{lit: lit}}
	}
	if fn := callerFunction(sp, expr); fn != nil {
		if !isIfaceMethod(fn) {
			if _, ok := g.bodies[callerNode{fn: fn.Origin()}]; ok {
				return []callerNode{{fn: fn.Origin()}}
			}
			return nil
		}
		var out []callerNode
		recv := fn.Type().(*types.Signature).Recv()
		var iface *types.Interface
		if recv != nil {
			iface, _ = recv.Type().Underlying().(*types.Interface)
		}
		for _, candidate := range g.methods[fn.Name()] {
			otherRecv := candidate.Type().(*types.Signature).Recv()
			if iface != nil && otherRecv != nil && !g.hasCallerTypeParam(otherRecv.Type()) && !g.hasCallerTypeParam(recv.Type()) {
				typ := otherRecv.Type()
				implements := types.Implements(typ, iface)
				if _, pointer := typ.(*types.Pointer); !pointer {
					implements = implements || types.Implements(types.NewPointer(typ), iface)
				}
				if !implements {
					continue
				}
			}
			if g.signatureCompatible(fn.Type().Underlying(), candidate.Type().Underlying()) {
				out = append(out, callerNode{fn: candidate})
			}
		}
		return out
	}
	typ := sp.info.TypeOf(expr)
	if typ == nil {
		return nil
	}
	t, ok := typ.Underlying().(*types.Signature)
	if !ok {
		return nil
	}
	var out []callerNode
	shape, _ := callerShape(t)
	for _, node := range g.signatureBodies[shape] {
		b := g.bodies[node]
		var other types.Type
		if node.fn != nil {
			other = node.fn.Type()
		} else {
			other = b.sp.info.TypeOf(node.lit)
		}
		if other != nil && g.signatureCompatible(t, other.Underlying()) {
			out = append(out, node)
		}
	}
	return out
}

func (g *callerGraph) signatureCompatibleRaw(a, b types.Type) bool {
	if types.Identical(a, b) {
		return true
	}
	x, xok := a.Underlying().(*types.Signature)
	y, yok := b.Underlying().(*types.Signature)
	if !xok || !yok || x.Variadic() != y.Variadic() || x.Params().Len() != y.Params().Len() || x.Results().Len() != y.Results().Len() {
		return false
	}
	compatible := func(a, b types.Type) bool {
		return types.Identical(a, b) || g.hasCallerTypeParam(a) || g.hasCallerTypeParam(b)
	}
	for i := 0; i < x.Params().Len(); i++ {
		if !compatible(x.Params().At(i).Type(), y.Params().At(i).Type()) {
			return false
		}
	}
	for i := 0; i < x.Results().Len(); i++ {
		if !compatible(x.Results().At(i).Type(), y.Results().At(i).Type()) {
			return false
		}
	}
	return true
}

func (g *callerGraph) callerValueCompatible(value callerOrigin, want types.Type) bool {
	if value.foreign || value.nilValue || value.node.fn == nil && value.node.lit == nil {
		return true
	}
	if _, ok := want.Underlying().(*types.Signature); !ok {
		return true
	}
	var typ types.Type
	if value.node.fn != nil {
		typ = value.node.fn.Type()
	} else {
		typ = g.bodies[value.node].sp.info.TypeOf(value.node.lit)
	}
	return typ == nil || g.signatureCompatible(want.Underlying(), typ.Underlying())
}

func (g *callerGraph) callerMayRead() {
	built := false
	g.mayMemo.once.Do(func() {
		built = true
		g.work.MayBuilds++
		g.callerMayReadRaw()
		g.mayMemo.err = g.analysisErr
		if g.analysisErr == nil {
			g.mayMemo.values = g.may
		}
	})
	if !built {
		g.work.MayHits++
	}
	g.may = g.mayMemo.values
	g.analysisErr = g.mayMemo.err
	if g.analysisErr != nil {
		callerGraphs.Delete(g.p)
	}
}

func (g *callerGraph) callerMayReadRaw() {
	g.may = map[callerNode]bool{}
	edges := map[callerNode][]callerNode{}
	start := time.Now()
	if g.observer != nil {
		g.observer("may-edges:start", g.work)
	}
	for node, b := range g.bodies {
		if err := g.ctx.Err(); err != nil {
			g.analysisErr = err
			return
		}
		ast.Inspect(b.node, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callerProducer(callerFunction(b.sp, call.Fun)) != "" {
				g.may[node] = true
			}
			// Как и фактический обход, MAY не принимает builtin или
			// преобразование типа за вызов функции подходящей подписи.
			if tv := b.sp.info.Types[call.Fun]; tv.IsType() {
				return true
			}
			if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
				if _, ok := b.sp.info.Uses[id].(*types.Builtin); ok {
					return true
				}
			}
			edges[node] = append(edges[node], g.potentialCallerTargets(b.sp, call.Fun)...)
			for _, arg := range call.Args {
				if typ := b.sp.info.TypeOf(arg); typ != nil {
					if _, ok := typ.Underlying().(*types.Signature); ok {
						edges[node] = append(edges[node], g.potentialCallerTargets(b.sp, arg)...)
					}
				}
			}
			return true
		})
	}
	g.work.MayEdges = time.Since(start)
	if g.observer != nil {
		g.observer("may-edges:end", g.work)
	}
	start = time.Now()
	if g.observer != nil {
		g.observer("may-propagation:start", g.work)
	}
	for changed := true; changed; {
		if err := g.ctx.Err(); err != nil {
			g.analysisErr = err
			return
		}
		changed = false
		for from, tos := range edges {
			if g.may[from] {
				continue
			}
			for _, to := range tos {
				if g.may[to] {
					g.may[from] = true
					changed = true
					break
				}
			}
		}
	}
	g.work.MayPropagation = time.Since(start)
	if g.observer != nil {
		g.observer("may-propagation:end", g.work)
	}
}

func (g *callerGraph) unresolvedCallerRelevant(sp *surfaceSrcPkg, expr ast.Expr) bool {
	candidates := g.potentialCallerTargets(sp, expr)
	if len(candidates) == 0 {
		if fn := callerFunction(sp, expr); fn != nil && fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] {
			return false
		}
		return true
	}
	for _, node := range candidates {
		if g.may[node] {
			return true
		}
	}
	return false
}
