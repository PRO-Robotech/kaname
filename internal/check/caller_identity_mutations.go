// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"slices"
)

// Запись поля хранит получателя: один объект объявления поля не делает
// все экземпляры структуры одним значением.
type callerFieldMutation struct {
	owner valueSrc
	path  []*types.Var
	value valueSrc
}
type callerObjectKey struct {
	pkg   *surfaceSrcPkg
	expr  ast.Expr
	zero  *types.Var
	field *types.Var
}

func (g *callerGraph) collectCallerMutations() {
	g.mutations = map[*types.Var][]callerFieldMutation{}
	for node, b := range g.bodies {
		ast.Inspect(b.node, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			a, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range a.Lhs {
				// Запись элемента сохраняет получателя контейнера: поле
				// backlog[0] не превращается в объединение всех Worker.
				if index, ok := ast.Unparen(lhs).(*ast.IndexExpr); ok {
					lhs = index.X
				}
				sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
				if !ok {
					continue
				}
				selection := b.sp.info.Selections[sel]
				if selection == nil || selection.Kind() != types.FieldVal {
					continue
				}
				path := fieldPath(selection)
				if len(path) == 0 {
					continue
				}
				value := valueSrc{pkg: b.sp, fk: callerKey(node), tuple: -1}
				if len(a.Rhs) == len(a.Lhs) {
					value.expr = a.Rhs[i]
				} else if len(a.Rhs) == 1 {
					value.expr = a.Rhs[0]
					value.tuple = i
				} else {
					continue
				}
				field := path[len(path)-1].Origin()
				g.mutations[field] = append(g.mutations[field], callerFieldMutation{valueSrc{pkg: b.sp, fk: callerKey(node), expr: sel.X, tuple: -1}, path[:len(path)-1], value})
			}
			return true
		})
	}
}

// callerObjectSourceID именует один точный канонический источник в прогоне графа.
// ID стабильны между эпохами связывания и корнями RPC, пока кадры могут быть активны.
type callerObjectSourceID uint64

func (g *callerGraph) internObjectSource(src valueSrc) callerObjectSourceID {
	key := callerResolveKeyFor(src, true)
	if id, ok := g.objectSourceIDs[key]; ok {
		return id
	}
	if g.objectSourceIDs == nil {
		g.objectSourceIDs = map[callerResolveKey]callerObjectSourceID{}
	}
	// Записи никогда не удаляются и не переиспользуются за время жизни графа.
	id := callerObjectSourceID(len(g.objectSourceIDs)) + 1
	g.objectSourceIDs[key] = id
	g.work.ObjectSourceIDs++
	return id
}

// Источники-объекты служат лишь для сопоставления записи её получателю.
// Никакая цель вызова не выводится из совпадения типа или имени.
type callerObjectAnswer struct {
	objects map[callerObjectKey]bool
	unknown bool
}

// Возвращённая карта доступна только для чтения независимо от допуска в кеш.
// nil представляет пустое множество только для чтения, в том числе в memo.
func (g *callerGraph) callerObjects(src valueSrc, seen map[callerObjectSourceID]bool) (map[callerObjectKey]bool, bool) {
	// Даже fresh hit является внешним входом для suspended interior chain.
	g.taintCallerTraces()
	if g.objectExecutions != nil && g.objectExecutions.graph == g && g.lifetimeScanning && len(seen) == 0 {
		return g.callerObjectExecution(src, seen)
	}
	objects, unknown, _ := g.callerObjectsOwned(src, seen)
	return objects, unknown
}

// Повторно используем лишь завершённые обходы происхождения в той же эпохе связывания.
// Ответ с отсечением рекурсии, включая снимок активного запроса поля, никогда
// не публикуется. Границы допуска влияют лишь на кеширование, а не вычисленный ответ.
// owned истинен только для непустого неопубликованного исходного результата. Единственный
// получатель может поглотить эту карту. Попадание в кеш или публикация передаёт владение;
// даже поздний сброс эпохи не делает заимствованную карту снова изменяемой.
// Пустой результат может быть nil и не передаёт владение картой.
func (g *callerGraph) callerObjectsOwned(src valueSrc, seen map[callerObjectSourceID]bool) (map[callerObjectKey]bool, bool, bool) {
	return g.callerObjectsOwnedScope(src, seen, nil)
}

// Переданный scope заимствован у внешнего fresh ticket до конца этого тела.
// Прямой старый Owned-вход не получает handoff; первый interior заново проверит
// полный snapshot и принадлежность узла, прежде чем создать собственный ticket.
func (g *callerGraph) callerObjectsOwnedScope(src valueSrc, seen map[callerObjectSourceID]bool, entryScope *callerObjectExecutionScope) (map[callerObjectKey]bool, bool, bool) {
	chain := g.beginCallerTrace(seen)
	if chain != nil {
		// Признак ограничен этим синхронным телом: указатели стека не выходят
		// вызывающему, а неизвестный Err не проходит допуск begin.
		chain.executing = true
		chain.entryScope = entryScope
	}
	defer g.endCallerTrace(chain)
	return g.callerObjectsTracked(src, seen, chain)
}

func (g *callerGraph) callerObjectsTracked(src valueSrc, seen map[callerObjectSourceID]bool, chain *callerTraceChain) (map[callerObjectKey]bool, bool, bool) {
	g.work.ObjectQueries++
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true, false
	}
	if g.objectMemo == nil || g.objectMemoEpoch != g.bindingEpoch {
		if g.objectMemo != nil {
			g.work.ObjectEpochResets++
		}
		g.objectMemo = map[callerObjectSourceID]callerObjectAnswer{}
		g.initialObjectMemo = nil
		g.objectMemoGeneration++
		g.objectMemoEpoch, g.objectMemoWeight = g.bindingEpoch, 0
	}
	initial := g.lifetimeScanning
	memo := g.objectMemo
	if initial {
		if g.initialObjectMemo == nil {
			g.initialObjectMemo = map[callerObjectSourceID]callerObjectAnswer{}
			g.objectMemoGeneration++
		}
		memo = g.initialObjectMemo
	}
	key := g.internObjectSource(src)
	if answer, ok := memo[key]; ok {
		objects, unknown := g.callerObjectMemoAnswer(answer, initial)
		return objects, unknown, false
	}
	epoch, cuts, initialSkips := g.bindingEpoch, g.resolveCuts, g.initialSkips
	completed := g.completedInitialSkips
	objects, unknown, owned := g.callerInteriorRaw(src, seen, key, chain)
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true, false
	}
	complete := g.resolveCuts-cuts == g.completedInitialSkips-completed
	if initial {
		// В начальном режиме исключаем только пропуск самого lifetime-барьера.
		// Настоящий цикл и снимок активного запроса по-прежнему запрещают публикацию.
		complete = cuts-initialSkips == g.resolveCuts-g.initialSkips
	}
	capacity := g.callerObjectMemoHasCapacity(len(objects))
	active := !g.semanticOverflow && (g.ctx == nil || g.ctx.Err() == nil)
	if !active {
		return nil, true, false
	}
	if epoch == g.bindingEpoch && complete && capacity && active {
		memo[key] = callerObjectAnswer{objects, unknown}
		g.objectMemoGeneration++
		g.objectMemoWeight += len(objects)
		g.work.ObjectRetained++
		owned = false
	} else {
		// Причины намеренно пересекаются: считаем каждый нарушенный предикат допуска.
		if epoch != g.bindingEpoch {
			g.work.ObjectRejectEpoch++
		}
		if !complete {
			g.work.ObjectRejectCut++
		}
		if initialSkips != g.initialSkips {
			g.work.ObjectRejectInitial++
		}
		if !capacity {
			g.work.ObjectRejectCapacity++
		}
	}
	return objects, unknown, owned
}

func (g *callerGraph) callerObjectMemoAnswer(answer callerObjectAnswer, initial bool) (map[callerObjectKey]bool, bool) {
	g.work.ObjectHits++
	if initial {
		// Начальные источники не доказывают сохранность за пределами lifetime-обхода.
		g.noteCallerInitialBoundary()
	}
	if g.semanticOverflow {
		return nil, true
	}
	return answer.objects, answer.unknown
}

// Непрозрачная ветка владеет своим аккумулятором и копирует заимствованные
// наборы перед объединением. Прозрачная ветка передаёт точный ответ ребёнка
// вместе с владением; непустой заимствованный набор не становится своим.
// Активный кадр не раскрывает аккумулятор запросам полей или lifetime.
func (g *callerGraph) callerObjectsRaw(src valueSrc, seen map[callerObjectSourceID]bool, key callerObjectSourceID, chain *callerTraceChain) (out map[callerObjectKey]bool, unknown, owned bool) {
	g.work.ObjectRawEvaluations++
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true, false
	}
	if src.pkg == nil || src.expr == nil {
		return out, true, false
	}
	e := ast.Unparen(src.expr)
	outer, cuts := len(seen) == 0, g.objectCuts
	defer func() {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			out, unknown, owned = nil, true, false
			return
		}
		// Цикл с конкретным основанием допустим, цикл без основания
		// не доказывает отсутствия alias и не становится нулевым объектом.
		if outer && g.objectCuts != cuts {
			anchored := false
			for object := range out {
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					out, unknown, owned = nil, true, false
					return
				}
				anchored = anchored || object.expr != nil
			}
			unknown = unknown || !anchored
		}
	}()
	g.callerTraceRead(chain, key, seen[key])
	if seen[key] {
		g.addCallerSemantic(1, 0, 1, 0)
		return out, false, false
	}
	frame := g.callerTracePush(chain, key)
	seen[key] = true
	defer func() {
		delete(seen, key)
		g.callerTracePop(chain, frame)
	}()
	if callerFunction(src.pkg, e) != nil {
		return out, false, false
	}
	if _, closure := e.(*ast.FuncLit); closure {
		return out, false, false
	}
	if callerNil(src.pkg, e) {
		return out, false, false
	}
	forward := func(ref valueSrc) (map[callerObjectKey]bool, bool, bool) {
		values, u, childOwned := g.callerObjectsTracked(ref, seen, chain)
		g.work.ObjectUnionBaselineWrites += len(values)
		return values, u, childOwned
	}
	// Заимствованный аккумулятор материализуется только на первом новом ключе.
	ensure := func(v callerObjectKey, countWrite bool) bool {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
		if out[v] {
			return true
		}
		if !owned {
			copyOut := make(map[callerObjectKey]bool, len(out)+1)
			for old := range out {
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return false
				}
				copyOut[old] = true
				g.work.ObjectUnionWrites++
			}
			out, owned = copyOut, true
		}
		out[v] = true
		if countWrite {
			g.work.ObjectUnionWrites++
		}
		return true
	}
	through := func(ref valueSrc, returnBoundary bool) bool {
		var values map[callerObjectKey]bool
		var u, childOwned bool
		if returnBoundary {
			values, u, childOwned = g.callerObjectsSeedReturn(ref, seen, chain)
		} else {
			values, u, childOwned = g.callerObjectsTracked(ref, seen, chain)
		}
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return false
		}
		g.work.ObjectUnionBaselineWrites += len(values)
		unknown = unknown || u
		if len(out) == 0 {
			out, owned = values, childOwned
			if childOwned && len(values) > 0 {
				g.work.ObjectUnionTransfers++
			}
			return true
		}
		if childOwned && len(values) > len(out) {
			// Только выбранная карта назначения принадлежит этому кадру.
			out, values = values, out
			owned = true
			g.work.ObjectUnionTransfers++
		}
		for v := range values {
			if !ensure(v, true) {
				return false
			}
		}
		return true
	}
	switch x := e.(type) {
	case *ast.CompositeLit:
		if out == nil {
			out = map[callerObjectKey]bool{}
		}
		out[callerObjectKey{pkg: src.pkg, expr: e}] = true
		owned = true
	case *ast.UnaryExpr:
		src.expr = x.X
		return forward(src)
	case *ast.StarExpr:
		src.expr = x.X
		return forward(src)
	case *ast.TypeAssertExpr:
		src.expr = x.X
		return forward(src)
	case *ast.IndexExpr:
		src.expr, src.tuple = x.X, -1
		return forward(src)
	case *ast.SliceExpr:
		src.expr, src.tuple = x.X, -1
		return forward(src)
	case *ast.CallExpr:
		if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok {
			if builtin, ok := src.pkg.info.Uses[id].(*types.Builtin); ok {
				switch builtin.Name() {
				case "new", "make":
					if out == nil {
						out = map[callerObjectKey]bool{}
					}
					out[callerObjectKey{pkg: src.pkg, expr: e}] = true
					return out, false, true
				case "append":
					if len(x.Args) > 0 {
						src.expr = x.Args[0]
						return forward(src)
					}
					return out, unknown, false
				}
			}
		}
		if tv := src.pkg.info.Types[x.Fun]; tv.IsType() && len(x.Args) == 1 {
			src.expr = x.Args[0]
			return forward(src)
		}
		// Разрешённое тело ещё не доказывает свежесть возвращённого
		// объекта: identity(box) возвращает исходный box. Идём по тем же
		// аргументам/tuple returns, что и resolver; непрослеженное — unknown.
		callerTraceScopeDependent(chain)
		if chain != nil {
			chain.bad = true
		}
		targets, u := g.resolve(valueSrc{pkg: src.pkg, fk: src.fk, expr: x.Fun, tuple: -1}, false, map[callerResolveKey]bool{})
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true, false
		}
		unknown = u
		if len(targets) == 0 {
			return out, true, false
		}
		for _, target := range targets {
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true, false
			}
			if target.node == (callerNode{}) {
				unknown = true
				continue
			}
			g.bindCaller(src.pkg, callerNode{fn: src.fk.fn, lit: src.fk.lit}, x, target.node)
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true, false
			}
			i := src.tuple
			if i < 0 {
				i = 0
			}
			results := g.index.returns[callerKey(target.node)]
			if i >= len(results) {
				unknown = true
				continue
			}
			refs := results[i]
			if len(refs) == 0 && target.node.fn != nil {
				sig := target.node.fn.Type().(*types.Signature)
				if i < sig.Results().Len() && sig.Results().At(i).Name() != "" {
					refs = g.sources(sig.Results().At(i))
				}
			}
			if len(refs) == 0 {
				unknown = true
			}
			for _, ref := range refs {
				if !through(ref, true) {
					return nil, true, false
				}
			}
		}
	case *ast.SelectorExpr:
		// Даже отсутствие active field query является чтением scope.
		// Помечаем весь живой путь до первого selector/query lookup.
		callerTraceScopeDependent(chain)
		selection := src.pkg.info.Selections[x]
		if chain != nil && !chain.bad && !g.callerTraceSelector(src, selection) {
			chain.bad = true
		}
		if selection == nil || selection.Kind() != types.FieldVal {
			return out, true, false
		}
		path := fieldPath(selection)
		base := src
		base.expr = x.X
		owners := []valueSrc{base}
		if len(path) > 1 {
			var u bool
			owners, u = g.embeddedCallerSources(base, path[:len(path)-1], map[callerFieldKey]bool{})
			unknown = unknown || u
		}
		for _, owner := range owners {
			objects, u, _ := g.callerObjectsTracked(owner, seen, chain)
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true, false
			}
			unknown = unknown || u
			for object := range objects {
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return nil, true, false
				}
				object.field = path[len(path)-1].Origin()
				if out == nil {
					out = map[callerObjectKey]bool{}
				}
				out[object] = true
				owned = true
			}
		}
		src.expr = x.X
		refs, u := g.embeddedCallerSources(src, path, map[callerFieldKey]bool{})
		unknown = unknown || u
		for _, ref := range refs {
			if !through(ref, false) {
				return nil, true, false
			}
		}
	default:
		v := callerVariable(src.pkg, e)
		if v == nil {
			return out, true, false
		}
		// Место хранения обязательно, но до конца обхода refs остаётся отложенным.
		storage := callerObjectKey{pkg: src.pkg, zero: v.Origin()}
		refs := g.sources(v)
		if objects, ok := g.callerSelfAppendObjects(src, v, refs, storage, seen, chain); ok {
			return objects, false, true
		}
		if len(refs) == 0 {
			if !ensure(storage, false) {
				return nil, true, false
			}
			// Идентичность места хранения не утверждает его значение.
			if _, zero := g.zeroVars[v.Origin()]; zero || g.emptyVariadic[v.Origin()] {
				return out, false, true
			}
			return out, true, true
		}
		for _, ref := range refs {
			if !through(ref, false) {
				return nil, true, false
			}
		}
		if !ensure(storage, false) {
			return nil, true, false
		}
	}
	return out, unknown, owned
}

func (g *callerGraph) callerMutations(src valueSrc, field *types.Var) (refs []valueSrc, unknown bool) {
	d := g.finalBoundary()
	var why finalCause
	if d != nil {
		defer func() { d.finishBoundary(unknown, why) }()
	}
	objects, u := g.callerObjects(src, map[callerObjectSourceID]bool{})
	unknown = u
	if d != nil && u && why.Kind == "" {
		why = causeAt("mutation_unknown_input_object", src.expr, nil, field)
	}
	for _, write := range g.mutations[field.Origin()] {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		if !g.callerLifetimeEffectPossible(write.owner) {
			continue
		}
		owners := []valueSrc{write.owner}
		if len(write.path) > 0 {
			var u bool
			owners, u = g.embeddedCallerSources(write.owner, write.path, map[callerFieldKey]bool{})
			if d != nil && u && why.Kind == "" {
				why = causeAt("mutation_unknown_embedded_owner", src.expr, write.owner.expr, field)
			}
			unknown = unknown || u
		}
		for _, owner := range owners {
			other, u := g.callerObjects(owner, map[callerObjectSourceID]bool{})
			if d != nil && u && why.Kind == "" {
				why = causeAt("mutation_unknown_write_owner", src.expr, owner.expr, field)
			}
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return nil, true
			}
			unknown = unknown || u // недоказанный alias не является доказанным чужим объектом
			for obj := range other {
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return nil, true
				}
				if objects[obj] {
					// Непрослеженный вызов callback не доказывает отсутствия
					// записи: учитываем её и сохраняем отказ до активации.
					if write.value.fk.lit != nil && !g.called[callerNode{lit: write.value.fk.lit}] {
						if d != nil && why.Kind == "" {
							why = causeAt("mutation_inactive_closure", src.expr, write.value.expr, field)
						}
						unknown = true
					}
					refs = append(refs, write.value)
					break
				}
			}
		}
	}
	return refs, unknown
}

// После штатного bind отдельная полная trace-цепь обслуживает один return ref.
// Исходный bad parent не восстанавливается; настоящие visited ancestors
// сохраняются и представлены учтёнными кадрами новой цепи.
func (g *callerGraph) callerObjectsSeedReturn(src valueSrc, seen map[callerObjectSourceID]bool, parent *callerTraceChain) (map[callerObjectKey]bool, bool, bool) {
	original := func() (map[callerObjectKey]bool, bool, bool) { return g.callerObjectsTracked(src, seen, parent) }
	c := g.objectExecutions
	const seedLimit = 64
	if parent == nil || !parent.bad || seen == nil || len(seen) == 0 || len(seen) > seedLimit || !g.lifetimeScanning || g.semanticOverflow || !callerTraceContext(g.ctx) || c == nil || c.graph != g {
		return original()
	}
	if !parent.live || parent.owner != c || !callerTraceSameContext(parent.ctx, g.ctx) {
		return original()
	}
	if g.ctx.Err() != nil {
		return original()
	}
	// Детерминированно упорядочены только metadata, не solver sites/outputs.
	var sources [seedLimit]callerObjectSourceID
	count := 0
	for source, present := range seen {
		if !present {
			return original()
		}
		sources[count] = source
		count++
	}
	slices.Sort(sources[:count])
	if c.graph != g || g.objectExecutions != c {
		return original()
	}
	g.taintCallerTraces()
	c.advance(g)
	// Один допуск chain+всех seed frames, включая возможный trace header.
	// До завершения выделения нет callbacks, scope mutation и повторного admit.
	if !c.admit(g, 1+count, callerTraceChainUnits+count*callerTraceFrameUnits, true) {
		return original()
	}
	if !c.traceAccount {
		c.traceAccount = true
		c.retained(g, callerTraceHeaderUnits)
		c.traceBuckets = new([callerTraceBucketCount]*callerTraceRecord)
	}
	c.retained(g, callerTraceChainUnits)
	child := &callerTraceChain{next: c.traceChains, owner: c, seen: seen, ctx: g.ctx, live: true}
	c.traceChains = child
	c.active++
	for i, source := range sources[:count] {
		c.retained(g, callerTraceFrameUnits)
		frame := &callerTraceFrame{next: c.traceFrames, parent: child.head, chain: child, source: source, depth: i + 1, live: true}
		c.traceFrames = frame
		child.head = frame
	}
	// executing намеренно false: полный stack validation и полный scope guard.
	// entryScope/record не наследуются. Первый interior приобретёт свежий scope.
	finish := func() {
		if child == nil {
			return
		}
		// Обычные raw defers уже сняли дочерние frames. Оставшиеся seed metadata
		// принадлежат только этой цепи; Pop не удаляет настоящие seen ancestors.
		for child.head != nil {
			g.callerTracePop(child, child.head)
		}
		g.endCallerTrace(child)
		child = nil
	}
	defer finish()
	if !g.callerTraceValid(child) {
		finish()
		return original()
	}
	return g.callerObjectsTracked(src, seen, child)
}
