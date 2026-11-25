// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"cmp"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
)

// Запись времени жизни — ребро от выделения памяти, а не имени переменной.
// Записи элементов также связывают алиасы общей памяти среза. Полные записи
// остаются неподдерживаемыми эффектами; их назначения требуют консервативного отказа.
type callerLifetimeWrite struct {
	owner, value valueSrc
	whole        bool
}

func (g *callerGraph) collectCallerLifetime() {
	for node, body := range g.bodies {
		if node.fn != nil && (node.fn.Name() == "init" || node.fn.Name() == "main" && body.sp == g.p.root) {
			g.startup = append(g.startup, node)
		}
		source := func(expr ast.Expr) valueSrc {
			return valueSrc{pkg: body.sp, fk: callerKey(node), expr: expr, tuple: -1}
		}
		g.indexUnpublishedMapWrites(body, source)
		ast.Inspect(body.node, func(n ast.Node) bool {
			if _, nested := n.(*ast.FuncLit); nested {
				return false
			}
			if call, ok := n.(*ast.CallExpr); ok && !body.sp.info.Types[call.Fun].IsType() {
				g.lifetimeCalls = append(g.lifetimeCalls, callSrc{body.sp, callerKey(node), call})
				if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
					if builtin, ok := body.sp.info.Uses[id].(*types.Builtin); ok && builtin.Name() == "append" && len(call.Args) > 1 {
						for _, value := range call.Args[1:] {
							g.lifetimeWrites = append(g.lifetimeWrites, callerLifetimeWrite{owner: source(call.Args[0]), value: source(value)})
						}
					}
				}
			}
			// В форме с «=» итератор пишет в уже существующие ячейки перед
			// телом каждой итерации. Обе позиции могут разыменовывать алиас.
			if loop, ok := n.(*ast.RangeStmt); ok && loop.Tok == token.ASSIGN {
				for slot, lhs := range [2]ast.Expr{loop.Key, loop.Value} {
					if dst, ok := ast.Unparen(lhs).(*ast.StarExpr); ok {
						value := source(loop.X)
						value.rangeKey, value.rangeVal = slot == 0, slot == 1
						g.lifetimeWrites = append(g.lifetimeWrites, callerLifetimeWrite{
							owner: source(dst.X), value: value, whole: true,
						})
					}
				}
			}
			if assign, ok := n.(*ast.AssignStmt); ok {
				for i, lhs := range assign.Lhs {
					var owner ast.Expr
					whole := false
					switch lhs := ast.Unparen(lhs).(type) {
					case *ast.IndexExpr:
						owner = lhs.X
					case *ast.StarExpr:
						owner, whole = lhs.X, true
					}
					if owner == nil {
						continue
					}
					value := source(nil)
					if len(assign.Rhs) == len(assign.Lhs) {
						value.expr = assign.Rhs[i]
					} else if len(assign.Rhs) == 1 {
						value.expr, value.tuple = assign.Rhs[0], i
					}
					g.lifetimeWrites = append(g.lifetimeWrites, callerLifetimeWrite{source(owner), value, whole})
				}
			}
			return true
		})
	}
	// Инициализаторы пакета находятся вне тел функций. Все они
	// вычисляются до зарегистрированного RPC, включая инициализаторы пустого имени.
	for _, sp := range g.p.pkgs {
		for _, file := range sp.files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.FuncDecl, *ast.FuncLit:
					return false
				}
				if call, ok := n.(*ast.CallExpr); ok && !sp.info.Types[call.Fun].IsType() {
					g.lifetimeCalls = append(g.lifetimeCalls, callSrc{pkg: sp, call: call})
				}
				return true
			})
		}
	}
	// Тела приходят из map; порядок раннего выхода задаём исходником.
	// Все callSrc и их кратность сохраняются. Физические координаты
	// не зависят от директив //line и порядка файлов внутри FileSet.
	slices.SortFunc(g.lifetimeCalls, func(a, b callSrc) int {
		if order := cmp.Compare(a.pkg.path, b.pkg.path); order != 0 {
			return order
		}
		ap := g.p.fset.PositionFor(a.call.Pos(), false)
		bp := g.p.fset.PositionFor(b.call.Pos(), false)
		if order := cmp.Compare(ap.Filename, bp.Filename); order != 0 {
			return order
		}
		if order := cmp.Compare(ap.Offset, bp.Offset); order != 0 {
			return order
		}
		// У factory()() оба вызова имеют один Pos, но разные концы.
		return cmp.Compare(a.call.End()-a.call.Pos(), b.call.End()-b.call.Pos())
	})
	g.orderCallerLifetimeWrites()
}

// Сбор тел идёт из map. Фиксируем порядок всех записей до назначения ordinal
// в indexCallerLifetimeWrites; сохраняем точные источники и их кратность.
// Физические координаты не зависят от //line и порядка файлов в FileSet.
func (g *callerGraph) orderCallerLifetimeWrites() {
	compareSource := func(a, b valueSrc) int {
		if order := cmp.Compare(a.pkg.path, b.pkg.path); order != 0 {
			return order
		}
		position := func(expr ast.Expr) (token.Position, int) {
			if expr == nil {
				return token.Position{Offset: -1}, 0
			}
			return g.p.fset.PositionFor(expr.Pos(), false), int(expr.End() - expr.Pos())
		}
		ap, al := position(a.expr)
		bp, bl := position(b.expr)
		if order := cmp.Compare(ap.Filename, bp.Filename); order != 0 {
			return order
		}
		if order := cmp.Compare(ap.Offset, bp.Offset); order != 0 {
			return order
		}
		if order := cmp.Compare(al, bl); order != 0 {
			return order
		}
		return cmp.Compare(a.tuple, b.tuple)
	}
	slices.SortStableFunc(g.lifetimeWrites, func(a, b callerLifetimeWrite) int {
		if order := compareSource(a.owner, b.owner); order != 0 {
			return order
		}
		if order := compareSource(a.value, b.value); order != 0 {
			return order
		}
		if a.whole == b.whole {
			return 0
		}
		if a.whole {
			return 1
		}
		return -1
	})
}

// Это доказательство не предоставляет цели вызовов. Оно лишь отвергает начальное значение,
// если достижимый эффект может адресовать его выделение памяти. Явные поля конструктора
// и пропущенные нулевые поля проходят через один и тот же барьер.
func (g *callerGraph) callerLifetimeUnknown(src valueSrc, fields ...*types.Var) bool {
	if g.semanticOverflow {
		return true
	}
	if g.lifetimeScanning {
		// Начальное происхождение имеет отдельный кеш и не заменяет
		// это доказательство времени жизни. Полные ответы сохраняют эту границу.
		g.noteCallerInitialBoundary()
		return g.semanticOverflow
	}
	epoch, cuts, skips := g.bindingEpoch, g.resolveCuts, g.initialSkips
	g.work.LifetimeProofs++
	g.lifetimeScanning = true
	defer func() { g.lifetimeScanning = false }()
	g.closeCallerEffects()
	if g.effectIncomplete {
		return true
	}
	objects, unknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
	if unknown {
		return true
	}
	for object := range objects {
		probe := callerLifetimeProbe{g: g, want: object, seen: map[callerResolveKey]bool{}, objects: map[callerObjectKey]bool{}}
		if len(fields) > 0 {
			probe.field = fields[0].Origin()
		}
		for _, write := range g.lifetimeWrites {
			if write.whole && g.callerLifetimeEffectPossible(write.owner) && probe.contains(write.owner) && !probe.separateScalarStore(write.owner, src, objects) {
				return true
			}
		}
		for _, site := range g.lifetimeCalls {
			if !g.callerEffectSiteActive(site) {
				continue
			}
			if g.callerLifetimeLocal(site) {
				continue
			}
			// Выражение функции несёт связанного получателя или замыкание;
			// проверка лишь аргументов пропускает мутацию получателя без аргументов.
			if probe.opaqueCalleeContains(site) {
				return true
			}
			for _, arg := range site.call.Args {
				if probe.contains(valueSrc{pkg: site.pkg, fk: site.fk, expr: arg, tuple: -1}) {
					return true
				}
			}
		}
	}
	// Только нормальное завершение внешнего барьера поглощает свои начальные
	// границы. Настоящие cuts, смена эпохи и незавершённость остаются видимыми.
	if !g.semanticOverflow && (g.ctx == nil || g.ctx.Err() == nil) && g.bindingEpoch == epoch && !g.effectIncomplete && g.resolveCuts-cuts == g.initialSkips-skips {
		g.addCallerSemantic(0, 0, 0, g.initialSkips-skips)
	}
	return g.semanticOverflow
}

func (g *callerGraph) callerLifetimeLocal(site callSrc) bool {
	if id, ok := ast.Unparen(site.call.Fun).(*ast.Ident); ok {
		if builtin, ok := site.pkg.info.Uses[id].(*types.Builtin); ok {
			// copy может перезаписывать через алиас среза; в отличие от append, его
			// содержимое не представлено рёбрами записей элементов выше.
			return builtin.Name() != "copy"
		}
	}
	if g.callerNilInterfaceCall(site) {
		return true
	}
	if fn := callerFunction(site.pkg, site.call.Fun); fn != nil && !isIfaceMethod(fn) {
		_, local := g.bodies[callerNode{fn: fn.Origin()}]
		return local && (fn.Pkg() == nil || !g.safeExternal[fn.Pkg().Path()])
	}
	targets, unknown := g.resolve(valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Fun, tuple: -1}, false, map[callerResolveKey]bool{})
	if unknown || len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if target.nilValue {
			continue // доказанно nil-функция не может выполнить мутацию
		}
		if target.foreign || target.node == (callerNode{}) {
			return false
		}
		if _, local := g.bodies[target.node]; !local {
			return false
		}
	}
	return g.callerLifetimeCallableStable(valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Fun, tuple: -1}, map[callerResolveKey]bool{})
}

type callerLifetimeProbe struct {
	g       *callerGraph
	want    callerObjectKey
	field   *types.Var
	seen    map[callerResolveKey]bool
	objects map[callerObjectKey]bool
	steps   int
}

// Границы влияют лишь на точность: исчерпание даёт UNKNOWN, а не пустое доказательство.
const callerLifetimeStepLimit = 16384

func (p *callerLifetimeProbe) contains(src valueSrc) bool {
	p.steps++
	p.g.work.LifetimeProbeSteps++
	if p.steps > callerLifetimeStepLimit || src.pkg == nil || src.expr == nil {
		return true
	}
	if p.g.ctx != nil && p.g.ctx.Err() != nil {
		return true
	}
	e := ast.Unparen(src.expr)
	if callerNil(src.pkg, e) {
		return false
	}
	key := callerResolveKeyFor(src, true)
	if p.seen[key] {
		// Это достижимость, а не независимое доказательство nil: внешний
		// кадр всё ещё посещает каждое исходящее ребро этого источника.
		return false
	}
	p.seen[key] = true
	defer delete(p.seen, key)
	through := func(expr ast.Expr) bool {
		ref := src
		ref.expr, ref.tuple = expr, -1
		return p.contains(ref)
	}
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return p.addressContains(src, x.X)
		}
		return through(x.X)
	case *ast.StarExpr:
		return through(x.X)
	case *ast.TypeAssertExpr:
		return through(x.X)
	case *ast.SliceExpr:
		return through(x.X)
	case *ast.IndexExpr:
		if fn := callerFunction(src.pkg, x); fn != nil {
			return through(x.X)
		}
	case *ast.IndexListExpr:
		return through(x.X)
	case *ast.CallExpr:
		if src.pkg.info.Types[x.Fun].IsType() && len(x.Args) == 1 {
			return through(x.Args[0])
		}
		if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok {
			if builtin, ok := src.pkg.info.Uses[id].(*types.Builtin); ok && builtin.Name() == "append" {
				// Достижимость включает прежний backing и все добавляемые значения,
				// в том числе содержимое spread. После них сохраняем обычный обход
				// объектов результата: поздние записи через алиасы тоже существенны.
				for _, arg := range x.Args {
					if through(arg) {
						return true
					}
				}
			}
		}
	case *ast.FuncLit:
		return p.captures(src.pkg, x, x.Body)
	case *ast.SelectorExpr:
		if selection := src.pkg.info.Selections[x]; selection != nil {
			if selection.Kind() == types.MethodVal {
				method, _ := selection.Obj().(*types.Func)
				if method != nil {
					signature, _ := method.Type().(*types.Signature)
					if signature != nil && signature.Recv() != nil {
						_, pointerMethod := signature.Recv().Type().Underlying().(*types.Pointer)
						receiverType := src.pkg.info.TypeOf(x.X)
						if pointerMethod && receiverType != nil {
							if _, pointerValue := receiverType.Underlying().(*types.Pointer); !pointerValue {
								// Go захватывает &receiver для метода адресуемого значения
								// с получателем-указателем, включая связанные значения.
								return p.addressContains(src, x.X)
							}
						}
					}
				}
				return through(x.X)
			}
			if selection.Kind() == types.FieldVal {
				base := src
				base.expr = x.X
				refs, unknown := p.g.embeddedCallerSources(base, fieldPath(selection), map[callerFieldKey]bool{})
				if unknown {
					return true
				}
				for _, ref := range refs {
					if p.contains(ref) {
						return true
					}
				}
				return false
			}
		}
	}
	if fn := callerFunction(src.pkg, e); fn != nil {
		// Упакованный именованный callback может достичь состояния пакета без лексического
		// замыкания или аргумента. Проверяем захваты и локальные вспомогательные функции.
		if body, ok := p.g.bodies[callerNode{fn: fn.Origin()}]; ok {
			return p.captures(body.sp, body.node, body.node)
		}
		return false
	}
	if variable := callerVariable(src.pkg, e); variable != nil {
		if _, ok := e.(*ast.Ident); ok {
			if p.want.zero == variable.Origin() {
				return true
			}
			refs := p.g.sources(variable)
			if len(refs) == 0 {
				if _, zero := p.g.zeroVars[variable.Origin()]; zero || p.g.emptyVariadic[variable.Origin()] {
					return p.objectWrites(callerObjectKey{pkg: src.pkg, zero: variable.Origin()})
				}
				return p.typeMayContain(src.pkg.info.TypeOf(e))
			}
			for _, ref := range refs {
				if p.contains(ref) {
					return true
				}
			}
			// Каждый источник выделения выше также обходит записи через его
			// алиасы, включая записи элементов, отсутствующие у этой переменной.
			return false
		}
	}
	if !p.typeMayContain(src.pkg.info.TypeOf(e)) {
		return false
	}
	objects, unknown := p.g.callerObjects(src, map[callerObjectSourceID]bool{})
	if unknown {
		return true
	}
	for object := range objects {
		// callerObjects возвращает адресуемые поля и загруженные значения.
		// Чтение интерфейсного поля не раскрывает содержащую его память;
		// addressContains отдельно обрабатывает явный &field.
		if object.field != nil {
			continue
		}
		if object == p.want {
			return true
		}
		if p.objects[object] {
			continue
		}
		p.objects[object] = true
		if p.objectWrites(object) {
			return true
		}
		if lit, ok := object.expr.(*ast.CompositeLit); ok {
			_, isMap := object.pkg.info.TypeOf(lit).Underlying().(*types.Map)
			for _, elt := range lit.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if isMap && p.contains(valueSrc{pkg: object.pkg, expr: kv.Key, tuple: -1}) {
						return true
					}
					elt = kv.Value
				}
				if p.contains(valueSrc{pkg: object.pkg, expr: elt, tuple: -1}) {
					return true
				}
			}
		}
		delete(p.objects, object)
	}
	return false
}

func (p *callerLifetimeProbe) opaqueCalleeContains(site callSrc) bool {
	src := valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Fun, tuple: -1}
	if sel, ok := ast.Unparen(src.expr).(*ast.SelectorExpr); ok {
		s := src.pkg.info.Selections[sel]
		if s != nil && s.Kind() == types.MethodVal && !s.Indirect() && len(s.Index()) == 1 {
			lit, layout := callerUnaddressableStructLiteral(src.pkg, sel.X)
			sig, _ := s.Obj().Type().(*types.Signature)
			if layout != nil && sig != nil && sig.Recv() != nil && types.Identical(src.pkg.info.TypeOf(sel.X), sig.Recv().Type()) {
				return p.containsDirectReceiverValue(src, lit, layout)
			}
		}
	}
	return p.contains(src)
}

func callerUnaddressableStructLiteral(sp *surfaceSrcPkg, expr ast.Expr) (*ast.CompositeLit, *types.Struct) {
	lit, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return nil, nil
	}
	value := sp.info.Types[lit]
	if value.Type == nil || value.Addressable() {
		return nil, nil
	}
	layout, _ := value.Type.Underlying().(*types.Struct)
	return lit, layout
}

// Прямой T{...}.M копирует временное значение. Другие записи не могут
// получить адрес этой ячейки. Через её поля по-прежнему доступны общие
// срезы, указатели, замыкания и прочие значения из инициализаторов.
func (p *callerLifetimeProbe) containsDirectReceiverValue(src valueSrc, lit *ast.CompositeLit, layout *types.Struct) bool {
	p.steps++
	p.g.work.LifetimeProbeSteps++
	if p.steps > callerLifetimeStepLimit || p.g.semanticOverflow || p.g.ctx != nil && p.g.ctx.Err() != nil ||
		(p.want.pkg == src.pkg && p.want.expr == lit) {
		return true
	}
	for i, elt := range lit.Elts {
		var field *types.Var
		if kv, keyed := elt.(*ast.KeyValueExpr); keyed {
			if name, ok := kv.Key.(*ast.Ident); ok {
				field, _ = src.pkg.info.Uses[name].(*types.Var)
			}
			elt = kv.Value
		} else if i < layout.NumFields() {
			field = layout.Field(i)
		}
		next := src
		next.expr, next.tuple = elt, -1
		// Дочерний struct копируется той же инициализацией. Для интерфейса
		// и для каждого другого выражения остаётся штатный обход.
		nested, shape := callerUnaddressableStructLiteral(src.pkg, elt)
		if shape != nil && field != nil && field.IsField() && types.Identical(field.Type(), src.pkg.info.TypeOf(elt)) {
			if p.containsDirectReceiverValue(next, nested, shape) {
				return true
			}
		} else if p.contains(next) {
			return true
		}
	}
	return false
}

func (p *callerLifetimeProbe) objectWrites(object callerObjectKey) bool {
	var adjacentOwners callerContainerObjectReuse
	sliceAllocation := callerLiteralSliceAllocation(object)
	for _, write := range p.g.lifetimeWrites {
		if !p.g.callerLifetimeEffectPossible(write.owner) {
			adjacentOwners = callerContainerObjectReuse{}
			continue
		}
		if sliceAllocation && p.separateClosedScalarSliceStore(write) {
			adjacentOwners = callerContainerObjectReuse{}
			continue
		}
		if sliceAllocation && p.separateUnpublishedMapWrite(write) {
			p.g.work.UnpublishedMapWriteSkips++
			adjacentOwners = callerContainerObjectReuse{}
			continue
		}
		var owners map[callerObjectKey]bool
		var unknown bool
		if callerFreshReplayContext(p.g.ctx) {
			owners, unknown = adjacentOwners.objects(p.g, write.owner)
		} else {
			adjacentOwners = callerContainerObjectReuse{}
			owners, unknown = p.g.callerObjects(write.owner, map[callerObjectSourceID]bool{})
		}
		if unknown && !owners[object] && (p.separateLocalAppendBacking(write, object) || p.separateClosedMapHandle(write, object)) {
			continue
		}
		if unknown || owners[object] {
			// Обход значения может изменить граф и открытые зависимости.
			adjacentOwners = callerContainerObjectReuse{}
			// X в range — источник итераций. Он может быть, например,
			// функцией, передающей значение через yield. После совпадения
			// владельца сохраняем UNKNOWN для такого значения.
			if write.value.rangeKey || write.value.rangeVal || p.contains(write.value) {
				return true
			}
		}
	}
	var typ types.Type
	if object.field != nil {
		typ = object.field.Type()
	} else if object.zero != nil {
		typ = object.zero.Type()
	} else if object.expr != nil {
		typ = object.pkg.info.TypeOf(object.expr)
	}
	if typ == nil {
		return true
	}
	if ptr, ok := typ.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	st, ok := typ.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		for _, write := range p.g.mutations[st.Field(i).Origin()] {
			if !p.g.callerLifetimeEffectPossible(write.owner) {
				continue
			}
			owners := []valueSrc{write.owner}
			unknown := false
			if len(write.path) > 0 {
				owners, unknown = p.g.embeddedCallerSources(write.owner, write.path, map[callerFieldKey]bool{})
			}
			matched := unknown
			for _, owner := range owners {
				objects, u := p.g.callerObjects(owner, map[callerObjectSourceID]bool{})
				matched = matched || u || objects[object]
			}
			if matched && p.contains(write.value) {
				return true
			}
		}
	}
	return false
}

func (p *callerLifetimeProbe) captures(sp *surfaceSrcPkg, scope, body ast.Node) bool {
	contains := false
	ast.Inspect(body, func(n ast.Node) bool {
		if contains {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && !sp.info.Types[call.Fun].IsType() {
			contains = p.contains(valueSrc{pkg: sp, expr: call.Fun, tuple: -1})
			if contains {
				return false
			}
		}
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := sp.info.Uses[id].(*types.Var)
		if !ok || v.IsField() || v.Pos() >= scope.Pos() && v.Pos() < scope.End() {
			return true
		}
		if parameter, ok := p.g.parameters[v.Origin()]; ok {
			if owner, ok := p.g.bodies[callerNode{fn: parameter.fk.fn, lit: parameter.fk.lit}]; ok && owner.node == body {
				return true
			}
		}
		contains = p.contains(valueSrc{pkg: sp, expr: id, tuple: -1})
		return !contains
	})
	return contains
}

func (p *callerLifetimeProbe) typeMayContain(typ types.Type) bool {
	var want types.Type
	if p.want.field != nil {
		want = p.want.field.Type()
	} else if p.want.zero != nil {
		want = p.want.zero.Type()
	} else if p.want.expr != nil {
		want = p.want.pkg.info.TypeOf(p.want.expr)
	}
	if want == nil {
		return true
	}
	return callerLifetimeTypeContains(typ, want, map[types.Type]bool{})
}

func callerLifetimeTypeContains(typ, want types.Type, seen map[types.Type]bool) bool {
	if typ == nil || types.Identical(typ, want) {
		return true
	}
	if seen[typ] {
		return false
	}
	seen[typ] = true
	switch t := typ.Underlying().(type) {
	case *types.Basic:
		return t.Kind() == types.UnsafePointer || t.Kind() == types.Uintptr
	case *types.Interface, *types.Signature, *types.TypeParam:
		return true
	case *types.Pointer:
		return callerLifetimeTypeContains(t.Elem(), want, seen)
	case *types.Slice:
		return callerLifetimeTypeContains(t.Elem(), want, seen)
	case *types.Array:
		return callerLifetimeTypeContains(t.Elem(), want, seen)
	case *types.Map:
		return callerLifetimeTypeContains(t.Key(), want, seen) || callerLifetimeTypeContains(t.Elem(), want, seen)
	case *types.Chan:
		return callerLifetimeTypeContains(t.Elem(), want, seen)
	case *types.Struct:
		for i := 0; i < t.NumFields(); i++ {
			if callerLifetimeTypeContains(t.Field(i).Type(), want, seen) {
				return true
			}
		}
	}
	return false
}

// Строим только после сбора всех тел. Сохраняем все внешние тела,
// включая не ближайшие: достижение любого удовлетворяет прежнему предикату.
// Позиции принадлежат неизменяемой разобранной программе; наложения строят новый граф.
func (g *callerGraph) indexCallerClosureOwners() {
	type extent struct {
		node       callerNode
		start, end token.Pos
	}
	bodies := make([]extent, 0, len(g.bodies))
	for node, body := range g.bodies {
		bodies = append(bodies, extent{node, body.node.Pos(), body.node.End()})
	}
	g.closureOwners = make(map[*ast.FuncLit][]callerNode)
	for node := range g.bodies {
		lit := node.lit
		if lit == nil {
			continue
		}
		start, end := lit.Pos(), lit.End()
		// Явная пустая запись отличает известные литералы без владельца от
		// неизвестных, для которых обязателен прежний полный обход.
		g.closureOwners[lit] = nil
		for _, body := range bodies {
			if body.node.lit != lit && body.start <= start && body.end >= end {
				g.closureOwners[lit] = append(g.closureOwners[lit], body.node)
			}
		}
	}
}

// Тело возвращённой опции не имеет выделения до достижения внешней функции.
// Литерал, созданный в достигнутом теле, остаётся возможным эффектом
// ещё до обнаружения вызова, в частности после упаковки в any.
func (g *callerGraph) callerClosureCreated(lit *ast.FuncLit) bool {
	g.work.ClosureOwnershipQueries++
	if g.called[callerNode{lit: lit}] {
		return true
	}
	if owners, known := g.closureOwners[lit]; known {
		for _, owner := range owners {
			g.work.ClosureOwnershipCandidates++
			if g.called[owner] {
				return true
			}
		}
		return false
	}
	// Графы, созданные вручную, и неизвестные идентичности литералов сохраняют
	// прежний предикат точно; отсутствие записи индекса не доказывает false.
	g.work.ClosureOwnershipFallbacks++
	for node, body := range g.bodies {
		g.work.ClosureOwnershipCandidates++
		if node.lit == lit || body.node.Pos() > lit.Pos() || body.node.End() < lit.End() {
			continue
		}
		if g.called[node] {
			return true
		}
	}
	return false
}

func (g *callerGraph) callerLifetimeEffectPossible(src valueSrc) bool {
	if src.fk.fn != nil {
		if pkg := src.fk.fn.Pkg(); pkg != nil && g.safeExternal[pkg.Path()] {
			return false // внешние тела представлены непрозрачным вызовом
		}
		return g.called[callerNode{fn: src.fk.fn}]
	}
	if src.fk.lit != nil {
		return g.callerClosureCreated(src.fk.lit)
	}
	return true
}

// Разрешение вызываемого значения при активном барьере времени жизни видит его
// начальные источники. Этот результат доказывает локальный эффект лишь тогда,
// когда само вызываемое значение не имеет изменяемой косвенности. Поля и
// индексируемые таблицы callback требуют своего доказательства эффекта и здесь непрозрачны.
func (g *callerGraph) callerLifetimeCallableStable(src valueSrc, seen map[callerResolveKey]bool) bool {
	if src.pkg == nil || src.expr == nil {
		return false
	}
	key := callerResolveKeyFor(src, false)
	if seen[key] {
		return false
	}
	seen[key] = true
	defer delete(seen, key)
	e := ast.Unparen(src.expr)
	if callerNil(src.pkg, e) {
		return true
	}
	if _, literal := e.(*ast.FuncLit); literal {
		return true
	}
	if fn := callerFunction(src.pkg, e); fn != nil {
		if !isIfaceMethod(fn) {
			return true
		}
		if sel, ok := e.(*ast.SelectorExpr); ok {
			selection := src.pkg.info.Selections[sel]
			if selection != nil && selection.Kind() == types.MethodVal && len(selection.Index()) == 1 {
				src.expr = sel.X
				return g.callerLifetimeReceiverStable(src, seen)
			}
		}
		return false
	}
	switch expr := e.(type) {
	case *ast.Ident:
		v := callerVariable(src.pkg, expr)
		if v == nil || g.index.addrTaken[v] {
			return false
		}
		switch v.Type().Underlying().(type) {
		case *types.Signature, *types.Interface:
		default:
			if !g.callerLifetimePrivateVariadic(v) {
				return false
			}
		}
		refs := g.sources(v)
		if len(refs) == 0 {
			_, zero := g.zeroVars[v.Origin()]
			return zero || g.emptyVariadic[v.Origin()]
		}
		for _, ref := range refs {
			if !g.callerLifetimeCallableStable(ref, seen) {
				return false
			}
		}
		return true
	case *ast.TypeAssertExpr:
		src.expr = expr.X
		return g.callerLifetimeCallableStable(src, seen)
	case *ast.CallExpr:
		if src.pkg.info.Types[expr.Fun].IsType() && len(expr.Args) == 1 {
			src.expr = expr.Args[0]
			return g.callerLifetimeCallableStable(src, seen)
		}
		fn := callerFunction(src.pkg, expr.Fun)
		if fn == nil || isIfaceMethod(fn) || fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] {
			return false
		}
		index := src.tuple
		if index < 0 {
			index = 0
		}
		results := g.index.returns[fkey{fn: fn.Origin()}]
		if index >= len(results) || len(results[index]) == 0 {
			return false
		}
		for _, ref := range results[index] {
			if !g.callerLifetimeCallableStable(ref, seen) {
				return false
			}
		}
		return true
	}
	return false
}

// Позиционные вариадические callback образуют частный срез, только если вызываемый код
// использует его исключительно как операнд range. Аргументы с многоточием и любой выход
// среза наружу или запись в него этим доказательством не покрываются.
func (g *callerGraph) callerLifetimePrivateVariadic(v *types.Var) bool {
	param, ok := g.parameters[v.Origin()]
	if !ok || param.fk.fn == nil {
		return false
	}
	sig := param.fk.fn.Type().(*types.Signature)
	if !sig.Variadic() || param.index != sig.Params().Len()-1 {
		return false
	}
	for _, ref := range g.sources(v) {
		if ref.pkg == nil || ref.expr == nil {
			return false
		}
		typ := ref.pkg.info.TypeOf(ref.expr)
		if typ == nil {
			return false
		}
		if _, function := typ.Underlying().(*types.Signature); !function {
			return false
		}
	}
	body, ok := g.bodies[callerNode{fn: param.fk.fn}]
	if !ok {
		return false
	}
	ranges := map[ast.Expr]bool{}
	ast.Inspect(body.node, func(n ast.Node) bool {
		if stmt, ok := n.(*ast.RangeStmt); ok {
			ranges[ast.Unparen(stmt.X)] = true
		}
		return true
	})
	stable := true
	ast.Inspect(body.node, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && body.sp.info.Uses[id] == v && !ranges[id] {
			stable = false
		}
		return stable
	})
	return stable
}

// Адрес обозначает память. Загрузка прежнего интерфейсного значения отбросила бы
// именно то место, которое может заменить Assign(*Reader, Reader).
func (p *callerLifetimeProbe) addressContains(src valueSrc, operand ast.Expr) bool {
	src.expr = operand
	if selection, ok := ast.Unparen(operand).(*ast.SelectorExpr); ok {
		if selected := src.pkg.info.Selections[selection]; selected != nil && selected.Kind() == types.FieldVal {
			objects, unknown := p.g.callerObjects(src, map[callerObjectSourceID]bool{})
			if unknown {
				return true
			}
			want := p.want
			if p.field != nil {
				want.field = p.field
			}
			if objects[want] {
				return true
			}
			// Адресация другой ячейки не может заменить эту ячейку. Её значение
			// всё ещё может содержать указатель на другое запрашиваемое выделение.
			return p.contains(src)
		}
	}
	return p.contains(src)
}

// Источники чтения элемента включают все записи через алиасы той же
// памяти. Одних рёбер вложенности недостаточно для прямого чтения.
func (g *callerGraph) callerContainerSources(src valueSrc, fields []*types.Var, seen map[callerFieldKey]bool) (refs []valueSrc, unknown bool) {
	g.work.ContainerCalls++
	if g.semanticOverflow {
		return nil, true
	}
	if src.pkg == nil || src.expr == nil {
		return nil, false
	}
	typ := callerContainerType(src.pkg.info.TypeOf(src.expr))
	if typ == nil {
		return nil, true
	}
	switch typ.Underlying().(type) {
	case *types.Slice, *types.Array, *types.Map:
	default:
		return nil, false
	}
	key := callerResolveKeyFor(src, true)
	if g.containerScanning[key] {
		g.addCallerSemantic(1, 0, 0, 0)
		return nil, g.semanticOverflow
	}
	if g.containerScanning == nil {
		g.containerScanning = map[callerResolveKey]bool{}
	}
	g.containerScanning[key] = true
	defer delete(g.containerScanning, key)
	before := CallerContainerCost{Scanned: g.work.ContainerScannedWrites, Active: g.work.ContainerActiveWrites, Compatible: g.work.ContainerTypeCompatibleWrites, Matched: g.work.ContainerMatchedWrites}
	defer func() {
		if g.observer != nil {
			g.observeContainerCost(src, before)
		}
	}()
	ctx := g.ctx
	if memo := g.containerInactive; memo != nil && memo.ctx != ctx {
		g.containerInactive = nil
	}
	objects, u := g.callerContainerObjects(src, key, callerContainerInput)
	unknown = u
	candidates, indexed := g.callerContainerWriteCandidates(typ)
	g.work.ContainerOriginalWrites += len(g.lifetimeWrites)
	count := len(g.lifetimeWrites)
	if indexed {
		count = len(candidates)
		g.work.ContainerExcludedWrites += len(g.lifetimeWrites) - count
	} else {
		g.work.ContainerIndexFallbacks++
	}
	var ownerReuse callerContainerObjectReuse
	var scan callerContainerScan
	if indexed {
		scan = g.callerContainerActiveScan(ctx, typ, candidates)
	}
	for i, ok := scan.take(g, count); ok; i, ok = scan.take(g, count) {
		ordinal := i
		if indexed {
			ordinal = candidates[i]
		}
		write := g.lifetimeWrites[ordinal]
		g.work.ContainerScannedWrites++
		if write.whole || !g.callerLifetimeEffectPossible(write.owner) {
			continue
		}
		g.work.ContainerActiveWrites++
		var ownerType types.Type
		if indexed {
			ownerType = g.lifetimeWriteIndex.entries[ordinal].ownerType
		} else {
			ownerType = callerContainerType(write.owner.pkg.info.TypeOf(write.owner.expr))
			if ownerType != nil && !types.Identical(ownerType.Underlying(), typ.Underlying()) && !g.hasCallerTypeParam(ownerType) && !g.hasCallerTypeParam(typ) {
				if g.observer != nil {
					g.observeContainerPair(ownerType, typ)
				}
				continue
			}
		}
		if g.observer != nil {
			g.observeContainerPair(ownerType, typ)
		}
		g.work.ContainerTypeCompatibleWrites++
		owners, u := ownerReuse.writeObjects(g, write.owner, true)
		unknown = unknown || u
		matched := false
		for object := range owners {
			matched = matched || objects[object]
		}
		if matched {
			g.work.ContainerMatchedWrites++
			// Обход значения может связать вызовы или опубликовать новые снимки полей.
			// Локальный сертификат никогда не пересекает этот переход.
			ownerReuse = callerContainerObjectReuse{}
			values, u := g.embeddedCallerSources(write.value, fields, seen)
			refs = append(refs, values...)
			unknown = unknown || u
		}
	}
	return refs, unknown
}

// Эффектам нужно транзитивное замыкание локальных вызовов независимо от обходчика
// READ: конструкторы и функции запуска могут исполняться до корня RPC.
// Связываются только реальные аргументы; READ производителей в отчёт не добавляются.
func (g *callerGraph) closeCallerEffects() {
	g.work.EffectClosureCalls++
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		g.effectIncomplete = true
		return
	}
	if g.effectScanning {
		return
	}
	g.effectScanning = true
	defer func() { g.effectScanning = false }()
	for _, node := range g.startup {
		body := g.bodies[node]
		if !g.safeExternal[body.sp.path] {
			g.markCallerCalled(node)
		}
	}
	if g.effectEpoch == g.bindingEpoch {
		return
	}
	g.effectIncomplete = true
	for round := 0; round < CeremonySolveRoundLimit; round++ {
		g.work.EffectClosureRounds++
		epoch := g.bindingEpoch
		for _, site := range g.lifetimeCalls {
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return
			}
			g.work.EffectClosureSites++
			if !g.callerEffectSiteActive(site) || g.safeExternal[site.pkg.path] {
				continue
			}
			g.work.EffectClosureActiveSites++
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return
			}
			if id, ok := ast.Unparen(site.call.Fun).(*ast.Ident); ok {
				if _, builtin := site.pkg.info.Uses[id].(*types.Builtin); builtin {
					continue
				}
			}
			if g.callerNilInterfaceCall(site) {
				continue
			}
			targets, _ := g.resolve(valueSrc{pkg: site.pkg, fk: site.fk, expr: site.call.Fun, tuple: -1}, false, map[callerResolveKey]bool{})
			if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
				return
			}
			for _, target := range targets {
				if target.node == (callerNode{}) || target.foreign {
					continue
				}
				g.bindCaller(site.pkg, callerNode{fn: site.fk.fn, lit: site.fk.lit}, site.call, target.node)
				if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
					return
				}
			}
		}
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return
		}
		if epoch == g.bindingEpoch {
			g.effectEpoch, g.effectIncomplete = epoch, false
			return
		}
	}
}

func (g *callerGraph) callerEffectSiteActive(site callSrc) bool {
	return site.fk == (fkey{}) || g.called[callerNode{fn: site.fk.fn, lit: site.fk.lit}]
}

// Вызов метода nil-интерфейса паникует до входа в вызываемую функцию. Это намеренно
// не распространяется на nil-получатели-указатели: тела их методов Go могут исполняться.
func (g *callerGraph) callerNilInterfaceCall(site callSrc) bool {
	sel, ok := ast.Unparen(site.call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	selection := site.pkg.info.Selections[sel]
	if selection == nil || selection.Kind() != types.MethodVal {
		return false
	}
	typ := site.pkg.info.TypeOf(sel.X)
	if typ == nil {
		return false
	}
	if _, iface := typ.Underlying().(*types.Interface); !iface {
		return false
	}
	receiver := valueSrc{pkg: site.pkg, fk: site.fk, expr: sel.X, tuple: -1}
	if !g.callerLifetimeCallableStable(receiver, map[callerResolveKey]bool{}) {
		return false
	}
	values, unknown := g.resolve(receiver, true, map[callerResolveKey]bool{})
	if unknown || len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !value.nilValue {
			return false
		}
	}
	return true
}

func callerContainerType(typ types.Type) types.Type {
	if typ == nil {
		return nil
	}
	if ptr, ok := typ.Underlying().(*types.Pointer); ok {
		if _, array := ptr.Elem().Underlying().(*types.Array); array {
			return ptr.Elem()
		}
	}
	return typ
}

// Конкретный динамический тип получателя нельзя заменить мутацией его полей.
// Ячейку интерфейса можно заменить, поэтому вся цепочка её источников должна
// быть без взятия адреса и не проходить через другое изменяемое интерфейсное поле.
func (g *callerGraph) callerLifetimeReceiverStable(src valueSrc, seen map[callerResolveKey]bool) bool {
	if src.pkg == nil || src.expr == nil {
		return false
	}
	key := callerResolveKeyFor(src, true)
	if seen[key] {
		return false
	}
	seen[key] = true
	defer delete(seen, key)
	e := ast.Unparen(src.expr)
	if callerNil(src.pkg, e) {
		return true
	}
	typ := src.pkg.info.TypeOf(e)
	if typ == nil {
		return false
	}
	if _, iface := typ.Underlying().(*types.Interface); !iface {
		return true
	}
	if _, ident := e.(*ast.Ident); ident {
		v := callerVariable(src.pkg, e)
		if v == nil || g.index.addrTaken[v] {
			return false
		}
		refs := g.sources(v)
		if len(refs) == 0 {
			_, zero := g.zeroVars[v.Origin()]
			return zero
		}
		for _, ref := range refs {
			if !g.callerLifetimeReceiverStable(ref, seen) {
				return false
			}
		}
		return true
	}
	if call, ok := e.(*ast.CallExpr); ok && src.pkg.info.Types[call.Fun].IsType() && len(call.Args) == 1 {
		src.expr = call.Args[0]
		return g.callerLifetimeReceiverStable(src, seen)
	}
	return false
}

// Значение функции или интерфейса копируется при чтении. Без адреса ячейки
// переменной непрозрачный получатель не может заменить её динамическое значение.
// Все прямые присваивания и все входящие источники всё равно разрешаются;
// источник из изменяемого поля сохраняет барьер времени жизни этого поля.
func (g *callerGraph) callerVariableLifetimeUnknown(src valueSrc, variable *types.Var) bool {
	if g.semanticOverflow {
		return true
	}
	if !g.index.addrTaken[variable.Origin()] {
		switch variable.Type().Underlying().(type) {
		case *types.Interface, *types.Signature:
			return false
		}
	}
	return g.callerLifetimeUnknown(src)
}

// Тело только из *destination = value переносит callback в память вызывающего;
// передача не исполняет его. Этот контракт, выведенный из исходного кода,
// подавляет лишь вымышленный немедленный READ. Запись назначения
// по-прежнему участвует в обычном барьере времени жизни непрозрачного вызова.
func (g *callerGraph) callerArgumentStoredWithoutCall(sp *surfaceSrcPkg, call *ast.CallExpr, index int) bool {
	fn := callerFunction(sp, call.Fun)
	if fn == nil || isIfaceMethod(fn) {
		return false
	}
	fn = fn.Origin()
	sig := fn.Type().(*types.Signature)
	if sig.Variadic() || index >= sig.Params().Len() || len(call.Args) != sig.Params().Len() {
		return false
	}
	body, ok := g.bodies[callerNode{fn: fn}]
	if !ok {
		return false
	}
	block, ok := body.node.(*ast.BlockStmt)
	if !ok || len(block.List) != 1 {
		return false
	}
	assign, ok := block.List[0].(*ast.AssignStmt)
	if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return false
	}
	value, ok := ast.Unparen(assign.Rhs[0]).(*ast.Ident)
	if !ok || callerVariable(body.sp, value) != sig.Params().At(index) {
		return false
	}
	deref, ok := ast.Unparen(assign.Lhs[0]).(*ast.StarExpr)
	if !ok {
		return false
	}
	destination, ok := ast.Unparen(deref.X).(*ast.Ident)
	if !ok {
		return false
	}
	variable := callerVariable(body.sp, destination)
	for i := 0; i < sig.Params().Len(); i++ {
		if variable == sig.Params().At(i) {
			pointer, ok := variable.Type().Underlying().(*types.Pointer)
			return ok && types.Identical(pointer.Elem(), sig.Params().At(index).Type())
		}
	}
	return false
}

func (g *callerGraph) noteCallerInitialBoundary() {
	g.addCallerSemantic(1, 1, 0, 0)
	g.work.LifetimeInitialSkips++
}
