// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_flow.go — КУДА ТЕЧЁТ обработчик: прослеживание значений от
// места рождения мультиплексора до объявления поверхности.
//
// # Модель
//
// Абстрактное значение — место рождения: вызов конструктора мультиплексора,
// литерал структуры, литерал функции, функция, взятая значением. Значения
// текут по присваиваниям, аргументам, возвратам, полям (поле — у каждого
// места рождения своё), элементам срезов и карт (свёрнуты в сам контейнер).
// Порядок операторов не учитывается: гейт судит СБОРКУ корня, а не посадку, и
// ветка, не исполняемая на этой посадке, остаётся в сборке.
//
// Фабрика различает вызывающих: значение, рождённое внутри вызванной функции
// и из неё возвращённое, получает отдельную копию на каждом месте вызова.
// Иначе два фронта, собранные одним помощником, слились бы в одну поверхность.
// Место вызова, уже пройденное значением (рекурсия), второй копии не даёт —
// цепочка копий конечна, и разбор доходит до неподвижной точки (clone).
//
// Текут только значения ВАЖНЫХ типов: мультиплексоры, обработчики, образцы
// шлюза, функции и структуры, их несущие, и интерфейсы, чьи методы их
// принимают или возвращают (регистратор, монтировщик). Метод мультиплексора,
// взятый значением, течёт вместе с получателем (avBound). Строки не текут
// вперёд — путь регистрации сводится к значению ОБРАТНЫМ разбором
// (ceremony_surface_resolve.go).

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
)

// avKind — вид абстрактного значения.
type avKind uint8

const (
	avHTTPMux avKind = iota + 1
	avGatewayMux
	avStruct
	avFunc
	avClosure
	avOpaque
	avExtWrap
	avNotFound
	// avBound — метод мультиплексора, взятый значением вместе с получателем
	// (mux.Handle, mux.ServeHTTP, метод интерфейса, который мультиплексор
	// реализует): вызов такого значения — вызов метода ЭТОГО получателя.
	avBound
)

// fkey — функция: объявленная либо литерал; нулевое значение — инициализация пакета.
type fkey struct {
	fn  *types.Func
	lit *ast.FuncLit
}

// absVal — абстрактное значение.
type absVal struct {
	kind   avKind
	site   token.Pos
	ctx    token.Pos
	parent *absVal
	origin fkey
	typ    types.Type
	fn     *types.Func
	lit    *ast.FuncLit
	pkg    *surfaceSrcPkg
	seq    int
}

type avSet map[*absVal]struct{}

func (s avSet) add(v *absVal) bool {
	if _, ok := s[v]; ok {
		return false
	}
	s[v] = struct{}{}
	return true
}

func (s avSet) addAll(o avSet) bool {
	changed := false
	for v := range o {
		if s.add(v) {
			changed = true
		}
	}
	return changed
}

func (s avSet) sorted() []*absVal {
	out := make([]*absVal, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

type avKey struct {
	kind   avKind
	site   token.Pos
	ctx    token.Pos
	parent *absVal
	fn     *types.Func
	lit    *ast.FuncLit
}

type fieldSlot struct {
	owner *absVal
	field *types.Var
}

// surfaceReg — одна регистрация маршрута.
type surfaceReg struct {
	kind    regKind
	call    *ast.CallExpr
	pkg     *surfaceSrcPkg
	fk      fkey
	path    ast.Expr
	method  ast.Expr
	handler ast.Expr
}

type regKind uint8

const (
	regHTTP regKind = iota + 1
	regDefault
	regGatewayPattern
	regGatewayPath
)

// flowNode — узел, влияющий на течение, с его функцией.
type flowNode struct {
	pkg  *surfaceSrcPkg
	fk   fkey
	node ast.Node
}

// funcDecl — тело функции радиуса.
type funcDecl struct {
	decl *ast.FuncDecl
	pkg  *surfaceSrcPkg
}

// surfaceFlow — состояние прослеживания.
type surfaceFlow struct {
	prog     *surfaceProgram
	vals     map[avKey]*absVal
	seq      int
	vars     map[*types.Var]avSet
	fields   map[fieldSlot]avSet
	results  map[fkey][]avSet
	extKids  map[*absVal]avSet
	regs     map[*absVal][]*surfaceReg
	regSeen  map[*absVal]map[*ast.CallExpr]bool
	untraced map[*ast.CallExpr]*surfaceReg
	changed  bool
	decls    map[*types.Func]funcDecl
	litPkg   map[*ast.FuncLit]*surfaceSrcPkg
	litOwner map[*ast.FuncLit]fkey
	nodes    []flowNode
	named    []flowNode
	memo     map[types.Type]bool
	handler  *types.Interface
	edges    map[fkey]map[fkey]bool
	escapes  map[token.Pos]escapeRef
	extCalls map[*absVal]flowNode
	defMux   *absVal

	// получатели значений-методов (avBound)
	boundRecv map[*absVal]avSet
	// типы мультиплексоров, как их видит проверка типов (для диспетчеризации)
	httpMuxT types.Type
	gwMuxT   types.Type
	// вызовы метода регистрации через интерфейс, который реализует
	// мультиплексор, и нашлась ли для них хоть одна реализация
	ifaceRegs  map[*ast.CallExpr]*surfaceReg
	dispatched map[*ast.CallExpr]bool
	// состояние каждого вызова метода интерфейса на последнем вычислении:
	// все ли получатели разрешились и несут ли аргументы мультиплексор
	ifaceCalls map[*ast.CallExpr]*ifaceCall
	// переменные, объявленные без значения (нулевое значение), и функция
	// объявления: нулевое значение своего типа с методами — место рождения
	zeroVars map[*types.Var]fkey
	// именованные типы, упомянутые в теле функции (приведение, литерал,
	// объявление переменной): их методы достижимы вместе с функцией
	typeUses map[fkey][]*types.TypeName
	// неподвижная точка «течёт ли тип» (Тарьян по графу типов)
	typeSCC *typeSCCState

	// объявления, собранные проходом (судит ceremony_surface.go)
	surfaceLits []flowNode
	raisedLits  []flowNode
	builders    []flowNode
	sinks       []sinkRef
	manual      []manualRef
	pathReads   []flowNode
	pathCands   []flowNode

	// индексы обратного разбора (ceremony_surface_resolve.go)
	idx *resolveIndex
}

func newSurfaceFlow(prog *surfaceProgram) *surfaceFlow {
	a := &surfaceFlow{
		prog:     prog,
		vals:     map[avKey]*absVal{},
		vars:     map[*types.Var]avSet{},
		fields:   map[fieldSlot]avSet{},
		results:  map[fkey][]avSet{},
		extKids:  map[*absVal]avSet{},
		regs:     map[*absVal][]*surfaceReg{},
		regSeen:  map[*absVal]map[*ast.CallExpr]bool{},
		untraced: map[*ast.CallExpr]*surfaceReg{},
		decls:    map[*types.Func]funcDecl{},
		litPkg:   map[*ast.FuncLit]*surfaceSrcPkg{},
		litOwner: map[*ast.FuncLit]fkey{},
		memo:     map[types.Type]bool{},
		edges:    map[fkey]map[fkey]bool{},
		escapes:  map[token.Pos]escapeRef{},
		extCalls: map[*absVal]flowNode{},

		boundRecv:  map[*absVal]avSet{},
		ifaceRegs:  map[*ast.CallExpr]*surfaceReg{},
		dispatched: map[*ast.CallExpr]bool{},
		ifaceCalls: map[*ast.CallExpr]*ifaceCall{},
		zeroVars:   map[*types.Var]fkey{},
		typeUses:   map[fkey][]*types.TypeName{},
		typeSCC:    newTypeSCCState(),
	}
	a.handler = lookupHandlerIface(prog)
	a.httpMuxT = lookupMuxPtr(prog, "net/http")
	a.gwMuxT = lookupMuxPtr(prog, gatewayRuntimePkg)
	a.defMux = a.intern(avKey{kind: avHTTPMux}, fkey{}, nil, nil)
	return a
}

// escapeRef — мультиплексор, переданный чужому коду.
type escapeRef struct {
	name string
	fk   fkey
}

// sinkRef — место, где обработчик отдаётся HTTP-серверу.
type sinkRef struct {
	node flowNode
	expr ast.Expr
}

// lookupMuxPtr — указатель на тип ServeMux пакета path, как его видит
// проверка типов; nil — пакет в радиус не импортирован.
func lookupMuxPtr(prog *surfaceProgram, path string) types.Type {
	for _, sp := range prog.pkgs {
		for _, imp := range sp.types.Imports() {
			if imp.Path() != path {
				continue
			}
			if tn, ok := imp.Scope().Lookup("ServeMux").(*types.TypeName); ok {
				return types.NewPointer(tn.Type())
			}
		}
	}
	return nil
}

// lookupHandlerIface — интерфейс http.Handler, как его видит проверка типов.
func lookupHandlerIface(prog *surfaceProgram) *types.Interface {
	for _, sp := range prog.pkgs {
		for _, imp := range sp.types.Imports() {
			if imp.Path() == "net/http" {
				if obj := imp.Scope().Lookup("Handler"); obj != nil {
					if it, ok := obj.Type().Underlying().(*types.Interface); ok {
						return it
					}
				}
			}
		}
	}
	return nil
}

func (a *surfaceFlow) intern(k avKey, origin fkey, typ types.Type, pkg *surfaceSrcPkg) *absVal {
	if v, ok := a.vals[k]; ok {
		return v
	}
	a.seq++
	v := &absVal{kind: k.kind, site: k.site, ctx: k.ctx, parent: k.parent, origin: origin, typ: typ, fn: k.fn, lit: k.lit, pkg: pkg, seq: a.seq}
	a.vals[k] = v
	a.changed = true
	return v
}

// clone — копия значения на месте вызова ctx.
//
// Значение, УЖЕ прошедшее это место вызова (оно само или его прародитель —
// копия, заведённая здесь), второй копии не получает: оно течёт дальше само.
// Так сливаются уровни рекурсии — самовызова и взаимного вызова. Копия нужна,
// чтобы различить ВЫЗЫВАЮЩИХ; уровни одной рекурсии — один вызывающий, а без
// слияния каждый раунд заводил бы нового потомка, и неподвижная точка не
// наступала бы. Слитое значение несёт регистрации всех уровней: гейт видит
// больше, а не меньше.
func (a *surfaceFlow) clone(v *absVal, ctx token.Pos, caller fkey) *absVal {
	for u := v; u != nil; u = u.parent {
		if u.ctx == ctx {
			return v
		}
	}
	return a.intern(avKey{kind: v.kind, site: v.site, ctx: ctx, parent: v, fn: v.fn, lit: v.lit}, caller, v.typ, v.pkg)
}

// ─── типы ───────────────────────────────────────────────────────────────────

func namedOf(t types.Type) *types.Named {
	t = types.Unalias(t)
	if p, ok := t.(*types.Pointer); ok {
		t = types.Unalias(p.Elem())
	}
	n, _ := t.(*types.Named)
	return n
}

func isNamed(t types.Type, pkgPath, name string) bool {
	n := namedOf(t)
	return n != nil && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == pkgPath && n.Obj().Name() == name
}

const (
	gatewayRuntimePkg  = "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	serviceContractPkg = "/corelib/servicecontract"
)

func (a *surfaceFlow) isHTTPMuxType(t types.Type) bool { return isNamed(t, "net/http", "ServeMux") }
func (a *surfaceFlow) isGatewayMuxType(t types.Type) bool {
	return isNamed(t, gatewayRuntimePkg, "ServeMux")
}

// isHandlerType — реализует ли тип (или указатель на него) http.Handler.
func (a *surfaceFlow) isHandlerType(t types.Type) bool {
	if a.handler == nil || t == nil {
		return false
	}
	if types.Implements(t, a.handler) {
		return true
	}
	if _, isPtr := t.(*types.Pointer); !isPtr {
		if _, isIface := t.Underlying().(*types.Interface); !isIface {
			return types.Implements(types.NewPointer(t), a.handler)
		}
	}
	return false
}

// isHandlerFuncSig — подпись обработчика: (ResponseWriter, *Request[, pathParams]).
func isHandlerFuncSig(t types.Type) bool {
	sig, ok := t.Underlying().(*types.Signature)
	if !ok || sig.Params().Len() < 2 || sig.Params().Len() > 3 || sig.Results().Len() != 0 {
		return false
	}
	return isNamed(sig.Params().At(0).Type(), "net/http", "ResponseWriter") &&
		isNamed(sig.Params().At(1).Type(), "net/http", "Request")
}

// interesting — течёт ли значение этого типа.
//
// «Течёт» — из типа достижим по его строению тип-носитель (мультиплексор,
// обработчик, образец шлюза, параметр типа). Граф типов цикличен (A несёт
// указатель на B, B — на A), и ответ — неподвижная точка по компонентам
// сильной связности: у всех типов одной компоненты он общий. Ответ, посчитанный
// при обрезанном цикле, не кэшируется как окончательный — иначе о типе
// отвечал бы тот, кого спросили первым (kaname#320, круг 3).
func (a *surfaceFlow) interesting(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if v, ok := a.memo[t]; ok {
		return v
	}
	a.typeSCC.visit(a, t)
	return a.memo[t]
}

// interestingBase — тип сам носитель, без обхода его строения.
func (a *surfaceFlow) interestingBase(t types.Type) bool {
	switch u := t.(type) {
	case *types.Named:
		return a.isHTTPMuxType(u) || a.isGatewayMuxType(u) || isNamed(u, gatewayRuntimePkg, "Pattern") ||
			isHandlerFuncSig(u) || a.isHandlerType(u)
	case *types.Pointer:
		return a.isHandlerType(u)
	case *types.Signature:
		return isHandlerFuncSig(u)
	case *types.Interface:
		return u.NumMethods() > 0 && a.isHandlerType(u)
	case *types.TypeParam:
		return true
	}
	return false
}

// interestingKids — типы, из которых тип строится. Интерфейс течёт, если течёт
// хоть одна подпись его методов (регистратор Handle(string, http.Handler),
// монтировщик Mount(*http.ServeMux)).
func interestingKids(t types.Type) []types.Type {
	var out []types.Type
	switch u := t.(type) {
	case *types.Named:
		out = append(out, u.Underlying())
	case *types.Pointer:
		out = append(out, u.Elem())
	case *types.Slice:
		out = append(out, u.Elem())
	case *types.Array:
		out = append(out, u.Elem())
	case *types.Chan:
		out = append(out, u.Elem())
	case *types.Map:
		out = append(out, u.Key(), u.Elem())
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			out = append(out, u.Field(i).Type())
		}
	case *types.Signature:
		for i := 0; i < u.Params().Len(); i++ {
			out = append(out, u.Params().At(i).Type())
		}
		for i := 0; i < u.Results().Len(); i++ {
			out = append(out, u.Results().At(i).Type())
		}
	case *types.Interface:
		for i := 0; i < u.NumMethods(); i++ {
			out = append(out, u.Method(i).Type())
		}
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			out = append(out, u.At(i).Type())
		}
	}
	return out
}

// typeSCCState — обход Тарьяна по графу типов для interesting.
type typeSCCState struct {
	next  int
	index map[types.Type]int
	low   map[types.Type]int
	on    map[types.Type]bool
	acc   map[types.Type]bool
	stack []types.Type
}

func newTypeSCCState() *typeSCCState {
	return &typeSCCState{index: map[types.Type]int{}, low: map[types.Type]int{}, on: map[types.Type]bool{}, acc: map[types.Type]bool{}}
}

// visit — компонента сильной связности типа t: ответ пишется в память
// разбора, когда компонента закрыта, и один на всю компоненту.
func (s *typeSCCState) visit(a *surfaceFlow, t types.Type) {
	i := s.next
	s.next++
	s.index[t], s.low[t] = i, i
	s.stack = append(s.stack, t)
	s.on[t] = true
	acc := a.interestingBase(t)
	for _, c := range interestingKids(t) {
		if acc {
			break
		}
		c = types.Unalias(c)
		if v, done := a.memo[c]; done {
			acc = v
			continue
		}
		if _, seen := s.index[c]; !seen {
			s.visit(a, c)
			if s.on[c] {
				s.low[t] = min(s.low[t], s.low[c])
			} else {
				acc = a.memo[c]
			}
			continue
		}
		if s.on[c] {
			s.low[t] = min(s.low[t], s.index[c])
		}
	}
	s.acc[t] = acc
	if s.low[t] != i {
		return
	}
	var members []types.Type
	val := false
	for {
		n := s.stack[len(s.stack)-1]
		s.stack = s.stack[:len(s.stack)-1]
		s.on[n] = false
		members = append(members, n)
		val = val || s.acc[n]
		if n == t {
			break
		}
	}
	for _, n := range members {
		a.memo[n] = val
	}
}

func (a *surfaceFlow) typeOf(sp *surfaceSrcPkg, e ast.Expr) types.Type {
	if tv, ok := sp.info.Types[e]; ok {
		return tv.Type
	}
	if id, ok := e.(*ast.Ident); ok {
		if obj := sp.info.ObjectOf(id); obj != nil {
			return obj.Type()
		}
	}
	return nil
}

// ─── сбор узлов ─────────────────────────────────────────────────────────────

// collect проходит все тела радиуса один раз: узлы течения, индексы
// обратного разбора, тела функций.
func (a *surfaceFlow) collect() {
	a.idx = newResolveIndex()
	for _, sp := range a.prog.pkgs {
		for _, f := range sp.files {
			for _, d := range f.Decls {
				switch d := d.(type) {
				case *ast.FuncDecl:
					fn, _ := sp.info.Defs[d.Name].(*types.Func)
					if fn == nil {
						continue
					}
					a.decls[fn] = funcDecl{decl: d, pkg: sp}
					a.idx.funcParams(sp, fkey{fn: fn}, d.Recv, d.Type)
					if d.Body != nil {
						a.walk(sp, fkey{fn: fn}, d.Body)
					}
				case *ast.GenDecl:
					if d.Tok == token.VAR || d.Tok == token.CONST {
						a.walk(sp, fkey{}, d)
					}
				}
			}
			a.idx.structTags(sp, f)
		}
	}
	a.judgePathCands()
}

// walk собирает узлы одного тела, помня ближайшую функцию.
func (a *surfaceFlow) walk(sp *surfaceSrcPkg, top fkey, root ast.Node) {
	stack := []fkey{top}
	var nodes []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			last := nodes[len(nodes)-1]
			nodes = nodes[:len(nodes)-1]
			if _, ok := last.(*ast.FuncLit); ok {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if _, ok := n.(*ast.TypeSpec); ok {
			// Объявление типа — не употребление: упомянутые в нём типы
			// значений не рождают (их рождает употребление самого типа).
			return false
		}
		nodes = append(nodes, n)
		fk := stack[len(stack)-1]
		a.notePathNode(sp, fk, n)
		switch n := n.(type) {
		case *ast.FuncLit:
			a.litPkg[n] = sp
			a.litOwner[n] = fk
			a.edge(fk, fkey{lit: n})
			lk := fkey{lit: n}
			a.idx.funcParams(sp, lk, nil, n.Type)
			if hasNamedResults(n.Type) && a.resultsInteresting(lk) {
				a.named = append(a.named, flowNode{sp, lk, n.Type})
			}
			stack = append(stack, lk)
		case *ast.AssignStmt:
			a.idx.assign(sp, fk, n)
			a.keep(sp, fk, n, a.assignInteresting(sp, n))
		case *ast.ValueSpec:
			a.idx.valueSpec(sp, fk, n)
			keep := false
			for _, id := range n.Names {
				if a.interesting(a.typeOf(sp, id)) {
					keep = true
				}
				if v, ok := sp.info.Defs[id].(*types.Var); ok && len(n.Values) == 0 {
					a.zeroVars[v] = fk
				}
			}
			a.keep(sp, fk, n, keep)
		case *ast.RangeStmt:
			a.idx.rangeStmt(sp, fk, n)
			a.keep(sp, fk, n, a.interesting(a.typeOf(sp, n.X)))
		case *ast.ReturnStmt:
			if sig := a.sigOf(fk); sig != nil {
				a.idx.ret(sp, fk, n, sig.Results().Len())
			}
			a.keep(sp, fk, n, a.resultsInteresting(fk))
		case *ast.CallExpr:
			a.idx.call(sp, fk, n)
			a.keep(sp, fk, n, a.callInteresting(sp, n))
			a.noteCall(sp, fk, n)
		case *ast.CompositeLit:
			a.idx.composite(sp, fk, n)
			a.keep(sp, fk, n, a.interesting(a.typeOf(sp, n)))
			a.noteComposite(sp, fk, n)
		case *ast.SendStmt:
			a.keep(sp, fk, n, a.interesting(a.typeOf(sp, n.Value)))
		case *ast.TypeSwitchStmt:
			a.keep(sp, fk, n, true)
		case *ast.UnaryExpr:
			a.idx.addressOf(sp, n)
		case *ast.Ident:
			// Ребро графа вызовов — у КАЖДОГО упоминания функции: вызов и
			// взятие значением. Не только у тех, что текут: достижимость
			// регистрации решает путь от входа процесса, а он идёт через
			// вызовы, чьи значения гейту неважны.
			switch obj := sp.info.Uses[n].(type) {
			case *types.Func:
				a.edge(fk, fkey{fn: obj.Origin()})
			case *types.TypeName:
				a.typeUses[fk] = append(a.typeUses[fk], obj)
			}
		}
		return true
	})
	if top.fn != nil {
		if fd, ok := a.decls[top.fn]; ok && hasNamedResults(fd.decl.Type) && a.resultsInteresting(top) {
			a.named = append(a.named, flowNode{sp, top, fd.decl.Type})
		}
	}
}

func hasNamedResults(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil {
		return false
	}
	for _, f := range ft.Results.List {
		if len(f.Names) > 0 {
			return true
		}
	}
	return false
}

func (a *surfaceFlow) resultsInteresting(fk fkey) bool {
	sig := a.sigOf(fk)
	return sig != nil && a.interesting(sig.Results())
}

// isURLPath — выражение читает путь ЗАПРОСА: r.URL.Path, r.URL.RawPath,
// r.URL.EscapedPath(), r.RequestURI, где r — *http.Request. Путь адреса из
// настройки (url.URL, разобранный из строки профиля) маршрутом не является.
func isURLPath(sp *surfaceSrcPkg, e ast.Expr) bool {
	switch x := ast.Unparen(e).(type) {
	case *ast.CallExpr:
		sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "EscapedPath" && isRequestField(sp, sel.X, "URL")
	case *ast.SelectorExpr:
		if isRequestField(sp, x, "RequestURI") {
			return true
		}
		s, ok := sp.info.Selections[x]
		if !ok || s.Kind() != types.FieldVal {
			return false
		}
		f, ok := s.Obj().(*types.Var)
		return ok && f.Pkg() != nil && f.Pkg().Path() == "net/url" && (f.Name() == "Path" || f.Name() == "RawPath") &&
			isRequestField(sp, x.X, "URL")
	}
	return false
}

// isRequestField — выбор поля name, принадлежащего http.Request: прямо у
// *http.Request и сквозь его встраивание в свой тип (cr.URL, где cr —
// struct{ *http.Request }).
func isRequestField(sp *surfaceSrcPkg, e ast.Expr, name string) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	s, ok := sp.info.Selections[sel]
	return ok && s.Kind() == types.FieldVal && isNamed(fieldOwner(s), "net/http", "Request")
}

// fieldOwner — тип, которому принадлежит выбранное поле, с продвижением через
// встроенные поля; nil — путь выбора не сквозь структуры.
func fieldOwner(s *types.Selection) types.Type {
	t := s.Recv()
	index := s.Index()
	for _, i := range index[:len(index)-1] {
		t = types.Unalias(t)
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = p.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			return nil
		}
		t = st.Field(i).Type()
	}
	return t
}

// noteCall — построители поверхности и отдача обработчика серверу.
func (a *surfaceFlow) noteCall(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) {
	fn := calleeFunc(sp, call)
	if fn == nil || fn.Pkg() == nil {
		return
	}
	pkg, name := fn.Pkg().Path(), fn.Name()
	switch {
	case sp.own && strings.HasSuffix(pkg, serviceContractPkg) && name == "NewSurface":
		a.builders = append(a.builders, flowNode{sp, fk, call})
	case pkg == "net/http" && (name == "ListenAndServe" || name == "ListenAndServeTLS") && len(call.Args) >= 2:
		a.sinks = append(a.sinks, sinkRef{flowNode{sp, fk, call}, call.Args[len(call.Args)-1]})
	case pkg == "net/http" && (name == "Serve" || name == "ServeTLS") && len(call.Args) >= 2:
		a.sinks = append(a.sinks, sinkRef{flowNode{sp, fk, call}, call.Args[1]})
	}
}

// noteComposite — объявления поверхности, срез подъёма, литерал HTTP-сервера.
func (a *surfaceFlow) noteComposite(sp *surfaceSrcPkg, fk fkey, lit *ast.CompositeLit) {
	t := a.typeOf(sp, lit)
	if t == nil {
		return
	}
	switch {
	case sp.own && isServiceContract(t, "Surface"):
		a.surfaceLits = append(a.surfaceLits, flowNode{sp, fk, lit})
	case isNamed(t, "net/http", "Server"):
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Handler" {
					a.sinks = append(a.sinks, sinkRef{flowNode{sp, fk, lit}, kv.Value})
				}
			}
		}
	case sp.root:
		if sl, ok := t.Underlying().(*types.Slice); ok {
			if st, ok := sl.Elem().Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					if isServiceContract(st.Field(i).Type(), "SurfaceDescriptor") {
						a.raisedLits = append(a.raisedLits, flowNode{sp, fk, lit})
						break
					}
				}
			}
		}
	}
}

func (a *surfaceFlow) keep(sp *surfaceSrcPkg, fk fkey, n ast.Node, ok bool) {
	if ok {
		a.nodes = append(a.nodes, flowNode{sp, fk, n})
	}
}

func (a *surfaceFlow) assignInteresting(sp *surfaceSrcPkg, n *ast.AssignStmt) bool {
	for _, l := range n.Lhs {
		if a.interesting(a.typeOf(sp, l)) {
			return true
		}
	}
	return false
}

func (a *surfaceFlow) callInteresting(sp *surfaceSrcPkg, call *ast.CallExpr) bool {
	t := a.typeOf(sp, call.Fun)
	if t == nil {
		return true
	}
	if a.interesting(t) {
		return true
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if s, ok := sp.info.Selections[sel]; ok && a.interesting(s.Recv()) {
			return true
		}
	}
	for _, arg := range call.Args {
		if a.interesting(a.typeOf(sp, arg)) {
			return true
		}
	}
	return false
}

func (a *surfaceFlow) edge(from, to fkey) {
	m, ok := a.edges[from]
	if !ok {
		m = map[fkey]bool{}
		a.edges[from] = m
	}
	m[to] = true
}

// ─── неподвижная точка ──────────────────────────────────────────────────────

// solve гоняет узлы до неподвижной точки не дольше limit раундов: число
// раундов и дошёл ли разбор до неё. Не дошедший разбор не судится — значения,
// ещё не дотёкшие до регистраций, неотличимы от отсутствующих.
func (a *surfaceFlow) solve(limit int) (rounds int, converged bool) {
	for round := 1; round <= limit; round++ {
		a.changed = false
		for _, n := range a.nodes {
			a.apply(n)
		}
		for _, n := range a.named {
			a.namedResults(n)
		}
		if !a.changed {
			return round, true
		}
	}
	return limit, false
}

func (a *surfaceFlow) setVar(v *types.Var, s avSet) {
	if v == nil || len(s) == 0 {
		return
	}
	cur, ok := a.vars[v]
	if !ok {
		cur = avSet{}
		a.vars[v] = cur
	}
	if cur.addAll(s) {
		a.changed = true
	}
}

func (a *surfaceFlow) setField(owner *absVal, f *types.Var, s avSet) {
	if len(s) == 0 {
		return
	}
	k := fieldSlot{owner, f}
	cur, ok := a.fields[k]
	if !ok {
		cur = avSet{}
		a.fields[k] = cur
	}
	if cur.addAll(s) {
		a.changed = true
	}
}

func (a *surfaceFlow) setResult(fk fkey, i, n int, s avSet) {
	if len(s) == 0 {
		return
	}
	rs := a.results[fk]
	for len(rs) < n {
		rs = append(rs, avSet{})
	}
	a.results[fk] = rs
	if i < len(rs) && rs[i].addAll(s) {
		a.changed = true
	}
}

func (a *surfaceFlow) apply(n flowNode) {
	sp, fk := n.pkg, n.fk
	switch x := n.node.(type) {
	case *ast.AssignStmt:
		if len(x.Lhs) == len(x.Rhs) {
			for i := range x.Lhs {
				a.assignTo(sp, fk, x.Lhs[i], a.eval(sp, fk, x.Rhs[i]))
			}
			return
		}
		if len(x.Rhs) == 1 {
			if call, ok := ast.Unparen(x.Rhs[0]).(*ast.CallExpr); ok {
				for i := range x.Lhs {
					a.assignTo(sp, fk, x.Lhs[i], a.evalCall(sp, fk, call, i))
				}
				return
			}
			// v, ok := m[k] / x.(T) / <-ch
			a.assignTo(sp, fk, x.Lhs[0], a.eval(sp, fk, x.Rhs[0]))
		}
	case *ast.ValueSpec:
		if len(x.Values) == len(x.Names) {
			for i, id := range x.Names {
				a.assignTo(sp, fk, id, a.eval(sp, fk, x.Values[i]))
			}
		} else if len(x.Values) == 1 {
			if call, ok := ast.Unparen(x.Values[0]).(*ast.CallExpr); ok {
				for i, id := range x.Names {
					a.assignTo(sp, fk, id, a.evalCall(sp, fk, call, i))
				}
			}
		}
	case *ast.RangeStmt:
		elems := a.eval(sp, fk, x.X)
		if x.Key != nil {
			a.assignTo(sp, fk, x.Key, elems)
		}
		if x.Value != nil {
			a.assignTo(sp, fk, x.Value, elems)
		}
	case *ast.ReturnStmt:
		sig := a.sigOf(fk)
		if sig == nil {
			return
		}
		nres := sig.Results().Len()
		if len(x.Results) == nres {
			for i, r := range x.Results {
				if a.interesting(sig.Results().At(i).Type()) {
					a.setResult(fk, i, nres, a.eval(sp, fk, r))
				}
			}
		} else if len(x.Results) == 1 && nres > 1 {
			if call, ok := ast.Unparen(x.Results[0]).(*ast.CallExpr); ok {
				for i := 0; i < nres; i++ {
					if a.interesting(sig.Results().At(i).Type()) {
						a.setResult(fk, i, nres, a.evalCall(sp, fk, call, i))
					}
				}
			}
		}
	case *ast.CallExpr:
		a.evalCall(sp, fk, x, 0)
	case *ast.CompositeLit:
		a.eval(sp, fk, x)
	case *ast.SendStmt:
		a.assignTo(sp, fk, x.Chan, a.eval(sp, fk, x.Value))
	case *ast.TypeSwitchStmt:
		var src ast.Expr
		switch as := x.Assign.(type) {
		case *ast.AssignStmt:
			if ta, ok := as.Rhs[0].(*ast.TypeAssertExpr); ok {
				src = ta.X
			}
		case *ast.ExprStmt:
			if ta, ok := as.X.(*ast.TypeAssertExpr); ok {
				src = ta.X
			}
		}
		if src == nil {
			return
		}
		vals := a.eval(sp, fk, src)
		for _, c := range x.Body.List {
			if obj, ok := sp.info.Implicits[c].(*types.Var); ok {
				a.setVar(obj, vals)
			}
		}
	}
}

// namedResults — именованные результаты возвращаются голым return.
func (a *surfaceFlow) namedResults(n flowNode) {
	ft, ok := n.node.(*ast.FuncType)
	if !ok || ft.Results == nil {
		return
	}
	sig := a.sigOf(n.fk)
	if sig == nil {
		return
	}
	i := 0
	for _, field := range ft.Results.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, id := range field.Names {
			if v, ok := n.pkg.info.Defs[id].(*types.Var); ok && a.interesting(v.Type()) {
				a.setResult(n.fk, i, sig.Results().Len(), a.vars[v])
			}
			i++
		}
	}
}

func (a *surfaceFlow) sigOf(fk fkey) *types.Signature {
	switch {
	case fk.fn != nil:
		sig, _ := fk.fn.Type().(*types.Signature)
		return sig
	case fk.lit != nil:
		if sp := a.litPkg[fk.lit]; sp != nil {
			sig, _ := sp.info.Types[fk.lit].Type.(*types.Signature)
			return sig
		}
	}
	return nil
}

// ─── присваивание ───────────────────────────────────────────────────────────

func (a *surfaceFlow) assignTo(sp *surfaceSrcPkg, fk fkey, lhs ast.Expr, s avSet) {
	if len(s) == 0 {
		return
	}
	switch l := ast.Unparen(lhs).(type) {
	case *ast.Ident:
		if l.Name == "_" {
			return
		}
		if v, ok := sp.info.ObjectOf(l).(*types.Var); ok {
			a.setVar(v, s)
		}
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[l]; ok && sel.Kind() == types.FieldVal {
			path := fieldPath(sel)
			owners := a.eval(sp, fk, l.X)
			for _, f := range path[:len(path)-1] {
				owners = a.readFrom(owners, f)
			}
			last := path[len(path)-1]
			wrote := false
			for o := range owners {
				if o.kind == avStruct {
					a.setField(o, last, s)
					wrote = true
				}
			}
			if !wrote {
				a.setField(nil, last, s)
			}
			return
		}
		if v, ok := sp.info.Uses[l.Sel].(*types.Var); ok {
			a.setVar(v, s)
		}
	case *ast.IndexExpr:
		a.assignTo(sp, fk, l.X, s)
	case *ast.StarExpr:
		a.assignTo(sp, fk, l.X, s)
	}
}

// fieldPath — поля по пути выбора (с продвижением через встроенные).
func fieldPath(sel *types.Selection) []*types.Var {
	var out []*types.Var
	t := sel.Recv()
	for _, i := range sel.Index() {
		t = types.Unalias(t)
		if p, ok := t.Underlying().(*types.Pointer); ok {
			t = p.Elem()
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || i >= st.NumFields() {
			break
		}
		f := st.Field(i)
		out = append(out, f)
		t = f.Type()
	}
	if len(out) == 0 {
		if v, ok := sel.Obj().(*types.Var); ok {
			out = append(out, v)
		}
	}
	return out
}

// fieldsOf — поле значения с наследованием от прародителя-копии.
func (a *surfaceFlow) fieldsOf(o *absVal, f *types.Var) avSet {
	out := avSet{}
	for v := o; v != nil; v = v.parent {
		out.addAll(a.fields[fieldSlot{v, f}])
	}
	return out
}

func (a *surfaceFlow) readFrom(owners avSet, f *types.Var) avSet {
	out := avSet{}
	for o := range owners {
		if o.kind == avStruct {
			out.addAll(a.fieldsOf(o, f))
		}
	}
	out.addAll(a.fields[fieldSlot{nil, f}])
	return out
}

// ─── вычисление ─────────────────────────────────────────────────────────────

func (a *surfaceFlow) eval(sp *surfaceSrcPkg, fk fkey, e ast.Expr) avSet {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return a.eval(sp, fk, x.X)
	case *ast.Ident:
		switch obj := sp.info.ObjectOf(x).(type) {
		case *types.Var:
			return a.varVals(obj)
		case *types.Func:
			return a.funcVal(fk, obj)
		}
		return nil
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[x]; ok {
			switch sel.Kind() {
			case types.FieldVal:
				path := fieldPath(sel)
				owners := a.eval(sp, fk, x.X)
				for _, f := range path {
					owners = a.readFrom(owners, f)
				}
				return owners
			case types.MethodVal:
				fn, _ := sel.Obj().(*types.Func)
				if fn == nil {
					return nil
				}
				fn = fn.Origin()
				recvs := a.throughEmbedded(a.eval(sp, fk, x.X), embedPath(sel.Recv(), sel.Index()))
				if a.boundKind(fn) {
					v := a.intern(avKey{kind: avBound, site: x.Pos(), fn: fn}, fk, nil, sp)
					a.addBound(v, recvs)
					a.edge(fk, fkey{fn: fn})
					return avSet{v: {}}
				}
				if !isIfaceMethod(fn) {
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil && a.interesting(sig.Recv().Type()) {
						a.setVar(sig.Recv(), recvs)
					}
				}
				return a.funcVal(fk, fn)
			case types.MethodExpr:
				if fn, ok := sel.Obj().(*types.Func); ok {
					return a.funcVal(fk, fn.Origin())
				}
			}
			return nil
		}
		switch obj := sp.info.Uses[x.Sel].(type) {
		case *types.Var:
			return a.varVals(obj)
		case *types.Func:
			return a.funcVal(fk, obj)
		}
		return nil
	case *ast.CallExpr:
		return a.evalCall(sp, fk, x, 0)
	case *ast.FuncLit:
		return avSet{a.intern(avKey{kind: avClosure, site: x.Pos(), lit: x}, fk, nil, sp): {}}
	case *ast.UnaryExpr:
		return a.eval(sp, fk, x.X)
	case *ast.StarExpr:
		return a.eval(sp, fk, x.X)
	case *ast.CompositeLit:
		return a.evalComposite(sp, fk, x)
	case *ast.TypeAssertExpr:
		return a.eval(sp, fk, x.X)
	case *ast.IndexExpr:
		return a.eval(sp, fk, x.X)
	case *ast.IndexListExpr:
		return a.eval(sp, fk, x.X)
	case *ast.SliceExpr:
		return a.eval(sp, fk, x.X)
	case *ast.KeyValueExpr:
		return a.eval(sp, fk, x.Value)
	}
	return nil
}

func (a *surfaceFlow) varVals(v *types.Var) avSet {
	if v.Pkg() != nil && v.Pkg().Path() == "net/http" && v.Name() == "DefaultServeMux" {
		return avSet{a.defMux: {}}
	}
	if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && isNamed(v.Type(), "net/http", "ServeMux") {
		// Переменная типа http.ServeMux (не указатель) — сама место рождения:
		// нулевое значение мультиплексора годно к регистрации.
		out := avSet{a.intern(avKey{kind: avHTTPMux, site: v.Pos()}, fkey{}, nil, nil): {}}
		out.addAll(a.vars[v])
		return out
	}
	if fk, zero := a.zeroVars[v]; zero {
		// `var s T` — нулевое значение своего типа с методами само место
		// рождения: получатель метода выбирается по ТИПУ, и монтировщик,
		// вызванный через интерфейс, диспетчеризуется на него.
		if b := a.typedBirth(v.Type(), v.Pos(), fk); b != nil {
			out := avSet{b: {}}
			out.addAll(a.vars[v])
			return out
		}
	}
	return a.vars[v]
}

// typedBirth — место рождения значения именованного типа радиуса, у которого
// есть методы: приведение `T(x)` без прослеженного значения и нулевое значение
// переменной. Интерфейсы, функции и указатели сюда не входят: у первых нет
// своего значения, вторые текут значением функции, третьи нулевые.
func (a *surfaceFlow) typedBirth(t types.Type, site token.Pos, fk fkey) *absVal {
	n, ok := types.Unalias(t).(*types.Named)
	if !ok || n.Obj().Pkg() == nil || a.prog.byPath[n.Obj().Pkg().Path()] == nil {
		return nil
	}
	switch n.Underlying().(type) {
	case *types.Interface, *types.Signature, *types.Pointer:
		return nil
	}
	if types.NewMethodSet(n).Len() == 0 && types.NewMethodSet(types.NewPointer(n)).Len() == 0 {
		return nil
	}
	return a.intern(avKey{kind: avStruct, site: site}, fk, n, a.prog.byPath[n.Obj().Pkg().Path()])
}

func (a *surfaceFlow) funcVal(fk fkey, fn *types.Func) avSet {
	fn = fn.Origin()
	a.edge(fk, fkey{fn: fn})
	return avSet{a.intern(avKey{kind: avFunc, fn: fn}, fkey{}, nil, nil): {}}
}

func (a *surfaceFlow) evalComposite(sp *surfaceSrcPkg, fk fkey, lit *ast.CompositeLit) avSet {
	t := a.typeOf(sp, lit)
	if t == nil {
		return nil
	}
	under := types.Unalias(t)
	if p, ok := under.Underlying().(*types.Pointer); ok {
		under = p.Elem()
	}
	if isNamed(under, "net/http", "ServeMux") {
		// http.ServeMux{} — место рождения мультиплексора, как NewServeMux.
		return avSet{a.intern(avKey{kind: avHTTPMux, site: lit.Pos()}, fk, nil, sp): {}}
	}
	switch u := under.Underlying().(type) {
	case *types.Struct:
		v := a.intern(avKey{kind: avStruct, site: lit.Pos()}, fk, under, sp)
		for i, el := range lit.Elts {
			var f *types.Var
			val := el
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok {
					f, _ = sp.info.Uses[id].(*types.Var)
				}
				val = kv.Value
			} else if i < u.NumFields() {
				f = u.Field(i)
			}
			if f != nil && a.interesting(f.Type()) {
				a.setField(v, f, a.eval(sp, fk, val))
			}
		}
		return avSet{v: {}}
	default:
		out := avSet{}
		for _, el := range lit.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				out.addAll(a.eval(sp, fk, kv.Key))
				out.addAll(a.eval(sp, fk, kv.Value))
				continue
			}
			out.addAll(a.eval(sp, fk, el))
		}
		return out
	}
}

// ─── вызовы ─────────────────────────────────────────────────────────────────

type surfaceCallee struct {
	fn       *types.Func
	lit      *ast.FuncLit
	recv     ast.Expr
	recvVals avSet
	shift    bool
	// embed — встроенные поля от выражения получателя до получателя метода
	// (метод, продвинутый из встроенного мультиплексора или структуры).
	embed []*types.Var
}

func (c surfaceCallee) key() fkey { return fkey{fn: c.fn, lit: c.lit} }

func (a *surfaceFlow) evalCall(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, idx int) avSet {
	fun := ast.Unparen(call.Fun)
	if tv, ok := sp.info.Types[fun]; ok && tv.IsType() {
		if len(call.Args) != 1 {
			return nil
		}
		vals := a.eval(sp, fk, call.Args[0])
		if len(vals) == 0 {
			// cv2IntMount(0) — значение своего типа рождено приведением.
			if b := a.typedBirth(tv.Type, call.Pos(), fk); b != nil {
				return avSet{b: {}}
			}
		}
		return vals
	}
	if id, ok := fun.(*ast.Ident); ok {
		if b, ok := sp.info.Uses[id].(*types.Builtin); ok {
			return a.builtin(sp, fk, call, b)
		}
	}
	out := avSet{}
	for _, c := range a.callees(sp, fk, call) {
		if c.fn != nil {
			a.edge(fk, fkey{fn: c.fn})
		}
		if k := a.regKindOf(c, call); k != 0 {
			a.register(sp, fk, call, c, k)
			continue
		}
		if a.hasBody(c) {
			a.bind(sp, fk, call, c)
			for v := range a.resultOf(c.key(), idx) {
				if v.origin == c.key() && (v.kind == avHTTPMux || v.kind == avGatewayMux || v.kind == avStruct) {
					out.add(a.clone(v, call.Pos(), fk))
				} else {
					out.add(v)
				}
			}
			continue
		}
		if c.fn != nil {
			out.addAll(a.external(sp, fk, call, c.fn, idx))
		}
	}
	return out
}

func (a *surfaceFlow) resultOf(k fkey, idx int) avSet {
	rs := a.results[k]
	if idx < len(rs) {
		return rs[idx]
	}
	return nil
}

func (a *surfaceFlow) hasBody(c surfaceCallee) bool {
	if c.lit != nil {
		return true
	}
	fd, ok := a.decls[c.fn]
	return ok && fd.decl.Body != nil
}

func (a *surfaceFlow) builtin(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, b *types.Builtin) avSet {
	switch b.Name() {
	case "append":
		out := avSet{}
		for _, arg := range call.Args {
			out.addAll(a.eval(sp, fk, arg))
		}
		return out
	case "new":
		if len(call.Args) == 1 {
			if t := a.typeOf(sp, call.Args[0]); t != nil {
				if isNamed(t, "net/http", "ServeMux") {
					return avSet{a.intern(avKey{kind: avHTTPMux, site: call.Pos()}, fk, nil, sp): {}}
				}
				if _, ok := t.Underlying().(*types.Struct); ok {
					return avSet{a.intern(avKey{kind: avStruct, site: call.Pos()}, fk, t, sp): {}}
				}
			}
		}
	}
	return nil
}

func (a *surfaceFlow) callees(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) []surfaceCallee {
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if fn, ok := sp.info.Uses[f].(*types.Func); ok {
			return []surfaceCallee{{fn: fn.Origin()}}
		}
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[f]; ok {
			switch sel.Kind() {
			case types.MethodVal:
				fn, _ := sel.Obj().(*types.Func)
				if fn == nil {
					return nil
				}
				embed := embedPath(sel.Recv(), sel.Index())
				if isIfaceMethod(fn) {
					return a.dispatchCall(sp, fk, call, fn, a.throughEmbedded(a.eval(sp, fk, f.X), embed))
				}
				return []surfaceCallee{{fn: fn.Origin(), recv: f.X, embed: embed}}
			case types.MethodExpr:
				if fn, ok := sel.Obj().(*types.Func); ok {
					return []surfaceCallee{{fn: fn.Origin(), shift: true}}
				}
				return nil
			}
		} else if fn, ok := sp.info.Uses[f.Sel].(*types.Func); ok {
			return []surfaceCallee{{fn: fn.Origin()}}
		}
	}
	var out []surfaceCallee
	for _, v := range a.eval(sp, fk, call.Fun).sorted() {
		switch v.kind {
		case avFunc:
			out = append(out, surfaceCallee{fn: v.fn})
		case avClosure:
			out = append(out, surfaceCallee{lit: v.lit})
		case avBound:
			if isIfaceMethod(v.fn) {
				out = append(out, a.dispatchCall(sp, fk, call, v.fn, a.boundRecv[v])...)
				continue
			}
			out = append(out, surfaceCallee{fn: v.fn, recvVals: a.boundRecv[v]})
		}
	}
	return out
}

// ifaceCall — вызов метода интерфейса на последнем вычислении.
type ifaceCall struct {
	node flowNode
	fn   *types.Func
	// unresolved — хоть у одного значения получателя (или при пустом
	// множестве значений) реализация не найдена.
	unresolved bool
	// muxArg — аргументы несут мультиплексор (сам или его метод значением).
	muxArg bool
}

// dispatchCall — вызов метода интерфейса fn над получателями recvs. Метод
// регистрации через интерфейс, который реализует мультиплексор, без
// реализации хоть у одного получателя — кандидат в непрослеженные: значения до
// получателя не дотекли (пустой интерфейс, чужой код), а молчать об этом
// нельзя, даже когда другие получатели разрешились. Мультиплексор, переданный
// такому вызову аргументом, уходит туда, где гейт регистраций не видит.
func (a *surfaceFlow) dispatchCall(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, fn *types.Func, recvs avSet) []surfaceCallee {
	out, unresolved := a.dispatchVals(recvs, fn, map[dispatchKey]bool{})
	if len(out) > 0 {
		a.dispatched[call] = true
	}
	st, ok := a.ifaceCalls[call]
	if !ok {
		st = &ifaceCall{node: flowNode{sp, fk, call}, fn: fn}
		a.ifaceCalls[call] = st
	}
	st.unresolved = unresolved || len(recvs) == 0
	st.muxArg = a.carriesMux(sp, fk, call.Args)
	if _, ok := a.ifaceRegs[call]; !ok {
		if k := a.ifaceRegKind(fn, len(call.Args)); k != 0 {
			reg := a.newReg(k, call.Args)
			reg.call, reg.pkg, reg.fk = call, sp, fk
			a.ifaceRegs[call] = reg
		}
	}
	return out
}

// dispatchKey — пара (значение, метод), уже пройденная диспетчеризацией одного
// вызова.
type dispatchKey struct {
	v  *absVal
	fn *types.Func
}

// dispatchVals — реализации метода интерфейса fn у значений-получателей:
// значения своего типа (с продвижением через встроенные поля) и
// мультиплексоры.
//
// Цикл встраивания (слой, встроивший значение, в котором он сам) отличает
// множество пройденных пар (значение, метод), а не глубина: пара проходится
// один раз, и обход конечен при любой глубине вложения. unresolved — у
// значения реализации нет (не своего типа, метод продвинут из встроенного
// интерфейса без единого значения).
func (a *surfaceFlow) dispatchVals(recvs avSet, fn *types.Func, seen map[dispatchKey]bool) (out []surfaceCallee, unresolved bool) {
	for _, v := range recvs.sorted() {
		k := dispatchKey{v: v, fn: fn}
		if seen[k] {
			continue
		}
		seen[k] = true
		var t types.Type
		switch v.kind {
		case avStruct:
			t = v.typ
		case avHTTPMux:
			t = a.httpMuxT
		case avGatewayMux:
			t = a.gwMuxT
		}
		if t == nil {
			unresolved = true
			continue
		}
		obj, index, _ := types.LookupFieldOrMethod(t, true, fn.Pkg(), fn.Name())
		m, ok := obj.(*types.Func)
		if !ok {
			unresolved = true
			continue
		}
		embed := embedPath(t, index)
		if isIfaceMethod(m) {
			// Продвинут из встроенного интерфейса — диспетчеризация дальше.
			inner := a.throughEmbedded(avSet{v: {}}, embed)
			if len(inner) == 0 {
				unresolved = true
				continue
			}
			more, un := a.dispatchVals(inner, m, seen)
			out = append(out, more...)
			unresolved = unresolved || un
			continue
		}
		out = append(out, surfaceCallee{fn: m.Origin(), recvVals: avSet{v: {}}, embed: embed})
	}
	return out, unresolved
}

// carriesMux — аргументы несут мультиплексор: сам или его метод значением.
func (a *surfaceFlow) carriesMux(sp *surfaceSrcPkg, fk fkey, args []ast.Expr) bool {
	for _, arg := range args {
		for v := range a.eval(sp, fk, arg) {
			switch v.kind {
			case avHTTPMux, avGatewayMux:
				return true
			case avBound:
				for r := range a.boundRecv[v] {
					if r.kind == avHTTPMux || r.kind == avGatewayMux {
						return true
					}
				}
			}
		}
	}
	return false
}

// embedPath — встроенные поля на пути выбора метода: все индексы, кроме
// последнего (он — номер метода).
func embedPath(t types.Type, index []int) []*types.Var {
	var out []*types.Var
	for k := 0; k+1 < len(index); k++ {
		t = types.Unalias(t)
		if p, ok := t.(*types.Pointer); ok {
			t = types.Unalias(p.Elem())
		}
		st, ok := t.Underlying().(*types.Struct)
		if !ok || index[k] >= st.NumFields() {
			return out
		}
		f := st.Field(index[k])
		out = append(out, f)
		t = f.Type()
	}
	return out
}

// throughEmbedded — значения встроенных полей по пути embed.
func (a *surfaceFlow) throughEmbedded(vals avSet, embed []*types.Var) avSet {
	for _, f := range embed {
		vals = a.readFrom(vals, f)
	}
	return vals
}

// receivers — значения получателя вызываемого метода.
func (a *surfaceFlow) receivers(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, c surfaceCallee) avSet {
	var vals avSet
	switch {
	case c.recvVals != nil:
		vals = c.recvVals
	case c.recv != nil:
		vals = a.eval(sp, fk, c.recv)
	case c.shift && len(call.Args) > 0:
		vals = a.eval(sp, fk, call.Args[0])
	}
	return a.throughEmbedded(vals, c.embed)
}

// isIfaceMethod — метод, объявленный интерфейсом (в том числе ограничением
// параметра типа): реализация выбирается по значению получателя.
func isIfaceMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() != nil && types.IsInterface(sig.Recv().Type())
}

// isMuxMethod — метод мультиплексора net/http либо шлюза.
func (a *surfaceFlow) isMuxMethod(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() != nil && (a.isHTTPMuxType(sig.Recv().Type()) || a.isGatewayMuxType(sig.Recv().Type()))
}

// muxImplements — реализует ли мультиплексор интерфейс, объявивший метод fn.
func (a *surfaceFlow) muxImplements(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	it, ok := sig.Recv().Type().Underlying().(*types.Interface)
	if !ok {
		return false
	}
	for _, t := range []types.Type{a.httpMuxT, a.gwMuxT} {
		if t != nil && types.Implements(t, it) {
			return true
		}
	}
	return false
}

// boundKind — метод, который берётся значением ВМЕСТЕ с получателем: метод
// мультиплексора и метод интерфейса, который мультиплексор реализует.
func (a *surfaceFlow) boundKind(fn *types.Func) bool {
	return a.isMuxMethod(fn) || (isIfaceMethod(fn) && a.muxImplements(fn))
}

func (a *surfaceFlow) addBound(v *absVal, recvs avSet) {
	cur, ok := a.boundRecv[v]
	if !ok {
		cur = avSet{}
		a.boundRecv[v] = cur
	}
	if cur.addAll(recvs) {
		a.changed = true
	}
}

func methodOf(t types.Type, name string) *types.Func {
	for _, tt := range []types.Type{t, types.NewPointer(t)} {
		ms := types.NewMethodSet(tt)
		if sel := ms.Lookup(nil, name); sel != nil {
			if fn, ok := sel.Obj().(*types.Func); ok {
				return fn
			}
		}
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() == name {
				if fn, ok := ms.At(i).Obj().(*types.Func); ok {
					return fn
				}
			}
		}
	}
	return nil
}

func (a *surfaceFlow) bind(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, c surfaceCallee) {
	sig := a.sigOf(c.key())
	if sig == nil {
		return
	}
	args := call.Args
	if sig.Recv() != nil && a.interesting(sig.Recv().Type()) {
		a.setVar(sig.Recv(), a.receivers(sp, fk, call, c))
	}
	if c.shift && len(args) > 0 {
		args = args[1:]
	}
	params := sig.Params()
	for i, arg := range args {
		var p *types.Var
		switch {
		case sig.Variadic() && i >= params.Len()-1:
			p = params.At(params.Len() - 1)
		case i < params.Len():
			p = params.At(i)
		}
		if p == nil || !a.interesting(p.Type()) {
			continue
		}
		a.setVar(p, a.eval(sp, fk, arg))
	}
}

// fnName — полное имя функции для находки: путь пакета, получатель, имя.
func fnName(fn *types.Func) string {
	if fn == nil {
		return "?"
	}
	pkg := ""
	if fn.Pkg() != nil {
		pkg = fn.Pkg().Path() + "."
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := namedOf(sig.Recv().Type()); n != nil {
			return pkg + n.Obj().Name() + "." + fn.Name()
		}
	}
	return pkg + fn.Name()
}

// external — вызов функции вне радиуса: что о её результате известно.
func (a *surfaceFlow) external(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, fn *types.Func, idx int) avSet {
	name := fnName(fn)
	switch name {
	case "net/http.NewServeMux":
		return avSet{a.intern(avKey{kind: avHTTPMux, site: call.Pos()}, fk, nil, sp): {}}
	case gatewayRuntimePkg + ".NewServeMux":
		return avSet{a.intern(avKey{kind: avGatewayMux, site: call.Pos()}, fk, nil, sp): {}}
	case "net/http.NotFoundHandler":
		return avSet{a.intern(avKey{kind: avNotFound, site: call.Pos()}, fk, nil, sp): {}}
	}
	sig, _ := fn.Type().(*types.Signature)
	kids := avSet{}
	muxEscapes := false
	for _, arg := range call.Args {
		for v := range a.eval(sp, fk, arg) {
			switch v.kind {
			case avHTTPMux, avGatewayMux:
				muxEscapes = true
				kids.add(v)
			case avBound:
				kids.add(v)
				for r := range a.boundRecv[v] {
					if r.kind == avHTTPMux || r.kind == avGatewayMux {
						muxEscapes = true
					}
				}
			case avStruct, avFunc, avClosure, avOpaque, avExtWrap, avNotFound:
				kids.add(v)
			}
		}
	}
	// Пакет, объявивший тип мультиплексора, — его собственное API (как
	// методы): функции шлюза, читающие настройки своего мультиплексора
	// (AnnotateContext, HTTPError, ForwardResponseMessage), маршрутов не
	// заводят. Передача ЧУЖОМУ пакету — место, где регистрацию не увидеть.
	ownAPI := fn.Pkg() != nil && (fn.Pkg().Path() == "net/http" || fn.Pkg().Path() == gatewayRuntimePkg)
	if muxEscapes && !ownAPI {
		a.escapes[call.Pos()] = escapeRef{name: name, fk: fk}
	}
	if sig == nil || idx >= sig.Results().Len() {
		return nil
	}
	rt := sig.Results().At(idx).Type()
	if !a.isHandlerType(rt) && !isHandlerFuncSig(rt) {
		return nil
	}
	if len(kids) == 0 {
		return avSet{a.intern(avKey{kind: avOpaque, site: call.Pos(), fn: fn}, fk, nil, sp): {}}
	}
	w := a.intern(avKey{kind: avExtWrap, site: call.Pos(), fn: fn}, fk, nil, sp)
	a.extCalls[w] = flowNode{sp, fk, call}
	cur, ok := a.extKids[w]
	if !ok {
		cur = avSet{}
		a.extKids[w] = cur
	}
	if cur.addAll(kids) {
		a.changed = true
	}
	return avSet{w: {}}
}

// ─── регистрации ────────────────────────────────────────────────────────────

// regKindOf — регистрация ли вызов callee и какого вида. Судит ВЫЗЫВАЕМЫЙ
// метод, а не синтаксис вызова: прямой выбор, значение метода, выражение
// метода, метод интерфейса и параметра типа, продвинутый из встроенного поля
// метод сводятся к одному и тому же методу мультиплексора.
func (a *surfaceFlow) regKindOf(c surfaceCallee, call *ast.CallExpr) regKind {
	if c.fn == nil || c.fn.Pkg() == nil {
		return 0
	}
	nargs := len(call.Args)
	if c.shift {
		nargs--
	}
	sig, ok := c.fn.Type().(*types.Signature)
	if !ok {
		return 0
	}
	name := c.fn.Name()
	switch {
	case sig.Recv() == nil:
		if c.fn.Pkg().Path() == "net/http" && (name == "Handle" || name == "HandleFunc") && nargs == 2 {
			return regDefault
		}
	case a.isHTTPMuxType(sig.Recv().Type()):
		if (name == "Handle" || name == "HandleFunc") && nargs == 2 {
			return regHTTP
		}
	case a.isGatewayMuxType(sig.Recv().Type()):
		switch {
		case name == "Handle" && nargs == 3:
			return regGatewayPattern
		case name == "HandlePath" && nargs == 3:
			return regGatewayPath
		}
	}
	return 0
}

// ifaceRegKind — вид регистрации, которой был бы вызов метода интерфейса,
// окажись получателем мультиплексор.
func (a *surfaceFlow) ifaceRegKind(fn *types.Func, nargs int) regKind {
	if !isIfaceMethod(fn) {
		return 0
	}
	it, _ := fn.Type().(*types.Signature).Recv().Type().Underlying().(*types.Interface)
	if it == nil {
		return 0
	}
	name := fn.Name()
	switch {
	case a.httpMuxT != nil && types.Implements(a.httpMuxT, it) && (name == "Handle" || name == "HandleFunc") && nargs == 2:
		return regHTTP
	case a.gwMuxT != nil && types.Implements(a.gwMuxT, it) && name == "Handle" && nargs == 3:
		return regGatewayPattern
	case a.gwMuxT != nil && types.Implements(a.gwMuxT, it) && name == "HandlePath" && nargs == 3:
		return regGatewayPath
	}
	return 0
}

// newReg — регистрация вида k по аргументам (без получателя).
func (a *surfaceFlow) newReg(k regKind, args []ast.Expr) *surfaceReg {
	switch k {
	case regGatewayPattern, regGatewayPath:
		return &surfaceReg{kind: k, method: args[0], path: args[1], handler: args[2]}
	}
	return &surfaceReg{kind: k, path: args[0], handler: args[1]}
}

// register — регистрация на мультиплексорах-получателях вызова.
func (a *surfaceFlow) register(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, c surfaceCallee, k regKind) {
	args := call.Args
	if c.shift {
		args = args[1:]
	}
	reg := a.newReg(k, args)
	reg.call, reg.pkg, reg.fk = call, sp, fk
	muxes := avSet{}
	if k == regDefault {
		muxes.add(a.defMux)
	} else {
		for v := range a.receivers(sp, fk, call, c) {
			if v.kind == avHTTPMux || v.kind == avGatewayMux {
				muxes.add(v)
			}
		}
	}
	if len(muxes) == 0 {
		if _, ok := a.untraced[call]; !ok {
			a.untraced[call] = reg
		}
		return
	}
	for m := range muxes {
		seen, ok := a.regSeen[m]
		if !ok {
			seen = map[*ast.CallExpr]bool{}
			a.regSeen[m] = seen
		}
		if seen[call] {
			continue
		}
		seen[call] = true
		a.regs[m] = append(a.regs[m], reg)
		a.changed = true
	}
}

// effectiveRegs — регистрации значения с унаследованными от прародителя.
func (a *surfaceFlow) effectiveRegs(m *absVal) []*surfaceReg {
	var out []*surfaceReg
	seen := map[*ast.CallExpr]bool{}
	for v := m; v != nil; v = v.parent {
		for _, r := range a.regs[v] {
			if !seen[r.call] {
				seen[r.call] = true
				out = append(out, r)
			}
		}
	}
	return out
}

// ─── достижимость ───────────────────────────────────────────────────────────

// reachable — функции, достижимые от входа процесса: main, init, инициализация
// пакетов; методы типа, чьё значение рождено или чей тип употреблён в
// достижимом коде (литерал, приведение, объявление переменной, new), достижимы
// все: их зовёт чужой код — сервер, маршрутизатор — и вызов через интерфейс.
// Употреблённый тип несёт нулевые значения своих полей, и их методы тоже
// достижимы.
func (a *surfaceFlow) reachable() map[fkey]bool {
	seen := map[fkey]bool{{}: true}
	var work []fkey
	push := func(k fkey) {
		if !seen[k] {
			seen[k] = true
			work = append(work, k)
		}
	}
	for fn, fd := range a.decls {
		if fd.decl.Recv == nil && (fn.Name() == "init" || (fn.Name() == "main" && fd.pkg.root)) {
			push(fkey{fn: fn})
		}
	}
	work = append(work, fkey{})
	structsOf := map[fkey][]*absVal{}
	for _, v := range a.vals {
		if v.kind == avStruct && v.parent == nil {
			structsOf[v.origin] = append(structsOf[v.origin], v)
		}
	}
	used := map[types.Type]bool{}
	var useType func(t types.Type)
	useType = func(t types.Type) {
		t = types.Unalias(t)
		if t == nil || used[t] {
			return
		}
		used[t] = true
		switch u := t.(type) {
		case *types.Named:
			for _, tt := range []types.Type{u, types.NewPointer(u)} {
				ms := types.NewMethodSet(tt)
				for i := 0; i < ms.Len(); i++ {
					if fn, ok := ms.At(i).Obj().(*types.Func); ok {
						push(fkey{fn: fn.Origin()})
					}
				}
			}
			useType(u.Underlying())
		case *types.Pointer:
			useType(u.Elem())
		case *types.Array:
			useType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				useType(u.Field(i).Type())
			}
		}
	}
	for len(work) > 0 {
		k := work[len(work)-1]
		work = work[:len(work)-1]
		for to := range a.edges[k] {
			push(to)
		}
		for _, v := range structsOf[k] {
			useType(v.typ)
		}
		for _, tn := range a.typeUses[k] {
			useType(tn.Type())
		}
	}
	return seen
}

// ─── делегирование ──────────────────────────────────────────────────────────

// delegates — кому обработчик передаёт запрос. isHandler=false — значение не
// обработчик; пустой kids при isHandler — конечная точка.
func (a *surfaceFlow) delegates(v *absVal) (kids avSet, isHandler bool, desc string) {
	switch v.kind {
	case avStruct:
		if v.typ == nil {
			return nil, false, ""
		}
		m := methodOf(v.typ, "ServeHTTP")
		if m == nil {
			return nil, false, ""
		}
		desc = "обёртка " + typeName(v.typ)
		fd, ok := a.decls[m.Origin()]
		if !ok || fd.decl.Body == nil {
			return nil, true, desc
		}
		var recv *types.Var
		if sig, ok := m.Origin().Type().(*types.Signature); ok {
			recv = sig.Recv()
		}
		return a.targets(fd.pkg, fkey{fn: m.Origin()}, fd.decl.Body, recv, v), true, desc
	case avClosure:
		sp := a.litPkg[v.lit]
		if sp == nil {
			return nil, true, ""
		}
		return a.targets(sp, fkey{lit: v.lit}, v.lit.Body, nil, nil), true, "функция-обёртка " + position(a.prog.fset, v.lit.Pos())
	case avFunc:
		fd, ok := a.decls[v.fn]
		if !ok || fd.decl.Body == nil {
			return nil, true, ""
		}
		return a.targets(fd.pkg, fkey{fn: v.fn}, fd.decl.Body, nil, nil), true, "функция " + fnName(v.fn)
	case avOpaque:
		return nil, true, ""
	case avExtWrap:
		return a.extKids[v], true, "чужая обёртка " + fnName(v.fn)
	case avHTTPMux, avGatewayMux:
		return nil, true, ""
	case avBound:
		if v.fn.Name() == "ServeHTTP" {
			return a.boundRecv[v], true, "метод " + fnName(v.fn) + " получателя"
		}
		return nil, false, ""
	}
	return nil, false, ""
}

// targets — выражения, которым тело передаёт запрос: X.ServeHTTP(…) и X(w, r)
// над переменной или полем. Выбор, начатый с получателя, читается у ЭТОГО
// значения, а не у всех, текущих в получатель.
func (a *surfaceFlow) targets(sp *surfaceSrcPkg, fk fkey, body *ast.BlockStmt, recv *types.Var, self *absVal) avSet {
	out := avSet{}
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var target ast.Expr
		switch f := ast.Unparen(call.Fun).(type) {
		case *ast.SelectorExpr:
			if f.Sel.Name == "ServeHTTP" {
				if s, ok := sp.info.Selections[f]; ok && s.Kind() == types.MethodVal {
					target = f.X
				}
			} else if s, ok := sp.info.Selections[f]; ok && s.Kind() == types.FieldVal && isHandlerFuncSig(s.Type()) {
				target = f
			}
		case *ast.Ident:
			if v, ok := sp.info.Uses[f].(*types.Var); ok && isHandlerFuncSig(v.Type()) {
				target = f
			}
		}
		if target == nil {
			return true
		}
		if self != nil && recv != nil {
			if vals, ok := a.readFromSelf(sp, target, recv, self); ok {
				out.addAll(vals)
				return true
			}
		}
		out.addAll(a.eval(sp, fk, target))
		return true
	})
	return out
}

// readFromSelf — выбор полей, начатый с получателя метода, у одного значения.
func (a *surfaceFlow) readFromSelf(sp *surfaceSrcPkg, e ast.Expr, recv *types.Var, self *absVal) (avSet, bool) {
	var chain []*ast.SelectorExpr
	cur := ast.Unparen(e)
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			break
		}
		chain = append([]*ast.SelectorExpr{sel}, chain...)
		cur = ast.Unparen(sel.X)
	}
	id, ok := cur.(*ast.Ident)
	if !ok || len(chain) == 0 || sp.info.Uses[id] != recv {
		return nil, false
	}
	owners := avSet{self: {}}
	for _, sel := range chain {
		s, ok := sp.info.Selections[sel]
		if !ok || s.Kind() != types.FieldVal {
			return nil, false
		}
		for _, f := range fieldPath(s) {
			owners = a.readFrom(owners, f)
		}
	}
	return owners, true
}

func typeName(t types.Type) string {
	if n := namedOf(t); n != nil && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Name() + "." + n.Obj().Name()
	}
	return types.TypeString(t, nil)
}

func position(fset *token.FileSet, pos token.Pos) string {
	p := fset.Position(pos)
	return p.Filename + ":" + strconv.Itoa(p.Line)
}

// isServiceContract — объявлен ли тип в пакете контракта поверхности фундамента.
func isServiceContract(t types.Type, name string) bool {
	n := namedOf(t)
	return n != nil && n.Obj().Pkg() != nil && strings.HasSuffix(n.Obj().Pkg().Path(), serviceContractPkg) && n.Obj().Name() == name
}
