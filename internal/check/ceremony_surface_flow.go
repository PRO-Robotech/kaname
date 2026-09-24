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
// шлюза, функции и структуры, их несущие. Строки не текут вперёд — путь
// регистрации сводится к значению ОБРАТНЫМ разбором (ceremony_surface_resolve.go).

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

	// объявления, собранные проходом (судит ceremony_surface.go)
	surfaceLits []flowNode
	raisedLits  []flowNode
	builders    []flowNode
	sinks       []sinkRef
	manual      []flowNode

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
	}
	a.handler = lookupHandlerIface(prog)
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
func (a *surfaceFlow) interesting(t types.Type) bool {
	if t == nil {
		return false
	}
	if v, ok := a.memo[t]; ok {
		return v
	}
	a.memo[t] = false
	v := a.interestingNow(t)
	a.memo[t] = v
	return v
}

func (a *surfaceFlow) interestingNow(t types.Type) bool {
	switch u := types.Unalias(t).(type) {
	case *types.Named:
		if a.isHTTPMuxType(u) || a.isGatewayMuxType(u) || isNamed(u, gatewayRuntimePkg, "Pattern") {
			return true
		}
		if isHandlerFuncSig(u) || a.isHandlerType(u) {
			return true
		}
		return a.interesting(u.Underlying())
	case *types.Pointer:
		return a.isHandlerType(u) || a.interesting(u.Elem())
	case *types.Slice:
		return a.interesting(u.Elem())
	case *types.Array:
		return a.interesting(u.Elem())
	case *types.Chan:
		return a.interesting(u.Elem())
	case *types.Map:
		return a.interesting(u.Key()) || a.interesting(u.Elem())
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if a.interesting(u.Field(i).Type()) {
				return true
			}
		}
		return false
	case *types.Signature:
		if isHandlerFuncSig(u) {
			return true
		}
		for i := 0; i < u.Params().Len(); i++ {
			if a.interesting(u.Params().At(i).Type()) {
				return true
			}
		}
		for i := 0; i < u.Results().Len(); i++ {
			if a.interesting(u.Results().At(i).Type()) {
				return true
			}
		}
		return false
	case *types.Interface:
		return u.NumMethods() > 0 && a.isHandlerType(u)
	case *types.TypeParam:
		return true
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if a.interesting(u.At(i).Type()) {
				return true
			}
		}
	}
	return false
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
					a.walk(sp, fkey{}, d)
				}
			}
			a.idx.structTags(sp, f)
		}
	}
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
		nodes = append(nodes, n)
		fk := stack[len(stack)-1]
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
		case *ast.BinaryExpr:
			if (n.Op == token.EQL || n.Op == token.NEQ) && (isURLPath(sp, n.X) || isURLPath(sp, n.Y)) {
				a.manual = append(a.manual, flowNode{sp, fk, n})
			}
		case *ast.SwitchStmt:
			if n.Tag != nil && isURLPath(sp, n.Tag) {
				a.manual = append(a.manual, flowNode{sp, fk, n})
			}
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
			if fn, ok := sp.info.Uses[n].(*types.Func); ok {
				a.edge(fk, fkey{fn: fn.Origin()})
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
	switch x := unparen(e).(type) {
	case *ast.CallExpr:
		sel, ok := unparen(x.Fun).(*ast.SelectorExpr)
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

// isRequestField — выбор поля name у *http.Request.
func isRequestField(sp *surfaceSrcPkg, e ast.Expr, name string) bool {
	sel, ok := unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	s, ok := sp.info.Selections[sel]
	return ok && s.Kind() == types.FieldVal && isNamed(s.Recv(), "net/http", "Request")
}

// noteCall — построители поверхности, отдача обработчика серверу, сравнение
// пути функцией строк.
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
	case (pkg == "strings" || pkg == "path") && len(call.Args) > 0 && isURLPath(sp, call.Args[0]):
		switch name {
		case "HasPrefix", "HasSuffix", "TrimPrefix", "TrimSuffix", "CutPrefix", "CutSuffix", "Contains", "EqualFold", "Compare", "Index", "Match", "Split", "SplitN", "Fields":
			a.manual = append(a.manual, flowNode{sp, fk, call})
		}
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
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
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

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
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
			if call, ok := unparen(x.Rhs[0]).(*ast.CallExpr); ok {
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
			if call, ok := unparen(x.Values[0]).(*ast.CallExpr); ok {
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
			if call, ok := unparen(x.Results[0]).(*ast.CallExpr); ok {
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
	switch l := unparen(lhs).(type) {
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
				if !types.IsInterface(sel.Recv()) {
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil && a.interesting(sig.Recv().Type()) {
						a.setVar(sig.Recv(), a.eval(sp, fk, x.X))
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
	return a.vars[v]
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
}

func (c surfaceCallee) key() fkey { return fkey{fn: c.fn, lit: c.lit} }

func (a *surfaceFlow) evalCall(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, idx int) avSet {
	fun := unparen(call.Fun)
	if tv, ok := sp.info.Types[fun]; ok && tv.IsType() {
		if len(call.Args) == 1 {
			return a.eval(sp, fk, call.Args[0])
		}
		return nil
	}
	if id, ok := fun.(*ast.Ident); ok {
		if b, ok := sp.info.Uses[id].(*types.Builtin); ok {
			return a.builtin(sp, fk, call, b)
		}
	}
	a.maybeRegister(sp, fk, call)
	out := avSet{}
	for _, c := range a.callees(sp, fk, call) {
		if c.fn != nil {
			a.edge(fk, fkey{fn: c.fn})
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
				if _, ok := t.Underlying().(*types.Struct); ok {
					return avSet{a.intern(avKey{kind: avStruct, site: call.Pos()}, fk, t, sp): {}}
				}
			}
		}
	}
	return nil
}

func (a *surfaceFlow) callees(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) []surfaceCallee {
	switch f := unparen(call.Fun).(type) {
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
				if types.IsInterface(sel.Recv()) {
					return a.dispatch(sp, fk, f.X, fn.Name())
				}
				return []surfaceCallee{{fn: fn.Origin(), recv: f.X}}
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
		}
	}
	return out
}

// dispatch — вызов метода интерфейса: по значениям-структурам получателя.
func (a *surfaceFlow) dispatch(sp *surfaceSrcPkg, fk fkey, recv ast.Expr, name string) []surfaceCallee {
	var out []surfaceCallee
	for _, v := range a.eval(sp, fk, recv).sorted() {
		if v.kind != avStruct || v.typ == nil {
			continue
		}
		if m := methodOf(v.typ, name); m != nil {
			out = append(out, surfaceCallee{fn: m.Origin(), recvVals: avSet{v: {}}})
		}
	}
	return out
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
		switch {
		case c.recv != nil:
			a.setVar(sig.Recv(), a.eval(sp, fk, c.recv))
		case c.recvVals != nil:
			a.setVar(sig.Recv(), c.recvVals)
		case c.shift && len(args) > 0:
			a.setVar(sig.Recv(), a.eval(sp, fk, args[0]))
		}
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

func (a *surfaceFlow) maybeRegister(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) {
	sel, ok := unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return
	}
	var reg *surfaceReg
	var muxes avSet
	if s, ok := sp.info.Selections[sel]; ok && s.Kind() == types.MethodVal {
		switch {
		case a.isHTTPMuxType(s.Recv()) && (sel.Sel.Name == "Handle" || sel.Sel.Name == "HandleFunc") && len(call.Args) == 2:
			reg = &surfaceReg{kind: regHTTP, path: call.Args[0], handler: call.Args[1]}
		case a.isGatewayMuxType(s.Recv()) && sel.Sel.Name == "Handle" && len(call.Args) == 3:
			reg = &surfaceReg{kind: regGatewayPattern, method: call.Args[0], path: call.Args[1], handler: call.Args[2]}
		case a.isGatewayMuxType(s.Recv()) && sel.Sel.Name == "HandlePath" && len(call.Args) == 3:
			reg = &surfaceReg{kind: regGatewayPath, method: call.Args[0], path: call.Args[1], handler: call.Args[2]}
		default:
			return
		}
		muxes = avSet{}
		for v := range a.eval(sp, fk, sel.X) {
			if v.kind == avHTTPMux || v.kind == avGatewayMux {
				muxes.add(v)
			}
		}
	} else if fn, ok := sp.info.Uses[sel.Sel].(*types.Func); ok && fn.Pkg() != nil && fn.Pkg().Path() == "net/http" &&
		(fn.Name() == "Handle" || fn.Name() == "HandleFunc") && len(call.Args) == 2 {
		reg = &surfaceReg{kind: regDefault, path: call.Args[0], handler: call.Args[1]}
		muxes = avSet{a.defMux: {}}
	} else {
		return
	}
	reg.call, reg.pkg, reg.fk = call, sp, fk
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
// пакетов; методы типа, чья структура рождена в достижимом коде, достижимы
// все (их зовёт чужой код — сервер, маршрутизатор).
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
	for len(work) > 0 {
		k := work[len(work)-1]
		work = work[:len(work)-1]
		for to := range a.edges[k] {
			push(to)
		}
		for _, v := range structsOf[k] {
			for _, tt := range []types.Type{v.typ, types.NewPointer(v.typ)} {
				ms := types.NewMethodSet(tt)
				for i := 0; i < ms.Len(); i++ {
					if fn, ok := ms.At(i).Obj().(*types.Func); ok {
						push(fkey{fn: fn.Origin()})
					}
				}
			}
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
		switch f := unparen(call.Fun).(type) {
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
	cur := unparen(e)
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			break
		}
		chain = append([]*ast.SelectorExpr{sel}, chain...)
		cur = unparen(sel.X)
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
