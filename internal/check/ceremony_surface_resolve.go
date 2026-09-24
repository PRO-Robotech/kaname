// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_resolve.go — ЧТО ЗА ПУТЬ стоит в регистрации: обратный
// разбор выражения пути до значений.
//
// Путь сводится к значению теми же правилами, какими его вычислит процесс:
// постоянная (проверка типов уже свернула склейку, локальную постоянную и
// псевдоним импорта), переменная — по всем её записям, поле — по всем записям
// этого поля во всём радиусе (литерал записи данных сюда тоже входит),
// параметр — по всем местам вызова, результат — по всем возвратам, склейка
// значений, fmt.Sprintf над постоянными и несколько чистых функций строк.
//
// Что НЕ сводится, не отбрасывается: оно становится ЛИСТОМ с именем — полем,
// которое заполняет декодер настройки, переменной без записей, вызовом чужой
// функции. Лист — не пропуск: регистрация с листом, не объявленным в
// ведомости, — находка «путь не разрешён».

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// valueSrc — источник значения переменной или поля.
type valueSrc struct {
	pkg      *surfaceSrcPkg
	fk       fkey
	expr     ast.Expr
	tuple    int
	elem     bool
	rangeKey bool
	rangeVal bool
	opAssign bool
}

type callSrc struct {
	pkg  *surfaceSrcPkg
	fk   fkey
	call *ast.CallExpr
}

type paramOf struct {
	fk    fkey
	index int
	recv  bool
	name  string
}

// resolveIndex — индексы записей, собранные одним проходом.
type resolveIndex struct {
	varWrites   map[*types.Var][]valueSrc
	fieldWrites map[*types.Var][]valueSrc
	returns     map[fkey][][]valueSrc
	calls       map[*types.Func][]callSrc
	params      map[*types.Var]paramOf
	tags        map[*types.Var]string
	owners      map[*types.Var]string
	addrTaken   map[*types.Var]bool
}

func newResolveIndex() *resolveIndex {
	return &resolveIndex{
		varWrites:   map[*types.Var][]valueSrc{},
		fieldWrites: map[*types.Var][]valueSrc{},
		returns:     map[fkey][][]valueSrc{},
		calls:       map[*types.Func][]callSrc{},
		params:      map[*types.Var]paramOf{},
		tags:        map[*types.Var]string{},
		owners:      map[*types.Var]string{},
		addrTaken:   map[*types.Var]bool{},
	}
}

func (ix *resolveIndex) write(sp *surfaceSrcPkg, lhs ast.Expr, src valueSrc) {
	switch l := ast.Unparen(lhs).(type) {
	case *ast.Ident:
		if v, ok := sp.info.ObjectOf(l).(*types.Var); ok {
			ix.varWrites[v] = append(ix.varWrites[v], src)
		}
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[l]; ok && sel.Kind() == types.FieldVal {
			p := fieldPath(sel)
			f := p[len(p)-1]
			ix.fieldWrites[f] = append(ix.fieldWrites[f], src)
			return
		}
		if v, ok := sp.info.Uses[l.Sel].(*types.Var); ok {
			ix.varWrites[v] = append(ix.varWrites[v], src)
		}
	case *ast.IndexExpr:
		src.elem = true
		ix.write(sp, l.X, src)
	case *ast.StarExpr:
		ix.write(sp, l.X, src)
	}
}

func (ix *resolveIndex) assign(sp *surfaceSrcPkg, fk fkey, n *ast.AssignStmt) {
	op := n.Tok != token.ASSIGN && n.Tok != token.DEFINE
	for i, lhs := range n.Lhs {
		src := valueSrc{pkg: sp, fk: fk, tuple: -1, opAssign: op}
		switch {
		case len(n.Lhs) == len(n.Rhs):
			src.expr = n.Rhs[i]
		case len(n.Rhs) == 1:
			if call, ok := ast.Unparen(n.Rhs[0]).(*ast.CallExpr); ok {
				src.expr, src.tuple = call, i
			} else if i == 0 {
				src.expr = n.Rhs[0]
			} else {
				continue
			}
		default:
			continue
		}
		ix.write(sp, lhs, src)
	}
}

func (ix *resolveIndex) valueSpec(sp *surfaceSrcPkg, fk fkey, n *ast.ValueSpec) {
	for i, id := range n.Names {
		src := valueSrc{pkg: sp, fk: fk, tuple: -1}
		switch {
		case len(n.Values) == len(n.Names):
			src.expr = n.Values[i]
		case len(n.Values) == 1:
			if call, ok := ast.Unparen(n.Values[0]).(*ast.CallExpr); ok {
				src.expr, src.tuple = call, i
			} else {
				continue
			}
		default:
			continue
		}
		ix.write(sp, id, src)
	}
}

func (ix *resolveIndex) rangeStmt(sp *surfaceSrcPkg, fk fkey, n *ast.RangeStmt) {
	if n.Key != nil {
		ix.write(sp, n.Key, valueSrc{pkg: sp, fk: fk, expr: n.X, tuple: -1, rangeKey: true})
	}
	if n.Value != nil {
		ix.write(sp, n.Value, valueSrc{pkg: sp, fk: fk, expr: n.X, tuple: -1, rangeVal: true})
	}
}

func (ix *resolveIndex) ret(sp *surfaceSrcPkg, fk fkey, n *ast.ReturnStmt, nres int) {
	rs := ix.returns[fk]
	for len(rs) < nres {
		rs = append(rs, nil)
	}
	switch {
	case len(n.Results) == nres:
		for i, r := range n.Results {
			rs[i] = append(rs[i], valueSrc{pkg: sp, fk: fk, expr: r, tuple: -1})
		}
	case len(n.Results) == 1 && nres > 1:
		// return f() — кортеж результатов вызванной функции.
		if call, ok := ast.Unparen(n.Results[0]).(*ast.CallExpr); ok {
			for i := 0; i < nres; i++ {
				rs[i] = append(rs[i], valueSrc{pkg: sp, fk: fk, expr: call, tuple: i})
			}
		}
	}
	ix.returns[fk] = rs
}

func (ix *resolveIndex) call(sp *surfaceSrcPkg, fk fkey, n *ast.CallExpr) {
	var fn *types.Func
	switch f := ast.Unparen(n.Fun).(type) {
	case *ast.Ident:
		fn, _ = sp.info.Uses[f].(*types.Func)
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[f]; ok {
			if sel.Kind() == types.MethodVal && !types.IsInterface(sel.Recv()) {
				fn, _ = sel.Obj().(*types.Func)
			}
		} else {
			fn, _ = sp.info.Uses[f.Sel].(*types.Func)
		}
	}
	if fn != nil {
		fn = fn.Origin()
		ix.calls[fn] = append(ix.calls[fn], callSrc{pkg: sp, fk: fk, call: n})
	}
}

func (ix *resolveIndex) composite(sp *surfaceSrcPkg, fk fkey, n *ast.CompositeLit) {
	tv, ok := sp.info.Types[n]
	if !ok {
		return
	}
	t := tv.Type
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i, el := range n.Elts {
		var f *types.Var
		val := el
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			if id, ok := kv.Key.(*ast.Ident); ok {
				f, _ = sp.info.Uses[id].(*types.Var)
			}
			val = kv.Value
		} else if i < st.NumFields() {
			f = st.Field(i)
		}
		if f != nil {
			ix.fieldWrites[f] = append(ix.fieldWrites[f], valueSrc{pkg: sp, fk: fk, expr: val, tuple: -1})
		}
	}
}

func (ix *resolveIndex) funcParams(sp *surfaceSrcPkg, fk fkey, recv *ast.FieldList, ft *ast.FuncType) {
	if recv != nil {
		for _, f := range recv.List {
			for _, id := range f.Names {
				if v, ok := sp.info.Defs[id].(*types.Var); ok {
					ix.params[v] = paramOf{fk: fk, recv: true, name: id.Name}
				}
			}
		}
	}
	if ft == nil || ft.Params == nil {
		return
	}
	i := 0
	for _, f := range ft.Params.List {
		if len(f.Names) == 0 {
			i++
			continue
		}
		for _, id := range f.Names {
			if v, ok := sp.info.Defs[id].(*types.Var); ok {
				ix.params[v] = paramOf{fk: fk, index: i, name: id.Name}
			}
			i++
		}
	}
}

func (ix *resolveIndex) structTags(sp *surfaceSrcPkg, file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		owner := ""
		var st *ast.StructType
		if ok {
			st, _ = ts.Type.(*ast.StructType)
			owner = sp.path + "." + ts.Name.Name
		} else if s, ok := n.(*ast.StructType); ok {
			st = s
		}
		if st == nil || st.Fields == nil {
			return true
		}
		for _, f := range st.Fields.List {
			for _, id := range f.Names {
				v, ok := sp.info.Defs[id].(*types.Var)
				if !ok {
					continue
				}
				if _, seen := ix.owners[v]; !seen || owner != "" {
					if owner != "" {
						ix.owners[v] = owner
					} else if _, seen := ix.owners[v]; !seen {
						ix.owners[v] = sp.path + ".<анонимная структура>"
					}
				}
				if f.Tag != nil {
					if tag, err := strconv.Unquote(f.Tag.Value); err == nil {
						ix.tags[v] = tag
					}
				}
			}
		}
		return true
	})
}

func (ix *resolveIndex) addressOf(sp *surfaceSrcPkg, n *ast.UnaryExpr) {
	if n.Op != token.AND {
		return
	}
	switch x := ast.Unparen(n.X).(type) {
	case *ast.Ident:
		if v, ok := sp.info.ObjectOf(x).(*types.Var); ok {
			ix.addrTaken[v] = true
		}
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[x]; ok && sel.Kind() == types.FieldVal {
			p := fieldPath(sel)
			ix.addrTaken[p[len(p)-1]] = true
		}
	}
}

// decoderTagged — поле заполняет декодер настройки (тег ключа декодера).
func decoderTagged(tag string) bool {
	st := reflect.StructTag(tag)
	for _, k := range []string{"mapstructure", "yaml", "json", "koanf", "toml", "env", "envconfig"} {
		if _, ok := st.Lookup(k); ok {
			return true
		}
	}
	return false
}

// ─── обратный разбор строк ──────────────────────────────────────────────────

// strRes — значения выражения и его несводимые листы.
type strRes struct {
	vals   map[string]bool
	leaves map[string]bool
}

func newStrRes() *strRes { return &strRes{vals: map[string]bool{}, leaves: map[string]bool{}} }

func (r *strRes) merge(o *strRes) {
	if o == nil {
		return
	}
	for v := range o.vals {
		r.vals[v] = true
	}
	for l := range o.leaves {
		r.leaves[l] = true
	}
}

func (r *strRes) sortedVals() []string {
	out := make([]string, 0, len(r.vals))
	for v := range r.vals {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// valueCeiling — потолок декартова произведения при склейке.
const valueCeiling = 256

// resKind — что сводится к значениям: само выражение, элементы или ключи
// контейнера.
type resKind uint8

const (
	resValue resKind = iota
	resElems
	resKeys
)

type resKey struct {
	e    ast.Expr
	kind resKind
}

// resFrame — сводимое выражение на стеке разбора: low — самый глубокий
// (ближайший к дну стека) узел, на котором обрезан цикл под этим кадром;
// xform — сколько преобразований значения было открыто при входе.
type resFrame struct {
	low   int
	xform int
}

// strResolver — обратный разбор строк.
//
// Цикл записей (P = Q, Q = S, S = P) обрезается на узле, который уже на
// стеке. Результат узла, посчитанный при обрезке цикла ВЫШЕ него, неполон и в
// память не кладётся: иначе значение переменной зависело бы от того, какую
// регистрацию свели первой (kaname#320, круг 3). Окончательным становится
// результат узла, под которым все обрезки — на нём самом или ниже: для цикла
// копирований он и есть объединение всех записей цикла. Цикл, проходящий
// сквозь ПРЕОБРАЗОВАНИЕ значения (склейка, форматирование, функция строк), даёт
// неограниченное множество значений, и это лист, а не молчаливое усечение.
type strResolver struct {
	a       *surfaceFlow
	done    map[resKey]*strRes
	onStack map[resKey]int
	frames  []resFrame
	xform   int
	steps   int
}

func newStrResolver(a *surfaceFlow) *strResolver {
	return &strResolver{a: a, done: map[resKey]*strRes{}, onStack: map[resKey]int{}}
}

// memoized — сводит k вычислением compute с учётом циклов (см. strResolver).
func (r *strResolver) memoized(k resKey, compute func() *strRes) *strRes {
	if res, ok := r.done[k]; ok {
		return res
	}
	if i, ok := r.onStack[k]; ok {
		if r.xform > r.frames[i].xform {
			return leaf("значение пути выводится из самого себя через преобразование — множество значений не ограничено")
		}
		if top := &r.frames[len(r.frames)-1]; i < top.low {
			top.low = i
		}
		return newStrRes()
	}
	r.steps++
	i := len(r.frames)
	r.frames = append(r.frames, resFrame{low: i, xform: r.xform})
	r.onStack[k] = i
	res := compute()
	low := r.frames[i].low
	r.frames = r.frames[:i]
	delete(r.onStack, k)
	if low >= i {
		r.done[k] = res
	} else if low < r.frames[i-1].low {
		r.frames[i-1].low = low
	}
	return res
}

// transform — вычисление, преобразующее значение (не копирование).
func (r *strResolver) transform(f func() *strRes) *strRes {
	r.xform++
	defer func() { r.xform-- }()
	return f()
}

func (r *strResolver) funcLabel(fk fkey) string {
	switch {
	case fk.fn != nil:
		return fnName(fk.fn)
	case fk.lit != nil:
		return "литерал функции " + position(r.a.prog.fset, fk.lit.Pos())
	}
	return "инициализация пакета"
}

func leaf(format string, args ...any) *strRes {
	res := newStrRes()
	res.leaves[fmt.Sprintf(format, args...)] = true
	return res
}

// str — значения строкового выражения.
func (r *strResolver) str(sp *surfaceSrcPkg, fk fkey, e ast.Expr) *strRes {
	if tv, ok := sp.info.Types[e]; ok && tv.Value != nil {
		res := newStrRes()
		if tv.Value.Kind() == constant.String {
			res.vals[constant.StringVal(tv.Value)] = true
		} else {
			res.vals[tv.Value.ExactString()] = true
		}
		return res
	}
	return r.memoized(resKey{e: e, kind: resValue}, func() *strRes { return r.strNow(sp, fk, e) })
}

func (r *strResolver) strNow(sp *surfaceSrcPkg, fk fkey, e ast.Expr) *strRes {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if v, ok := sp.info.ObjectOf(x).(*types.Var); ok {
			return r.variable(v, fk)
		}
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[x]; ok {
			if sel.Kind() == types.FieldVal {
				p := fieldPath(sel)
				return r.field(p[len(p)-1])
			}
			break
		}
		if v, ok := sp.info.Uses[x.Sel].(*types.Var); ok {
			return r.variable(v, fk)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return r.transform(func() *strRes { return concat(r.str(sp, fk, x.X), r.str(sp, fk, x.Y)) })
		}
	case *ast.CallExpr:
		return r.callStr(sp, fk, x, 0)
	case *ast.IndexExpr:
		return r.elemsOf(sp, fk, x.X, false)
	case *ast.StarExpr:
		return r.str(sp, fk, x.X)
	}
	return leaf("выражение %T в %s", e, r.funcLabel(fk))
}

func concat(a, b *strRes) *strRes {
	out := newStrRes()
	for l := range a.leaves {
		out.leaves[l] = true
	}
	for l := range b.leaves {
		out.leaves[l] = true
	}
	for x := range a.vals {
		for y := range b.vals {
			if len(out.vals) >= valueCeiling {
				out.leaves["склейка даёт больше значений, чем потолок разбора"] = true
				return out
			}
			out.vals[x+y] = true
		}
	}
	return out
}

func (r *strResolver) variable(v *types.Var, fk fkey) *strRes {
	ix := r.a.idx
	if p, ok := ix.params[v]; ok {
		return r.param(v, p)
	}
	res := newStrRes()
	writes := ix.varWrites[v]
	if ix.addrTaken[v] {
		res.leaves[fmt.Sprintf("переменная %s (адрес отдан наружу)", v.Name())] = true
	}
	if len(writes) == 0 && !ix.addrTaken[v] {
		res.leaves[fmt.Sprintf("переменная %s (записей нет)", qualVar(v))] = true
	}
	for _, w := range writes {
		if w.elem {
			continue
		}
		res.merge(r.src(w))
	}
	return res
}

func qualVar(v *types.Var) string {
	if v.Pkg() != nil {
		return v.Pkg().Path() + "." + v.Name()
	}
	return v.Name()
}

func (r *strResolver) field(f *types.Var) *strRes {
	ix := r.a.idx
	res := newStrRes()
	owner := ix.owners[f]
	if owner == "" {
		owner = "<вне радиуса>"
	}
	if tag := ix.tags[f]; decoderTagged(tag) {
		res.leaves[fmt.Sprintf("поле %s.%s (заполняется декодером настройки)", owner, f.Name())] = true
	}
	if ix.addrTaken[f] {
		res.leaves[fmt.Sprintf("поле %s.%s (адрес отдан наружу)", owner, f.Name())] = true
	}
	writes := ix.fieldWrites[f]
	if len(writes) == 0 && len(res.leaves) == 0 {
		res.leaves[fmt.Sprintf("поле %s.%s (записей в коде нет)", owner, f.Name())] = true
	}
	for _, w := range writes {
		if w.elem {
			continue
		}
		res.merge(r.src(w))
	}
	return res
}

func (r *strResolver) param(v *types.Var, p paramOf) *strRes {
	if p.fk.lit != nil {
		return leaf("параметр %s литерала функции %s", p.name, position(r.a.prog.fset, p.fk.lit.Pos()))
	}
	if p.recv || p.fk.fn == nil {
		return leaf("получатель %s", r.funcLabel(p.fk))
	}
	sites := r.a.idx.calls[p.fk.fn]
	if len(sites) == 0 {
		return leaf("параметр %s.%s (вызывающих нет)", fnName(p.fk.fn), p.name)
	}
	sig, _ := p.fk.fn.Type().(*types.Signature)
	res := newStrRes()
	for _, s := range sites {
		if sig != nil && sig.Variadic() && p.index == sig.Params().Len()-1 {
			for i := p.index; i < len(s.call.Args); i++ {
				res.merge(r.str(s.pkg, s.fk, s.call.Args[i]))
			}
			continue
		}
		if p.index < len(s.call.Args) {
			res.merge(r.str(s.pkg, s.fk, s.call.Args[p.index]))
		}
	}
	return res
}

func (r *strResolver) src(w valueSrc) *strRes {
	switch {
	case w.opAssign:
		return leaf("составное присваивание в %s", r.funcLabel(w.fk))
	case w.rangeVal:
		return r.elemsOf(w.pkg, w.fk, w.expr, false)
	case w.rangeKey:
		return r.elemsOf(w.pkg, w.fk, w.expr, true)
	case w.tuple >= 0:
		if call, ok := ast.Unparen(w.expr).(*ast.CallExpr); ok {
			return r.callStr(w.pkg, w.fk, call, w.tuple)
		}
	}
	return r.str(w.pkg, w.fk, w.expr)
}

// callStr — значения результата вызова.
func (r *strResolver) callStr(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, idx int) *strRes {
	fun := ast.Unparen(call.Fun)
	if tv, ok := sp.info.Types[fun]; ok && tv.IsType() && len(call.Args) == 1 {
		return r.str(sp, fk, call.Args[0])
	}
	var fn *types.Func
	switch f := fun.(type) {
	case *ast.Ident:
		fn, _ = sp.info.Uses[f].(*types.Func)
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[f]; ok {
			if sel.Kind() == types.MethodVal && types.IsInterface(sel.Recv()) {
				return leaf("динамический вызов %s", f.Sel.Name)
			}
			fn, _ = sel.Obj().(*types.Func)
		} else {
			fn, _ = sp.info.Uses[f.Sel].(*types.Func)
		}
	}
	if fn == nil {
		return leaf("вызов значения функции в %s", r.funcLabel(fk))
	}
	fn = fn.Origin()
	if fd, ok := r.a.decls[fn]; ok && fd.decl.Body != nil {
		rs := r.a.idx.returns[fkey{fn: fn}]
		if idx >= len(rs) || len(rs[idx]) == 0 {
			return leaf("функция %s ничего не возвращает", fnName(fn))
		}
		res := newStrRes()
		for _, w := range rs[idx] {
			res.merge(r.src(w))
		}
		return res
	}
	return r.pure(sp, fk, call, fn)
}

// pure — чистые функции строк, которые процесс вычислит так же, как разбор.
func (r *strResolver) pure(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, fn *types.Func) *strRes {
	name := fnName(fn)
	args := make([]*strRes, len(call.Args))
	r.xform++
	for i, a := range call.Args {
		args[i] = r.str(sp, fk, a)
	}
	r.xform--
	apply := func(f func(vals []string) string) *strRes {
		out := newStrRes()
		combos := [][]string{{}}
		for _, a := range args {
			for l := range a.leaves {
				out.leaves[l] = true
			}
			var next [][]string
			for _, c := range combos {
				for _, v := range a.sortedVals() {
					cc := append(append([]string(nil), c...), v)
					next = append(next, cc)
					if len(next) > valueCeiling {
						out.leaves["вызов даёт больше значений, чем потолок разбора"] = true
						return out
					}
				}
			}
			combos = next
		}
		for _, c := range combos {
			out.vals[f(c)] = true
		}
		return out
	}
	switch name {
	case "fmt.Sprintf":
		// Аргументы-постоянные переносятся с их видом: %d получает число.
		consts := make([]any, len(call.Args))
		for i, a := range call.Args {
			if tv, ok := sp.info.Types[a]; ok && tv.Value != nil {
				consts[i] = constant.Val(tv.Value)
				if tv.Value.Kind() == constant.String {
					consts[i] = constant.StringVal(tv.Value)
				}
			}
		}
		return apply(func(vals []string) string {
			if len(vals) == 0 {
				return ""
			}
			rest := make([]any, 0, len(vals)-1)
			for i, v := range vals[1:] {
				if c := consts[i+1]; c != nil {
					rest = append(rest, c)
					continue
				}
				rest = append(rest, v)
			}
			return fmt.Sprintf(vals[0], rest...)
		})
	case "strings.TrimSpace":
		return apply(func(v []string) string { return strings.TrimSpace(v[0]) })
	case "strings.TrimSuffix":
		return apply(func(v []string) string { return strings.TrimSuffix(v[0], v[1]) })
	case "strings.TrimPrefix":
		return apply(func(v []string) string { return strings.TrimPrefix(v[0], v[1]) })
	case "strings.ToLower":
		return apply(func(v []string) string { return strings.ToLower(v[0]) })
	case "path.Join":
		return apply(func(v []string) string { return path.Join(v...) })
	}
	return leaf("вызов %s", name)
}

// elemsOf — значения элементов контейнера (или ключей).
func (r *strResolver) elemsOf(sp *surfaceSrcPkg, fk fkey, e ast.Expr, keys bool) *strRes {
	kind := resElems
	if keys {
		kind = resKeys
	}
	return r.memoized(resKey{e: e, kind: kind}, func() *strRes { return r.elemsNow(sp, fk, e, keys) })
}

func (r *strResolver) elemsNow(sp *surfaceSrcPkg, fk fkey, e ast.Expr, keys bool) *strRes {
	ix := r.a.idx
	switch x := ast.Unparen(e).(type) {
	case *ast.CompositeLit:
		res := newStrRes()
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if keys {
					res.merge(r.str(sp, fk, kv.Key))
				} else {
					res.merge(r.str(sp, fk, kv.Value))
				}
				continue
			}
			res.merge(r.str(sp, fk, el))
		}
		return res
	case *ast.Ident, *ast.SelectorExpr:
		var writes []valueSrc
		var v *types.Var
		if id, ok := x.(*ast.Ident); ok {
			v, _ = sp.info.ObjectOf(id).(*types.Var)
			if v != nil {
				writes = ix.varWrites[v]
			}
		} else {
			sel := x.(*ast.SelectorExpr)
			if s, ok := sp.info.Selections[sel]; ok && s.Kind() == types.FieldVal {
				p := fieldPath(s)
				v = p[len(p)-1]
				writes = ix.fieldWrites[v]
			} else if vv, ok := sp.info.Uses[sel.Sel].(*types.Var); ok {
				v = vv
				writes = ix.varWrites[v]
			}
		}
		if v == nil {
			break
		}
		if len(writes) == 0 {
			return leaf("контейнер %s (записей нет)", v.Name())
		}
		res := newStrRes()
		for _, w := range writes {
			if w.elem {
				res.merge(r.str(w.pkg, w.fk, w.expr))
				continue
			}
			if w.tuple >= 0 || w.rangeKey || w.rangeVal || w.opAssign {
				res.merge(leaf("контейнер %s из %s", v.Name(), r.funcLabel(w.fk)))
				continue
			}
			res.merge(r.elemsOf(w.pkg, w.fk, w.expr, keys))
		}
		return res
	case *ast.CallExpr:
		if id, ok := ast.Unparen(x.Fun).(*ast.Ident); ok {
			if b, ok := sp.info.Uses[id].(*types.Builtin); ok && b.Name() == "append" && len(x.Args) > 0 {
				res := r.elemsOf(sp, fk, x.Args[0], keys)
				out := newStrRes()
				out.merge(res)
				for _, a := range x.Args[1:] {
					if x.Ellipsis.IsValid() {
						out.merge(r.elemsOf(sp, fk, a, keys))
					} else {
						out.merge(r.str(sp, fk, a))
					}
				}
				return out
			}
		}
	case *ast.SliceExpr:
		return r.elemsOf(sp, fk, x.X, keys)
	}
	return leaf("контейнер %T в %s", e, r.funcLabel(fk))
}

// ─── обратный разбор образцов шлюза ─────────────────────────────────────────

// gwPattern — образец шлюза, собранный из постоянных порождённого кода.
type gwPattern struct {
	version int
	ops     []int
	pool    []string
	verb    string
}

func (p gwPattern) key() string { return fmt.Sprint(p.version, p.ops, p.pool, p.verb) }

type patRes struct {
	vals   []gwPattern
	leaves map[string]bool
}

func (r *strResolver) pattern(sp *surfaceSrcPkg, fk fkey, e ast.Expr) patRes {
	out := patRes{leaves: map[string]bool{}}
	seen := map[string]bool{}
	var walk func(sp *surfaceSrcPkg, fk fkey, e ast.Expr, depth int)
	walk = func(sp *surfaceSrcPkg, fk fkey, e ast.Expr, depth int) {
		if depth > 8 {
			out.leaves["образец шлюза: слишком глубокая цепочка"] = true
			return
		}
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident, *ast.SelectorExpr:
			var v *types.Var
			if id, ok := x.(*ast.Ident); ok {
				v, _ = sp.info.ObjectOf(id).(*types.Var)
			} else if vv, ok := sp.info.Uses[x.(*ast.SelectorExpr).Sel].(*types.Var); ok {
				v = vv
			}
			if v == nil {
				break
			}
			writes := r.a.idx.varWrites[v]
			if len(writes) == 0 {
				out.leaves[fmt.Sprintf("образец шлюза %s (записей нет)", v.Name())] = true
				return
			}
			for _, w := range writes {
				walk(w.pkg, w.fk, w.expr, depth+1)
			}
			return
		case *ast.CallExpr:
			fn := calleeFunc(sp, x)
			switch fnName(fn) {
			case gatewayRuntimePkg + ".MustPattern":
				if len(x.Args) == 1 {
					walk(sp, fk, x.Args[0], depth+1)
					return
				}
			case gatewayRuntimePkg + ".NewPattern":
				if p, ok := r.newPattern(sp, fk, x); ok {
					if !seen[p.key()] {
						seen[p.key()] = true
						out.vals = append(out.vals, p)
					}
					return
				}
				out.leaves["образец шлюза не из постоянных"] = true
				return
			}
		}
		out.leaves[fmt.Sprintf("образец шлюза: выражение %T в %s", e, r.funcLabel(fk))] = true
	}
	walk(sp, fk, e, 0)
	return out
}

func calleeFunc(sp *surfaceSrcPkg, call *ast.CallExpr) *types.Func {
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := sp.info.Uses[f].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel, ok := sp.info.Selections[f]; ok {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		fn, _ := sp.info.Uses[f.Sel].(*types.Func)
		return fn
	}
	return nil
}

func (r *strResolver) newPattern(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) (gwPattern, bool) {
	if len(call.Args) != 4 {
		return gwPattern{}, false
	}
	ver, ok := constInt(sp, call.Args[0])
	if !ok {
		return gwPattern{}, false
	}
	opsLit, ok := ast.Unparen(call.Args[1]).(*ast.CompositeLit)
	if !ok {
		return gwPattern{}, false
	}
	var ops []int
	for _, el := range opsLit.Elts {
		n, ok := constInt(sp, el)
		if !ok {
			return gwPattern{}, false
		}
		ops = append(ops, n)
	}
	poolLit, ok := ast.Unparen(call.Args[2]).(*ast.CompositeLit)
	if !ok {
		return gwPattern{}, false
	}
	var pool []string
	for _, el := range poolLit.Elts {
		tv, ok := sp.info.Types[el]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return gwPattern{}, false
		}
		pool = append(pool, constant.StringVal(tv.Value))
	}
	verb := r.str(sp, fk, call.Args[3])
	if len(verb.leaves) > 0 || len(verb.vals) != 1 {
		return gwPattern{}, false
	}
	return gwPattern{version: ver, ops: ops, pool: pool, verb: verb.sortedVals()[0]}, true
}

func constInt(sp *surfaceSrcPkg, e ast.Expr) (int, bool) {
	tv, ok := sp.info.Types[e]
	if !ok || tv.Value == nil {
		return 0, false
	}
	n, exact := constant.Int64Val(constant.ToInt(tv.Value))
	return int(n), exact
}
