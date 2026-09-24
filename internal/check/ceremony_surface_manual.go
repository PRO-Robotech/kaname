// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_manual.go — маршрут, решаемый по ПУТИ ЗАПРОСА в теле
// обработчика: форма монтажа, которой мультиплексор не видит.
//
// # Что опознаётся
//
// Значение, ПРОИЗВЕДЁННОЕ из пути запроса. Источник — сам путь (r.URL.Path,
// RawPath, EscapedPath(), RequestURI, в том числе у *http.Request, встроенного
// в свой тип) и адрес запроса (r.URL, адрес, разобранный из его строки): его
// Path, RawPath, EscapedPath(), RequestURI(), String(). Путь ТЕЧЁТ: в
// переменную, в поле (любой структуры, по всем записям этого поля), в параметр
// вызванной функции — именованной, метода (и в получатель: метод своего
// строкового типа), литерала функции и функции-значения, переданной
// аргументом, записанной в переменную или поле, — в результат функции радиуса,
// сквозь преобразование чужой функцией (strings.ToLower, path.Base,
// strings.Split, url.Parse, fmt.Sprintf), срез, индекс, склейку, приведение.
// Вызов метода интерфейса передаёт путь всем реализациям типов радиуса.
//
// Выведение — наименьшая неподвижная точка по всем записям радиуса сразу, а не
// обход по запросу с памятью: ответ о переменной не зависит от того, кто о ней
// спросил первым (kaname#320, круг 3), и в цикле записей P ↔ Q насчитаны оба
// решения.
//
// Решение о маршруте — место, где такое значение выбирает ветку: сравнение,
// switch по нему, выбор из карты по нему и функция сопоставления над ним —
// признак (результат-булево среди результатов: strings.HasPrefix, path.Match,
// strings.Cut) или позиция (ЕДИНСТВЕННЫЙ целый результат: strings.Index,
// strings.Compare). Счёт записанных байтов (int, error) — не позиция: путь,
// записанный в ответ (fmt.Fprintf, w.Write), маршрута не выбирает.
//
// # Чем не судится (границы, названные прямо)
//
//   - Число, выведенное из пути (длина, разобранный номер), — проверка ввода,
//     а не маршрут: len(r.URL.Path) > N решением не является.
//   - Путь, прошедший через пустой интерфейс, записанный в построитель или
//     буфер (strings.Builder, bytes.Buffer), или функция-значение, пришедшая
//     результатом вызова, дальше не выводятся.
//
// Чтение пути само решением не является: путь, отданный журналу, маршрута не
// выбирает. Чтения и носители считаются отдельно (перепись), чтобы «решений
// ноль» было отличимо от «чтений не видно» и от «выведение ослепло».

import (
	"go/ast"
	"go/token"
	"go/types"
)

// manualRef — решение о маршруте по пути запроса и его форма словом.
type manualRef struct {
	node flowNode
	form string
}

// notePathNode — чтения пути и места-кандидаты; судятся после сбора, когда
// индекс записей переменных полон.
func (a *surfaceFlow) notePathNode(sp *surfaceSrcPkg, fk fkey, n ast.Node) {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		if isURLPath(sp, x) {
			a.pathReads = append(a.pathReads, flowNode{sp, fk, x})
		}
	case *ast.CallExpr:
		if isURLPath(sp, x) {
			a.pathReads = append(a.pathReads, flowNode{sp, fk, x})
		}
		a.pathCands = append(a.pathCands, flowNode{sp, fk, x})
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			a.pathCands = append(a.pathCands, flowNode{sp, fk, x})
		}
	case *ast.SwitchStmt:
		if x.Tag != nil {
			a.pathCands = append(a.pathCands, flowNode{sp, fk, x})
		}
	case *ast.IndexExpr:
		if t := a.typeOf(sp, x.X); t != nil {
			if _, ok := t.Underlying().(*types.Map); ok {
				a.pathCands = append(a.pathCands, flowNode{sp, fk, x})
			}
		}
	}
}

// judgePathCands — решения о маршруте среди кандидатов: сначала неподвижная
// точка выведения по всему радиусу, затем суд над каждым кандидатом.
func (a *surfaceFlow) judgePathCands() {
	d := newPathTaint(a)
	d.solve()
	a.pathCarriers = d.carriers()
	for _, c := range a.pathCands {
		sp, fk := c.pkg, c.fk
		derived := func(e ast.Expr) bool { return d.of(sp, fk, e)&taintPath != 0 }
		var form string
		switch x := c.node.(type) {
		case *ast.BinaryExpr:
			if derived(x.X) || derived(x.Y) {
				form = "сравнение пути"
			}
		case *ast.SwitchStmt:
			if derived(x.Tag) {
				form = "switch по пути"
			}
		case *ast.IndexExpr:
			if derived(x.Index) {
				form = "выбор из карты по пути"
			}
		case *ast.CallExpr:
			fn := calleeFunc(sp, x)
			if fn == nil || !matchesByResult(fn) {
				break
			}
			hit := false
			for _, arg := range x.Args {
				hit = hit || derived(arg)
			}
			if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok {
				if s, ok := sp.info.Selections[sel]; ok && s.Kind() == types.MethodVal {
					hit = hit || derived(sel.X)
				}
			}
			if hit {
				form = "сопоставление пути функцией " + fnName(fn)
			}
		}
		if form != "" {
			a.manual = append(a.manual, manualRef{node: c, form: form})
		}
	}
}

// matchesByResult — функция, чей результат выбирает ветку: признак (булево
// среди результатов) либо позиция (единственный целый результат). Счёт
// записанных байтов (int, error) и функция, возвращающая лишь строки, —
// не решение: результат второй судится там, где его сравнят.
func matchesByResult(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	res := sig.Results()
	for i := 0; i < res.Len(); i++ {
		if b, ok := res.At(i).Type().Underlying().(*types.Basic); ok && b.Info()&types.IsBoolean != 0 {
			return true
		}
	}
	if res.Len() == 1 {
		b, ok := res.At(0).Type().Underlying().(*types.Basic)
		return ok && b.Info()&types.IsInteger != 0
	}
	return false
}

// taint — что значение несёт от запроса.
type taint uint8

const (
	// taintPath — строка (срез строк, байтов, указатель на строку), выведенная
	// из пути запроса.
	taintPath taint = 1 << iota
	// taintURL — адрес ЭТОГО запроса либо разобранный из его пути.
	taintURL
)

// pathTaint — наименьшая неподвижная точка «произведено из пути запроса» по
// переменным, полям, параметрам, получателям и результатам радиуса.
type pathTaint struct {
	a       *surfaceFlow
	vars    map[*types.Var]taint
	results map[fkey][]taint
	funcs   map[*types.Var]map[fkey]bool
	impls   map[*types.Func][]fkey
	// byName — именованные типы радиуса по имени метода их набора методов
	// (своего и указателя): кандидаты в реализации метода интерфейса.
	byName  map[string][]*types.Named
	changed bool
}

func newPathTaint(a *surfaceFlow) *pathTaint {
	d := &pathTaint{a: a, vars: map[*types.Var]taint{}, results: map[fkey][]taint{},
		funcs: map[*types.Var]map[fkey]bool{}, impls: map[*types.Func][]fkey{}, byName: map[string][]*types.Named{}}
	for _, sp := range a.prog.pkgs {
		scope := sp.types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			n, ok := tn.Type().(*types.Named)
			if !ok || n.TypeParams().Len() != 0 || types.IsInterface(n) {
				continue
			}
			ms := types.NewMethodSet(types.NewPointer(n))
			for i := 0; i < ms.Len(); i++ {
				m := ms.At(i).Obj().Name()
				d.byName[m] = append(d.byName[m], n)
			}
		}
	}
	return d
}

// carriers — переменные, параметры и поля, несущие путь или адрес запроса.
func (d *pathTaint) carriers() int {
	n := 0
	for _, t := range d.vars {
		if t != 0 {
			n++
		}
	}
	return n
}

// carrierOf — что может нести значение этого типа.
func carrierOf(t types.Type) taint {
	if t == nil {
		return 0
	}
	if isNamed(t, "net/url", "URL") {
		return taintURL
	}
	if tup, ok := t.(*types.Tuple); ok {
		var out taint
		for i := 0; i < tup.Len(); i++ {
			out |= carrierOf(tup.At(i).Type())
		}
		return out
	}
	if stringish(t) {
		return taintPath
	}
	if p, ok := t.Underlying().(*types.Pointer); ok && stringish(p.Elem()) {
		return taintPath
	}
	return 0
}

// solve — неподвижная точка: записи переменных и полей, возвраты, связывание
// аргументов с параметрами на каждом месте вызова. Решётка конечна (биты по
// конечному числу переменных и функций), обновление монотонно — обход
// заканчивается, и его исход от порядка обхода не зависит.
//
// Записи и вызовы, которым нести нечего по ТИПУ (не строка, не адрес, не
// функция), отбираются один раз: по ним путь не течёт ни в одном раунде.
func (d *pathTaint) solve() {
	ix := d.a.idx
	type written struct {
		v  *types.Var
		ws []valueSrc
	}
	var writes []written
	for _, m := range []map[*types.Var][]valueSrc{ix.varWrites, ix.fieldWrites} {
		for v, ws := range m {
			if carrierOf(v.Type()) != 0 || isFuncType(v.Type()) {
				writes = append(writes, written{v, ws})
			}
		}
	}
	var calls []flowNode
	for _, c := range d.a.pathCands {
		call, ok := c.node.(*ast.CallExpr)
		if !ok {
			continue
		}
		carry := false
		for _, arg := range call.Args {
			t := d.a.typeOf(c.pkg, arg)
			carry = carry || carrierOf(t) != 0 || isFuncType(t)
		}
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			carry = carry || carrierOf(d.a.typeOf(c.pkg, sel.X)) != 0
		}
		if carry {
			calls = append(calls, c)
		}
	}
	for {
		d.changed = false
		for _, w := range writes {
			d.writes(w.v, w.ws)
		}
		for fk, rs := range ix.returns {
			d.returns(fk, rs)
		}
		for _, c := range calls {
			d.bind(c.pkg, c.fk, c.node.(*ast.CallExpr))
		}
		if !d.changed {
			return
		}
	}
}

func (d *pathTaint) setVar(v *types.Var, t taint) {
	if v == nil || t == 0 || d.vars[v]|t == d.vars[v] {
		return
	}
	d.vars[v] |= t
	d.changed = true
}

func (d *pathTaint) setResult(fk fkey, i, n int, t taint) {
	if t == 0 {
		return
	}
	rs := d.results[fk]
	for len(rs) < n {
		rs = append(rs, 0)
	}
	d.results[fk] = rs
	if i < len(rs) && rs[i]|t != rs[i] {
		rs[i] |= t
		d.changed = true
	}
}

func (d *pathTaint) addFuncs(v *types.Var, fks []fkey) {
	if v == nil || len(fks) == 0 {
		return
	}
	cur, ok := d.funcs[v]
	if !ok {
		cur = map[fkey]bool{}
		d.funcs[v] = cur
	}
	for _, k := range fks {
		if !cur[k] {
			cur[k] = true
			d.changed = true
		}
	}
}

func isFuncType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := t.Underlying().(*types.Signature)
	return ok
}

// writes — записи переменной или поля: путь и функции-значения.
func (d *pathTaint) writes(v *types.Var, ws []valueSrc) {
	want := carrierOf(v.Type())
	fn := isFuncType(v.Type())
	if want == 0 && !fn {
		return
	}
	for _, w := range ws {
		if w.expr == nil {
			continue
		}
		if want != 0 {
			var t taint
			if call, ok := ast.Unparen(w.expr).(*ast.CallExpr); ok && w.tuple >= 0 {
				t = d.call(w.pkg, w.fk, call, w.tuple)
			} else {
				t = d.of(w.pkg, w.fk, w.expr)
			}
			d.setVar(v, t&want)
		}
		if fn && w.tuple < 0 {
			d.addFuncs(v, d.funcValues(w.pkg, w.fk, w.expr))
		}
	}
}

// returns — результаты функции: по выражениям возврата и по именованным
// результатам (голый return).
func (d *pathTaint) returns(fk fkey, rs [][]valueSrc) {
	sig := d.a.sigOf(fk)
	if sig == nil {
		return
	}
	n := sig.Results().Len()
	for i := 0; i < n && i < len(rs); i++ {
		want := carrierOf(sig.Results().At(i).Type())
		if want == 0 {
			continue
		}
		for _, w := range rs[i] {
			var t taint
			if call, ok := ast.Unparen(w.expr).(*ast.CallExpr); ok && w.tuple >= 0 {
				t = d.call(w.pkg, w.fk, call, w.tuple)
			} else {
				t = d.of(w.pkg, w.fk, w.expr)
			}
			d.setResult(fk, i, n, t&want)
		}
		if r := sig.Results().At(i); r.Name() != "" {
			d.setResult(fk, i, n, d.vars[r]&want)
		}
	}
}

// bind — аргументы места вызова текут в параметры каждой вызываемой функции,
// выражение получателя — в получатель метода. Вызов, чьи аргументы и
// получатель не несут ни пути, ни функции-значения, связывать нечем: его
// вызываемые (реализации метода интерфейса — перебор типов радиуса) не ищутся.
func (d *pathTaint) bind(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) {
	args := call.Args
	var recv ast.Expr
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if s, ok := sp.info.Selections[sel]; ok {
			switch s.Kind() {
			case types.MethodVal:
				recv = sel.X
			case types.MethodExpr:
				if len(args) > 0 {
					recv, args = args[0], args[1:]
				}
			}
		}
	}
	flows := recv != nil && d.of(sp, fk, recv) != 0
	for _, arg := range args {
		if flows {
			break
		}
		flows = d.of(sp, fk, arg) != 0 || (isFuncType(d.a.typeOf(sp, arg)) && len(d.funcValues(sp, fk, arg)) > 0)
	}
	if !flows {
		return
	}
	targets := d.targets(sp, fk, call)
	for _, t := range targets {
		sig := d.a.sigOf(t)
		if sig == nil {
			continue
		}
		if recv != nil && sig.Recv() != nil {
			d.flow(sp, fk, recv, sig.Recv())
		}
		params := sig.Params()
		for i, arg := range args {
			var p *types.Var
			switch {
			case sig.Variadic() && i >= params.Len()-1 && !call.Ellipsis.IsValid():
				p = params.At(params.Len() - 1)
				// Элемент вариадического параметра течёт в срез.
				if t := d.of(sp, fk, arg); t != 0 {
					d.setVar(p, t&carrierOf(p.Type()))
				}
				continue
			case i < params.Len():
				p = params.At(i)
			}
			if p != nil {
				d.flow(sp, fk, arg, p)
			}
		}
	}
}

// flow — значение выражения течёт в переменную: путь и функции-значения.
func (d *pathTaint) flow(sp *surfaceSrcPkg, fk fkey, e ast.Expr, v *types.Var) {
	if want := carrierOf(v.Type()); want != 0 {
		d.setVar(v, d.of(sp, fk, e)&want)
	}
	if isFuncType(v.Type()) {
		d.addFuncs(v, d.funcValues(sp, fk, e))
	}
}

// funcValues — функции, которые несёт выражение функционального типа. Метод,
// взятый значением, уносит и получатель: он связывается здесь же.
func (d *pathTaint) funcValues(sp *surfaceSrcPkg, fk fkey, e ast.Expr) []fkey {
	switch x := ast.Unparen(e).(type) {
	case *ast.FuncLit:
		return []fkey{{lit: x}}
	case *ast.Ident:
		switch obj := sp.info.Uses[x].(type) {
		case *types.Func:
			return d.withBody(obj.Origin())
		case *types.Var:
			return d.funcsOf(obj)
		}
	case *ast.SelectorExpr:
		if s, ok := sp.info.Selections[x]; ok {
			switch s.Kind() {
			case types.MethodVal:
				fns := d.methodTargets(s.Obj().(*types.Func).Origin())
				for _, t := range fns {
					if sig := d.a.sigOf(t); sig != nil && sig.Recv() != nil {
						d.flow(sp, fk, x.X, sig.Recv())
					}
				}
				return fns
			case types.MethodExpr:
				return d.methodTargets(s.Obj().(*types.Func).Origin())
			case types.FieldVal:
				p := fieldPath(s)
				return d.funcsOf(p[len(p)-1])
			}
			return nil
		}
		switch obj := sp.info.Uses[x.Sel].(type) {
		case *types.Func:
			return d.withBody(obj.Origin())
		case *types.Var:
			return d.funcsOf(obj)
		}
	}
	return nil
}

// targets — функции, которые вызов может исполнить: объявленная функция и
// метод, литерал функции, функция-значение переменной, параметра или поля,
// реализации метода интерфейса.
func (d *pathTaint) targets(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr) []fkey {
	fun := ast.Unparen(call.Fun)
	for {
		switch x := fun.(type) {
		case *ast.IndexExpr:
			fun = ast.Unparen(x.X)
			continue
		case *ast.IndexListExpr:
			fun = ast.Unparen(x.X)
			continue
		}
		break
	}
	if tv, ok := sp.info.Types[fun]; ok && tv.IsType() {
		return nil
	}
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		if s, ok := sp.info.Selections[sel]; ok && s.Kind() != types.FieldVal {
			return d.methodTargets(s.Obj().(*types.Func).Origin())
		}
	}
	return d.funcValues(sp, fk, fun)
}

// methodTargets — метод с телом либо реализации метода интерфейса.
func (d *pathTaint) methodTargets(fn *types.Func) []fkey {
	if !isIfaceMethod(fn) {
		return d.withBody(fn)
	}
	if out, ok := d.impls[fn]; ok {
		return out
	}
	var out []fkey
	it, _ := fn.Type().(*types.Signature).Recv().Type().Underlying().(*types.Interface)
	if it != nil {
		for _, n := range d.byName[fn.Name()] {
			for _, t := range []types.Type{n, types.NewPointer(n)} {
				if !types.Implements(t, it) {
					continue
				}
				obj, _, _ := types.LookupFieldOrMethod(t, true, fn.Pkg(), fn.Name())
				if m, ok := obj.(*types.Func); ok && !isIfaceMethod(m) {
					out = append(out, d.withBody(m.Origin())...)
				}
				break
			}
		}
	}
	d.impls[fn] = out
	return out
}

func (d *pathTaint) withBody(fn *types.Func) []fkey {
	if fd, ok := d.a.decls[fn]; ok && fd.decl.Body != nil {
		return []fkey{{fn: fn}}
	}
	return nil
}

func (d *pathTaint) funcsOf(v *types.Var) []fkey {
	out := make([]fkey, 0, len(d.funcs[v]))
	for k := range d.funcs[v] {
		out = append(out, k)
	}
	return out
}

// of — что выражение несёт от запроса (с учётом того, что может нести его тип).
func (d *pathTaint) of(sp *surfaceSrcPkg, fk fkey, e ast.Expr) taint {
	e = ast.Unparen(e)
	if isURLPath(sp, e) {
		return taintPath
	}
	want := carrierOf(d.a.typeOf(sp, e))
	if want == 0 {
		return 0
	}
	return d.raw(sp, fk, e) & want
}

func (d *pathTaint) raw(sp *surfaceSrcPkg, fk fkey, e ast.Expr) taint {
	switch x := e.(type) {
	case *ast.Ident:
		if v, ok := sp.info.ObjectOf(x).(*types.Var); ok {
			return d.vars[v]
		}
	case *ast.SelectorExpr:
		if isRequestField(sp, x, "URL") {
			return taintURL
		}
		if s, ok := sp.info.Selections[x]; ok {
			if s.Kind() != types.FieldVal {
				return 0
			}
			p := fieldPath(s)
			f := p[len(p)-1]
			out := d.vars[f]
			if isURLPathField(f) && d.of(sp, fk, x.X)&taintURL != 0 {
				out |= taintPath
			}
			return out
		}
		if v, ok := sp.info.Uses[x.Sel].(*types.Var); ok {
			return d.vars[v]
		}
	case *ast.CallExpr:
		return d.call(sp, fk, x, -1)
	case *ast.SliceExpr:
		return d.of(sp, fk, x.X)
	case *ast.IndexExpr:
		return d.of(sp, fk, x.X)
	case *ast.StarExpr:
		return d.of(sp, fk, x.X)
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return d.of(sp, fk, x.X)
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return d.of(sp, fk, x.X) | d.of(sp, fk, x.Y)
		}
	case *ast.CompositeLit:
		var out taint
		for _, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			out |= d.of(sp, fk, el)
		}
		return out
	}
	return 0
}

// call — что несёт результат вызова (idx — член кортежа, -1 — весь).
//
// Функция радиуса — по своим возвратам. Чужая функция (без тела в радиусе)
// над путём несёт путь: strings.ToLower, path.Base, url.Parse. Метод адреса
// запроса несёт путь, если возвращает его (EscapedPath, RequestURI, String,
// JoinPath), и не несёт, если возвращает хост, порт или запрос.
func (d *pathTaint) call(sp *surfaceSrcPkg, fk fkey, call *ast.CallExpr, idx int) taint {
	fun := ast.Unparen(call.Fun)
	if tv, ok := sp.info.Types[fun]; ok && tv.IsType() {
		if len(call.Args) == 1 {
			return d.of(sp, fk, call.Args[0])
		}
		return 0
	}
	if id, ok := fun.(*ast.Ident); ok {
		if b, ok := sp.info.Uses[id].(*types.Builtin); ok {
			var out taint
			if b.Name() == "append" {
				for _, arg := range call.Args {
					out |= d.of(sp, fk, arg)
				}
			}
			return out
		}
	}
	targets := d.targets(sp, fk, call)
	if len(targets) > 0 {
		var out taint
		for _, t := range targets {
			rs := d.results[t]
			if idx >= 0 {
				if idx < len(rs) {
					out |= rs[idx]
				}
				continue
			}
			for _, r := range rs {
				out |= r
			}
		}
		return out
	}
	var in taint
	for _, arg := range call.Args {
		in |= d.of(sp, fk, arg)
	}
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		if s, ok := sp.info.Selections[sel]; ok && s.Kind() == types.MethodVal {
			recv := d.of(sp, fk, sel.X)
			in |= recv & taintPath
			if recv&taintURL != 0 && urlPathMethod(sel.Sel.Name) {
				in |= taintPath
			}
		}
	}
	if in != 0 {
		return taintPath | taintURL
	}
	return 0
}

// urlPathMethod — метод url.URL, возвращающий путь (или адрес с ним).
func urlPathMethod(name string) bool {
	switch name {
	case "EscapedPath", "RequestURI", "String", "JoinPath":
		return true
	}
	return false
}

// isURLPathField — поле пути url.URL.
func isURLPathField(f *types.Var) bool {
	return f.Pkg() != nil && f.Pkg().Path() == "net/url" && (f.Name() == "Path" || f.Name() == "RawPath")
}

// stringish — строка, срез строк или байтов: носители пути.
func stringish(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Info()&types.IsString != 0
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && (b.Info()&types.IsString != 0 || b.Kind() == types.Byte)
	case *types.Tuple:
		for i := 0; i < u.Len(); i++ {
			if stringish(u.At(i).Type()) {
				return true
			}
		}
	}
	return false
}
