// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_manual.go — маршрут, решаемый по ПУТИ ЗАПРОСА в теле
// обработчика: форма монтажа, которой мультиплексор не видит.
//
// # Что опознаётся
//
// Значение, ПРОИЗВЕДЁННОЕ из пути запроса: сам путь (r.URL.Path, RawPath,
// EscapedPath(), RequestURI) и всё, что из него выведено строкой — переменная
// с такой записью, преобразование (strings.ToLower, path.Base, path.Clean,
// url.PathUnescape, fmt.Sprintf), срез, склейка, приведение типа, элементы
// strings.Split. Решение о маршруте — место, где такое значение выбирает
// ветку: сравнение, switch по нему, выбор из карты по нему и функция
// сопоставления (результат — признак или позиция: strings.HasPrefix,
// strings.Compare, path.Match, regexp).
//
// Чтение пути само решением не является: путь, отданный журналу, маршрута не
// выбирает. Чтения считаются отдельно (перепись), чтобы «решений ноль» было
// отличимо от «чтений не видно».

import (
	"go/ast"
	"go/token"
	"go/types"
)

// pathCandKind — вид места, где значение может выбирать ветку.
type pathCandKind uint8

const (
	candCompare pathCandKind = iota + 1
	candSwitch
	candMapIndex
	candMatchCall
)

// pathCand — место-кандидат в решение о маршруте.
type pathCand struct {
	node flowNode
	kind pathCandKind
}

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
		a.pathCands = append(a.pathCands, pathCand{flowNode{sp, fk, x}, candMatchCall})
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			a.pathCands = append(a.pathCands, pathCand{flowNode{sp, fk, x}, candCompare})
		}
	case *ast.SwitchStmt:
		if x.Tag != nil {
			a.pathCands = append(a.pathCands, pathCand{flowNode{sp, fk, x}, candSwitch})
		}
	case *ast.IndexExpr:
		if t := a.typeOf(sp, x.X); t != nil {
			if _, ok := t.Underlying().(*types.Map); ok {
				a.pathCands = append(a.pathCands, pathCand{flowNode{sp, fk, x}, candMapIndex})
			}
		}
	}
}

// judgePathCands — решения о маршруте среди кандидатов.
func (a *surfaceFlow) judgePathCands() {
	d := &pathDeriver{a: a, memo: map[*types.Var]bool{}, busy: map[*types.Var]bool{}}
	for _, c := range a.pathCands {
		sp := c.node.pkg
		var form string
		switch x := c.node.node.(type) {
		case *ast.BinaryExpr:
			if d.derived(sp, x.X) || d.derived(sp, x.Y) {
				form = "сравнение пути"
			}
		case *ast.SwitchStmt:
			if d.derived(sp, x.Tag) {
				form = "switch по пути"
			}
		case *ast.IndexExpr:
			if d.derived(sp, x.Index) {
				form = "выбор из карты по пути"
			}
		case *ast.CallExpr:
			if fn := calleeFunc(sp, x); fn != nil && matchesByResult(fn) {
				for _, arg := range x.Args {
					if d.derived(sp, arg) {
						form = "сопоставление пути функцией " + fnName(fn)
						break
					}
				}
			}
		}
		if form != "" {
			a.manual = append(a.manual, manualRef{node: c.node, form: form})
		}
	}
}

// matchesByResult — функция, чей результат выбирает ветку: признак либо
// позиция (strings.HasPrefix, strings.Compare, strings.Index, path.Match,
// (*regexp.Regexp).MatchString). Функция, возвращающая лишь строки, —
// преобразование, а не решение: её результат судится там, где его сравнят.
func matchesByResult(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		b, ok := sig.Results().At(i).Type().Underlying().(*types.Basic)
		if ok && (b.Info()&types.IsBoolean != 0 || b.Info()&types.IsInteger != 0) {
			return true
		}
	}
	return false
}

// pathDeriver — произведено ли строковое значение из пути запроса.
type pathDeriver struct {
	a    *surfaceFlow
	memo map[*types.Var]bool
	busy map[*types.Var]bool
}

func (d *pathDeriver) derived(sp *surfaceSrcPkg, e ast.Expr) bool {
	e = ast.Unparen(e)
	if isURLPath(sp, e) {
		return true
	}
	if !stringish(d.a.typeOf(sp, e)) {
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		if v, ok := sp.info.ObjectOf(x).(*types.Var); ok {
			return d.variable(v)
		}
	case *ast.CallExpr:
		for _, arg := range x.Args {
			if d.derived(sp, arg) {
				return true
			}
		}
		if sel, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok {
			if s, ok := sp.info.Selections[sel]; ok && s.Kind() == types.MethodVal {
				// Метод строки пути (bytes, свой тип) либо адреса запроса
				// (u.EscapedPath(), u.RequestURI(), u.String()).
				return d.derived(sp, sel.X) || d.requestURL(sp, sel.X)
			}
		}
	case *ast.SelectorExpr:
		// u.Path / u.RawPath, где u — адрес ЭТОГО запроса, взятый значением.
		if s, ok := sp.info.Selections[x]; ok && s.Kind() == types.FieldVal {
			if f, ok := s.Obj().(*types.Var); ok && f.Pkg() != nil && f.Pkg().Path() == "net/url" &&
				(f.Name() == "Path" || f.Name() == "RawPath") {
				return d.requestURL(sp, x.X)
			}
		}
	case *ast.SliceExpr:
		return d.derived(sp, x.X)
	case *ast.IndexExpr:
		return d.derived(sp, x.X)
	case *ast.BinaryExpr:
		return x.Op == token.ADD && (d.derived(sp, x.X) || d.derived(sp, x.Y))
	case *ast.StarExpr:
		return d.derived(sp, x.X)
	}
	return false
}

// requestURL — выражение — адрес ЭТОГО запроса: r.URL либо переменная,
// в которую он записан (в том числе разыменованием).
func (d *pathDeriver) requestURL(sp *surfaceSrcPkg, e ast.Expr) bool {
	switch x := ast.Unparen(e).(type) {
	case *ast.SelectorExpr:
		return isRequestField(sp, x, "URL")
	case *ast.StarExpr:
		return d.requestURL(sp, x.X)
	case *ast.UnaryExpr:
		return x.Op == token.AND && d.requestURL(sp, x.X)
	case *ast.Ident:
		v, ok := sp.info.ObjectOf(x).(*types.Var)
		if !ok || d.busy[v] {
			return false
		}
		d.busy[v] = true
		defer delete(d.busy, v)
		for _, w := range d.a.idx.varWrites[v] {
			if w.expr != nil && d.requestURL(w.pkg, w.expr) {
				return true
			}
		}
	}
	return false
}

// variable — хоть одна запись переменной произведена из пути запроса.
func (d *pathDeriver) variable(v *types.Var) bool {
	if r, ok := d.memo[v]; ok {
		return r
	}
	if d.busy[v] {
		return false
	}
	d.busy[v] = true
	r := false
	for _, w := range d.a.idx.varWrites[v] {
		if w.expr != nil && d.derivedWrite(w) {
			r = true
			break
		}
	}
	delete(d.busy, v)
	d.memo[v] = r
	return r
}

// derivedWrite — запись, чей источник произведён из пути: сам источник,
// элемент источника (range, v, ok := m[k]) либо член кортежа вызова над ним.
func (d *pathDeriver) derivedWrite(w valueSrc) bool {
	if d.derived(w.pkg, w.expr) {
		return true
	}
	if call, ok := ast.Unparen(w.expr).(*ast.CallExpr); ok {
		for _, arg := range call.Args {
			if d.derived(w.pkg, arg) {
				return true
			}
		}
	}
	return false
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
