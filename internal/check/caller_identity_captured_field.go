// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package check

import (
	"go/ast"
	"go/types"
)

// callerFunction читает Uses для идентификатора и пакетного селектора, а
// Selections — для метода. Обе таблицы неизменяемы после проверки типов.
func (g *callerGraph) indexDirectCallerMethods() {
	direct := map[*types.Func]bool{}
	record := func(obj types.Object) {
		if f, ok := obj.(*types.Func); ok && f.Signature().Recv() != nil {
			direct[f.Origin()] = true
		}
	}
	for _, sp := range g.p.pkgs {
		if sp == nil || sp.info == nil || sp.info.Uses == nil || sp.info.Selections == nil {
			return
		}
		for _, obj := range sp.info.Uses {
			record(obj)
		}
		for _, selection := range sp.info.Selections {
			record(selection.Obj())
		}
	}
	g.directMethodRefs = direct
}

// Вызов записи-функции box.F(args) использует уже захваченного получателя.
// Если ни одно выражение программы не ссылается на конкретный метод напрямую,
// такой target мог вернуть только boundMethodOwned, который уже внёс каждый
// точный источник в live. Сам box — носитель функции, его нельзя передать
// методом этому target. Для неизученной формы остаётся прежнее связывание.
func (g *callerGraph) capturedCallerField(sp *surfaceSrcPkg, sel *ast.SelectorExpr, s *types.Selection, target *types.Func, sig *types.Signature) bool {
	if s == nil || s.Kind() != types.FieldVal || len(s.Index()) != 1 || target == nil || g.directMethodRefs == nil || g.directMethodRefs[target.Origin()] ||
		len(g.live[sig.Recv().Origin()]) == 0 || sig.TypeParams().Len() != 0 || sig.RecvTypeParams().Len() != 0 {
		return false
	}
	if _, local := g.bodies[callerNode{fn: target.Origin()}]; !local {
		return false
	}
	typ := sp.info.TypeOf(sel.X)
	if typ == nil {
		return false
	}
	holder, recv := namedOf(typ), namedOf(sig.Recv().Type())
	if holder == nil || recv == nil || holder.Origin() == recv.Origin() || holder.TypeParams().Len() != 0 {
		return false
	}
	if _, structHolder := holder.Underlying().(*types.Struct); !structHolder {
		return false
	}
	field, ok := s.Obj().(*types.Var)
	return ok && field.IsField() && types.Identical(field.Type().Underlying(), sig)
}
