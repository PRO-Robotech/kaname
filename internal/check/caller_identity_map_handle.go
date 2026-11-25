// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
)

// varWrites объединяет handle карты и payload записей m[k]. Отдельность
// доказываем только для владельца записи и другого конкретного выделения.
// Источники элементов, содержимое карты и её собственные записи не меняются.
func (p *callerLifetimeProbe) separateClosedMapHandle(write callerLifetimeWrite, object callerObjectKey) bool {
	src := write.owner
	if write.whole || src.pkg == nil || src.pkg.info == nil || src.pkg.types == nil || src.expr == nil ||
		src.tuple != -1 || src.elem || src.rangeKey || src.rangeVal || src.opAssign ||
		object.pkg == nil || object.pkg.info == nil || object.expr == nil || object.field != nil || object.zero != nil ||
		p.steps > callerLifetimeStepLimit || !callerFreshReplayContext(p.g.ctx) || p.g.semanticOverflow || p.g.ctx != nil && p.g.ctx.Err() != nil {
		return false
	}
	if !callerExactAllocation(object) {
		return false
	}
	id, ok := ast.Unparen(src.expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := src.pkg.info.Uses[id].(*types.Var)
	if !ok || v.Pkg() != src.pkg.types || v.IsField() || v.Parent() == nil ||
		v.Parent() == src.pkg.types.Scope() && v.Exported() || p.g.index == nil || p.g.index.addrTaken[v] || len(p.g.live[v]) != 0 {
		return false
	}
	if _, isMap := v.Type().Underlying().(*types.Map); !isMap {
		return false
	}
	if _, parameter := p.g.parameters[v]; parameter {
		return false
	}
	if _, indexed := p.g.index.varWrites[v]; !indexed {
		return false
	}
	allocation, found := p.g.closedMapHandles[v]
	if !found {
		allocation = p.g.closedMapHandle(src.pkg, v)
		if p.g.ctx != nil && p.g.ctx.Err() != nil {
			return false
		}
		if p.g.closedMapHandles == nil {
			p.g.closedMapHandles = map[*types.Var]callerObjectKey{}
		}
		// Только переменные из конечного varWrites могут попасть в этот memo.
		p.g.closedMapHandles[v] = allocation
	}
	// Даже неполный ответ owner не позволяет отделить карту от самой себя.
	return allocation.expr != nil && allocation != object
}

// Допустим один прямой literal/make initializer и только m[key] во всех Uses.
// Ни payload, ни его тип не используются для доказательства handle.
func (g *callerGraph) closedMapHandle(sp *surfaceSrcPkg, variable *types.Var) callerObjectKey {
	refs, indexed := g.index.varWrites[variable]
	if !indexed || len(refs) > callerLifetimeStepLimit {
		return callerObjectKey{}
	}
	var initializer ast.Expr
	for _, ref := range refs {
		if ref.elem {
			continue
		}
		if initializer != nil || ref.pkg != sp || ref.expr == nil || ref.tuple != -1 || ref.rangeKey || ref.rangeVal || ref.opAssign {
			return callerObjectKey{}
		}
		initializer = ast.Unparen(ref.expr)
	}
	if initializer == nil || !types.Identical(sp.info.TypeOf(initializer), variable.Type()) {
		return callerObjectKey{}
	}
	allocation := callerObjectKey{pkg: sp, expr: initializer}
	if !callerExactAllocation(allocation) {
		return callerObjectKey{}
	}
	uses := map[*ast.Ident]bool{}
	positions := []token.Pos{variable.Pos()}
	for id, obj := range sp.info.Uses {
		if g.ctx != nil && g.ctx.Err() != nil {
			return callerObjectKey{}
		}
		if obj == variable {
			if len(uses) >= callerLifetimeStepLimit {
				return callerObjectKey{}
			}
			uses[id] = false
			positions = append(positions, id.Pos())
		}
	}
	if len(uses) == 0 {
		return callerObjectKey{}
	}
	slices.Sort(positions)
	declared, complete := false, true
	steps := 0
	for _, file := range sp.files {
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil || !complete {
				return false
			}
			steps++
			if steps > callerLifetimeStepLimit || g.ctx != nil && g.ctx.Err() != nil {
				complete = false
				return false
			}
			// Обходим только ветви, содержащие точное объявление или Uses.
			// Полный census выше включает также замыкания и другие тела пакета.
			i, _ := slices.BinarySearch(positions, node.Pos())
			if i == len(positions) || positions[i] >= node.End() {
				return false
			}
			switch n := node.(type) {
			case *ast.ValueSpec:
				if len(n.Values) == len(n.Names) {
					for i, id := range n.Names {
						if sp.info.Defs[id] == variable && ast.Unparen(n.Values[i]) == initializer {
							declared = true
						}
					}
				}
			case *ast.AssignStmt:
				if n.Tok == token.DEFINE && len(n.Lhs) == 1 && len(n.Rhs) == 1 {
					if id, ok := n.Lhs[0].(*ast.Ident); ok && sp.info.Defs[id] == variable && ast.Unparen(n.Rhs[0]) == initializer {
						declared = true
					}
				}
			case *ast.IndexExpr:
				if id, ok := ast.Unparen(n.X).(*ast.Ident); ok && sp.info.Uses[id] == variable {
					uses[id] = true
				}
			}
			return true
		})
		if !complete {
			return callerObjectKey{}
		}
	}
	if !declared {
		return callerObjectKey{}
	}
	for _, indexed := range uses {
		if !indexed {
			return callerObjectKey{}
		}
	}
	return allocation
}
