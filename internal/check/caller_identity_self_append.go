// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
)

// В запросе владельца append читает только первый аргумент. Для k присваиваний
// v = append(v, ...) обычный DFS посещает перестановки одних и тех же k рёбер.
// Здесь сворачиваем только этот подграф. У каждого ребра сохраняются два разных
// ключа seen: сам вызов и точное выражение v в его первом аргументе.
func (g *callerGraph) callerSelfAppendObjects(src valueSrc, v *types.Var, refs []valueSrc, storage callerObjectKey,
	seen map[callerObjectSourceID]bool, chain *callerTraceChain) (map[callerObjectKey]bool, bool) {
	// При k <= 16 формулы ниже укладываются в uint64; редкие большие группы
	// остаются на штатном пути. Малые не требуют отдельной проверки.
	const minSites, maxSites = 4, 16
	if len(refs) < minSites || len(refs) > maxSites+1 || g.index == nil || g.index.addrTaken[v] ||
		len(g.live[v]) != 0 || src.pkg.types == nil || v.Pkg() != src.pkg.types || v.IsField() ||
		v.Parent() == nil || v.Parent() == src.pkg.types.Scope() || src.fk == (fkey{}) ||
		src.tuple != -1 || src.elem || src.rangeKey || src.rangeVal || src.opAssign || !callerFreshReplayContext(g.ctx) {
		return nil, false
	}
	if _, ok := ast.Unparen(src.expr).(*ast.Ident); !ok {
		return nil, false
	}
	if _, ok := types.Unalias(v.Type()).(*types.Slice); !ok {
		return nil, false
	}
	if _, parameter := g.parameters[v]; parameter {
		return nil, false
	}
	memo := g.objectMemo
	if g.lifetimeScanning {
		memo = g.initialObjectMemo
	}
	var literal ast.Expr
	var siteCount, free uint64
	ids := make(map[callerObjectSourceID]bool, 2*len(refs))
	for index, ref := range refs {
		if ref.pkg != src.pkg || ref.fk != src.fk || ref.expr == nil || ref.tuple != -1 ||
			ref.elem || ref.rangeKey || ref.rangeVal || ref.opAssign {
			return nil, false
		}
		e := ast.Unparen(ref.expr)
		if lit, ok := e.(*ast.CompositeLit); ok && index == 0 {
			if !types.Identical(src.pkg.info.TypeOf(lit), v.Type()) {
				return nil, false
			}
			// Холодный процесс штатно посетит первый литерал. Лишь после его
			// публикации все последующие чтения имеют одинаковый эффект.
			key := g.internObjectSource(ref)
			answer, warm := memo[key]
			if !warm || seen[key] || answer.unknown || len(answer.objects) != 1 ||
				!answer.objects[callerObjectKey{pkg: src.pkg, expr: lit}] {
				return nil, false
			}
			literal = lit
			continue
		}
		call, ok := e.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return nil, false
		}
		fun, ok := ast.Unparen(call.Fun).(*ast.Ident)
		if !ok {
			return nil, false
		}
		builtin, ok := src.pkg.info.Uses[fun].(*types.Builtin)
		if !ok || builtin.Name() != "append" {
			return nil, false
		}
		first, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
		if !ok || src.pkg.info.Uses[first] != v {
			return nil, false
		}
		left := g.internObjectSource(ref)
		ref.expr = first
		right := g.internObjectSource(ref)
		// Обычный memo проверяется до seen. Если он уже знает одно из двух
		// выражений, исходное ребро может вообще не дойти до отсечения.
		_, leftCached := memo[left]
		_, rightCached := memo[right]
		if left == right || ids[left] || ids[right] || leftCached || rightCached {
			return nil, false
		}
		ids[left], ids[right] = true, true
		siteCount++
		if !seen[left] && !seen[right] {
			free++
		}
	}
	if siteCount < minSites || siteCount > maxSites {
		return nil, false
	}
	if literal == nil {
		if fk, zero := g.zeroVars[v]; !zero || fk != src.fk {
			return nil, false
		}
	}
	// Каждый кадр переменной посещает все k рёбер. Ровно N−1 из k*N
	// попыток создают дочерний кадр, остальные дают по одному object cut.
	frames := uint64(1)
	for i := uint64(1); i <= free; i++ {
		frames = 1 + i*frames
	}
	cycles := (siteCount-1)*frames + 1
	var skips uint64
	if literal != nil && g.lifetimeScanning {
		skips = frames // по одному попаданию в начальный memo на каждом кадре
	}
	if cycles+skips > ^g.resolveCuts || skips > ^g.initialSkips || cycles > ^g.objectCuts ||
		g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		// Порядок наступления overflow и отмены оставляем штатному обходу.
		return nil, false
	}
	// Виртуальные дочерние кадры не публикуют trace с неполным набором
	// зависимостей seen. Обычная внешняя проверка цикла остаётся в Raw.
	g.taintCallerTraces()
	if chain != nil {
		callerTraceScopeDependent(chain)
		chain.bad = true
	}
	g.addCallerSemantic(cycles+skips, skips, cycles, 0)
	objects := map[callerObjectKey]bool{storage: true}
	if literal != nil {
		objects[callerObjectKey{pkg: src.pkg, expr: literal}] = true
	}
	return objects, true
}
