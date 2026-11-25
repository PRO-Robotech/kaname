// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"weak"
)

// Scratch-only observation for a typed Check witness. One cause per returned
// UNKNOWN. No arguments, expression strings, data values or object addresses.
type copiedFieldObservation struct {
	FirstRejection                                                        string
	Reached, Accepted, HasKnownSource, KnownSourceReturnedTrue, Continued bool
}

type finalCause struct {
	Copied                  copiedFieldObservation
	Kind, Nested            string
	NestedAt                token.Pos
	Source, Evidence, Field token.Pos
}

func causeAt(kind string, src ast.Expr, evidence ast.Node, field *types.Var) finalCause {
	c := finalCause{Kind: kind}
	if src != nil {
		c.Source = src.Pos()
	}
	if evidence != nil {
		c.Evidence = evidence.Pos()
	}
	if field != nil {
		c.Field = field.Pos()
	}
	return c
}

type finalSite struct {
	Root             *ast.SelectorExpr
	Seen, Unresolved bool
	CompletedBy      string
	Cause            finalCause
}

type finalCauseProbe struct {
	read        *ast.SelectorExpr
	observed    copiedFieldObservation
	index       map[ast.Expr]int
	memo        map[finalMemoKey]finalSaved
	records     map[weak.Pointer[callerOriginRecord]]finalSaved
	replayCause finalSaved
	rows        [1]finalSite
	sites       [1]finalSite
	warming     [1]bool
	active      *finalSite
	first       finalCause
	muted       bool
	round       int
}

func (d *finalCauseProbe) startRound(n int) {
	if d == nil {
		return
	}
	d.rows = d.sites
	d.round = n
}

func (g *callerGraph) finalReason(kind string, src ast.Expr, evidence ast.Node, field *types.Var) {
	d := g.finalProbe
	if d != nil && d.active != nil && !d.muted && d.first.Kind == "" {
		d.first = causeAt(kind, src, evidence, field)
	}
}

// Object/lifetime machinery can deliberately disregard nested UNKNOWN results.
// Only its returned verdict can enter an enclosing field/receiver decision.
func (g *callerGraph) finalBoundary() *finalCauseProbe {
	d := g.finalProbe
	if d == nil || d.active == nil || d.muted {
		return nil
	}
	d.muted = true
	return d
}

func (d *finalCauseProbe) finishBoundary(unknown bool, why finalCause) {
	d.muted = false
	if unknown && d.first.Kind == "" {
		d.first = why
	}
}

func (g *callerGraph) finalTarget(e ast.Expr) (*finalCauseProbe, *finalSite) {
	d := g.finalProbe
	if d == nil || d.muted || d.active != nil {
		return nil, nil
	}
	i, ok := d.index[e]
	if !ok {
		return nil, nil
	}
	r := &d.rows[i]
	r.Seen = true
	d.active, d.first = r, finalCause{}
	return d, r
}

func (g *callerGraph) finalCacheResult(src valueSrc, answer callerResolveAnswer, root bool, layer string, saved finalSaved) {
	d := g.finalProbe
	if d == nil || d.active == nil || d.muted {
		return
	}
	if root && src.expr == d.active.Root {
		d.active.CompletedBy = layer
	}
	if answer.unknown && d.first.Kind == "" {
		d.first = saved.cause
		if d.first.Kind == "" {
			d.first = causeAt(layer+"_without_origin", src.expr, nil, nil)
		}
	}
}

type finalSaved struct {
	cause finalCause
}

type finalMemoKey struct {
	key     callerResolveKey
	initial bool
}

func (d *finalCauseProbe) saveMemo(key callerResolveKey, initial, unknown bool) {
	if len(d.memo) == 0 && (d.active == nil || d.muted) {
		return
	}
	k := finalMemoKey{key, initial}
	delete(d.memo, k)
	if d.active == nil || d.muted || (!unknown && key.source.expr != d.active.Root) {
		return
	}
	if _, root := d.index[key.source.expr]; !root && len(d.memo) >= 256 {
		return
	}
	if len(d.memo) >= 288 {
		return
	}
	d.memo[k] = finalSaved{cause: d.first}
}
func (d *finalCauseProbe) saveRecord(rec *callerOriginRecord) {
	root := !rec.key.receiver && rec.key.source.expr == d.active.Root
	if (!root && (d.first.Kind == "" || len(d.records) >= 256)) || len(d.records) >= 288 {
		return
	}
	d.records[weak.Make(rec)] = finalSaved{cause: d.first}
}
func (d *finalCauseProbe) recordReason(rec *callerOriginRecord) finalSaved {
	return d.records[weak.Make(rec)]
}

func (p *callerLifetimeProbe) noteFinalDetail(kind string, src ast.Expr) {
	if p.detail != nil && p.detail.Kind == "" {
		*p.detail = causeAt(kind, src, nil, nil)
	}
}
