// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"encoding/json"
	"reflect"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// Prove сравнивает символические формулы компилятора. Он не проверяет право
// CreateBinding и не превращает исход в разрешение мутации. Равенство регионов
// с метками/creator и конечными ID судит прежнее проверенное ядро.
func Prove(actor, proposed Set) grantcoverage.Result {
	fail := func(reason grantcoverage.Reason, index int) grantcoverage.Result {
		return grantcoverage.Result{Status: grantcoverage.NotProved, Reason: reason, Side: grantcoverage.ProposedSide, Index: index}
	}
	if actor.identity != proposed.identity {
		return fail(grantcoverage.ReasonIdentity, -1)
	}
	if !actor.Complete() || !proposed.Complete() {
		return fail(grantcoverage.ReasonIncomplete, -1)
	}
	if len(actor.effects) > MaxEffects || len(proposed.effects) > MaxEffects-len(actor.effects) {
		return fail(grantcoverage.ReasonLimit, -1)
	}
	if len(proposed.effects) == 0 {
		return fail(grantcoverage.ReasonEmpty, -1)
	}
	steps := MaxSteps
	for i, w := range proposed.effects {
		// Декартово разбиение только по конечным именам каждого уровня. Его предел
		// общий: children не могут умножить локальные лимиты ядра без ограничения.
		cells, ok := splitFinite(w, &steps)
		if !ok {
			return fail(grantcoverage.ReasonWorkLimit, i)
		}
		for _, cell := range cells {
			covered := false
			unresolved := false
			for _, h := range actor.effects {
				steps--
				if steps < 0 {
					return fail(grantcoverage.ReasonWorkLimit, i)
				}
				if residualObligation(h, cell) {
					unresolved = true
				}
				if effectCovers(h, cell, actor.identity, &steps) {
					covered = true
					break
				}
				if steps < 0 {
					return fail(grantcoverage.ReasonWorkLimit, i)
				}
			}
			if !covered {
				if unresolved {
					return fail(grantcoverage.ReasonUnsupported, i)
				}
				return fail(grantcoverage.ReasonUncovered, i)
			}
		}
	}
	return grantcoverage.Result{Status: grantcoverage.Proved, Index: -1}
}

func splitFinite(e Effect, steps *int) ([]Effect, bool) {
	cells := []Effect{e}
	for i, c := range e.Constraints {
		if c.Region.Objects.Kind != grantcoverage.ObjectIDs || len(c.Region.Objects.IDs) < 2 {
			continue
		}
		if len(cells) > MaxEffects/len(c.Region.Objects.IDs) {
			return nil, false
		}
		bytes := 0
		var next []Effect
		for _, cell := range cells {
			for _, id := range c.Region.Objects.IDs {
				*steps--
				if *steps < 0 {
					return nil, false
				}
				copy := cell
				copy.Constraints = cloneConstraints(cell.Constraints)
				copy.Constraints[i].Region.Objects.IDs = []string{id}
				raw, _ := json.Marshal(copy)
				if len(raw) > MaxInputBytes-bytes {
					return nil, false
				}
				bytes += len(raw)
				next = append(next, copy)
			}
		}
		cells = next
	}
	return cells, true
}

func effectCovers(h, w Effect, identity grantcoverage.Identity, steps *int) bool {
	if h.Kind != w.Kind {
		return false
	}
	if h.Condition.Name != "" && h.Condition != w.Condition {
		return false
	}
	switch w.Kind {
	case CreateBinding:
		return h.Anchor == w.Anchor
	case BindRole:
		return h.Anchor == w.Anchor && h.RoleID == w.RoleID
	case Use:
		if h.Type != w.Type || !(h.Action == w.Action || h.Action.Kind == grantcoverage.AllVerbs && w.Action.Kind == grantcoverage.Verb) {
			return false
		}
	case ScopeAdmin:
		if h.Type != w.Type {
			return false
		}
	default:
		return false
	}
	// Wanted ⇒ Held: каждый conjunct источника должен следовать из wanted.
	// Отсутствие ограничений на родителя у actor шире любого children selector.
	for _, hc := range h.Constraints {
		found := false
		for _, wc := range w.Constraints {
			*steps--
			if *steps < 0 {
				return false
			}
			if hc.Type != wc.Type || authzmodel.EffectPathKey(hc.Path) != authzmodel.EffectPathKey(wc.Path) {
				continue
			}
			if hc.Within != nil && (wc.Within == nil || *hc.Within != *wc.Within) {
				continue
			}
			// Между разными областями нельзя выдумывать hierarchy. Такой переход
			// требует writer-proven structural anchor substitution и пока не доказан.
			if regionCovers(hc, wc, identity, steps) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func regionCovers(h, w Constraint, identity grantcoverage.Identity, steps *int) bool {
	// Общее ядро требует проверенный anchor. Для безобластного direct источника
	// он лишь нейтральная одинаковая координата сравнения двух регионов.
	anchor := grantcoverage.Anchor{Type: "cluster", ID: "cluster_root"}
	if h.Within != nil {
		anchor = *h.Within
	} else if w.Within != nil {
		anchor = *w.Within
	}
	cost := len(h.Region.Objects.IDs) + len(w.Region.Objects.IDs) + len(h.Region.Labels) + len(w.Region.Labels) + 1
	*steps -= cost
	if *steps < 0 {
		return false
	}
	action := grantcoverage.Action{Kind: grantcoverage.Relation, Name: "region"}
	effect := func(c Constraint) grantcoverage.Effect {
		return grantcoverage.Effect{Kind: grantcoverage.ResourceUse, Anchor: anchor, Resource: grantcoverage.Resource{Module: "region", Type: c.Type, Action: action, Region: c.Region}}
	}
	req := grantcoverage.Request{Identity: identity, Actor: grantcoverage.EffectSet{Identity: identity, Complete: true, Effects: []grantcoverage.Effect{effect(h)}}, Proposed: grantcoverage.EffectSet{Identity: identity, Complete: true, Effects: []grantcoverage.Effect{effect(w)}}}
	result := grantcoverage.Prove(req)
	return result.Status == grantcoverage.Proved
}

// EqualEffects служит диагностике без выдачи mutable доступа к внутреннему Set.
func EqualEffects(a, b Set) bool {
	return a.identity == b.identity && reflect.DeepEqual(a.effects, b.effects) && reflect.DeepEqual(a.obligations, b.obligations)
}

// residualObligation отличает отсутствующее доказательство преобразования
// условия/структурного пути от доказанного несовпадения имён либо меток.
func residualObligation(h, w Effect) bool {
	if h.Kind != w.Kind || h.Type != w.Type {
		return false
	}
	if w.Kind == Use && !(h.Action == w.Action || h.Action.Kind == grantcoverage.AllVerbs && w.Action.Kind == grantcoverage.Verb) {
		return false
	}
	if h.Condition.Name != "" && h.Condition != w.Condition {
		return true
	}
	for _, hc := range h.Constraints {
		found := false
		for _, wc := range w.Constraints {
			if hc.Type != wc.Type || authzmodel.EffectPathKey(hc.Path) != authzmodel.EffectPathKey(wc.Path) {
				continue
			}
			found = true
			if hc.Within != nil && (wc.Within == nil || *hc.Within != *wc.Within) {
				return true
			}
		}
		if !found && len(hc.Path) > 0 {
			return true
		}
	}
	return false
}
