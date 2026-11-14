// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"sort"
)

// Создаётся только protectPolicyPlan после проверки объединённого RR token.
// Нельзя превратить captured boundary в защищённую простым вызовом checker.
type protectedNativeRead struct {
	boundary *nativeReadBoundary
	global   bool
	budget   *relverdict.AdministrativeReadBudget
}

func (p *protectedNativeRead) NativeScopes(subject, typ, id, relation string) ([]relverdict.AdministrativeScope, bool, error) {
	if p == nil || p.boundary == nil || p.budget == nil {
		return nil, false, kaname.ErrSourceUnconfirmed
	}
	if err := p.boundary.requireQuestion(p.boundary.bundle, subject, relation, typ+":"+id); err != nil {
		return nil, false, err
	}
	if p.global {
		return nil, true, nil
	}
	shape := p.boundary.questions[nativePolicyQuestion{subject, relation, typ, id}]
	root := nativeReadNode{typ, id}
	if shape.capability {
		coordinate, err := grantcapability.Decode(grantcapability.Reference{ObjectType: typ, ObjectID: id, Relation: relation})
		if err != nil {
			return nil, false, err
		}
		root = nativeReadNode{coordinate.Anchor.Type, coordinate.Anchor.ID}
	}
	out := make([]relverdict.AdministrativeScope, 0, len(shape.scopes))
	for n := range shape.scopes {
		depth := 1
		if n == root {
			depth = 0
		}
		out = append(out, relverdict.AdministrativeScope{Type: n.typ, ID: n.id, Depth: depth})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Type < out[j].Type || out[i].Type == out[j].Type && out[i].ID < out[j].ID
	})
	return out, false, nil
}

// Общий счётчик принадлежит одной попытке writer и переживает все вопросы и
// повторные source collections. Вне подключённого subset прежний сбор прежний.
func (w *authorityWriteTx) ChargeSourceRead(cost kaname.SourceReadCost) error {
	if w.producerBudget != nil {
		return chargeNativePolicyBudget(w.producerBudget, cost.Rows, cost.Reads)
	}
	if w.nativeRead == nil {
		return nil
	}
	if w.nativeRead.budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	if err := w.nativeRead.budget.Charge(cost.Rows, cost.Reads); err != nil {
		return kaname.ErrSourceReadLimit
	}
	return nil
}

func chargeNativePolicyBudget(budget *relverdict.AdministrativeReadBudget, rows, reads int) error {
	if budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	if err := budget.Charge(rows, reads); err != nil {
		return kaname.ErrSourceReadLimit
	}
	return nil
}
