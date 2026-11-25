// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// CompileScopedMaterializedTuple уточняет требуемый физический эффект на OLD
// объекта. Писатель читает объект и фактическую область привязки в одном
// удержанном снимке. Общие эффекты правил и эффекты изменения меток на фокусе
// требуют отдельных проверок, в том числе для будущих объектов.
func (b *Bundle) CompileScopedMaterializedTuple(bindingID domain.AccessBindingID, old domain.MirrorObject, scope domain.ScopeAnchor, recipient domain.Subject, tuple domain.MembershipTuple) Set {
	ref := domain.ResourceRef{Type: old.ObjectType, ID: old.ObjectID}
	leaf := b.CompileMaterializedTuple(bindingID, ref, recipient, tuple)
	if !leaf.Complete() {
		return leaf
	}
	scoped := Set{identity: leaf.identity, steps: leaf.steps}
	fail := func(detail string) Set {
		return Set{identity: leaf.identity, steps: scoped.steps, obligations: []Obligation{{Code: "scoped_materialized_tuple", Detail: detail}}}
	}
	if !domain.IsScopeAnchorKind(scope.Type) || !materializedToken(scope.ID) ||
		domain.DeriveFromResourceType(scope.Type).ValidateAgainst(scope.Type, scope.ID) != nil || !old.IsContainedIn(scope) {
		return fail("OLD object is outside the binding scope or the scope is invalid")
	}
	for _, labels := range []map[string]string{old.Labels, old.AccessLabels} {
		if len(labels) > grantcoverage.MaxSelectorEntries {
			return fail("OLD label input limit")
		}
		typed := make(domain.Labels, len(labels))
		for k, v := range labels {
			if !utf8.ValidString(v) {
				return fail("invalid OLD label value")
			}
			typed[domain.LabelKey(k)] = domain.LabelVal(v)
		}
		if typed.Validate() != nil {
			return fail("invalid OLD labels")
		}
	}
	typ, _ := b.compiler.facts.FGAObjectType(old.ObjectType) // Проверено CompileMaterializedTuple.
	for _, e := range leaf.effects {
		scoped.steps++
		if scoped.steps > MaxSteps {
			return fail("scoped effect work limit")
		}
		// У прямого кортежа единственное ограничение на конце пути вывода.
		// Даже при наследовании OLD описывает только этот объект.
		if len(e.Constraints) != 1 {
			return fail("missing exact primitive constraint")
		}
		c := &e.Constraints[0]
		if c.Type != typ || c.Region.Objects.Kind != grantcoverage.ObjectIDs || len(c.Region.Objects.IDs) != 1 || c.Region.Objects.IDs[0] != old.ObjectID {
			return fail("primitive object coordinate mismatch")
		}
		c.Within = &scope
		c.Region.Labels = old.Labels
		c.Region.AccessLabels = old.AccessLabels
		b.compiler.append(&scoped, e)
		if scoped.limited {
			break
		}
	}
	return scoped
}
