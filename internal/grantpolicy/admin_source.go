// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// administrativePrimitives отдельно воспроизводит существующий scope producer.
// Неизвестность остальных эффектов wildcard-роли не отменяет независимо
// доказанный D3 primitive. Исходный incomplete census и lower-bound неизменны.
// Это не фильтрация effects incomplete Set: primitive вычисляется заново из
// живого carrier и подтверждённых authored rules общими production-функциями.
func administrativePrimitives(p WitnessedLowerBound) ([]granteffect.Effect, error) {
	var halves catalog.Halves
	if err := json.Unmarshal(p.bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	out := []granteffect.Effect{}
	for _, binding := range p.census.Bindings {
		source := binding.Source
		if source.Role == nil {
			continue
		}
		role := *source.Role
		if _, ok := p.census.RoleCheckpoints[role.ID]; !ok {
			continue
		}
		scope := domain.ScopeAnchor{Type: string(source.Binding.ResourceType), ID: source.Binding.ResourceID}
		var relations []string
		if len(role.Rules) == 0 {
			for _, rel := range authzmap.BindingScopeRelations(scope.Type, role) {
				relations = append(relations, string(rel))
			}
		} else if len(source.Binding.Target.Resources) == 0 && scope.Type != "cluster" {
			ordinary, _, e := domain.SplitGrantCapabilityRules(role.Rules)
			if e != nil {
				return nil, e
			}
			verbs := facts.VerbsOfType(scope.Type)
			if len(verbs) == 0 {
				verbs = facts.CommonVerbVocabulary()
			}
			authored := domain.RecipientVerbs(source.Recipient, ordinary.ScopeSelfVerbs(scope.Type, verbs), false)
			relations = facts.ScopeSelfRelations(scope.Type, authored, verbs)
		}
		for _, rel := range relations {
			// Только реальные administrative producer отношения, не CRUD tier editor.
			if rel != "admin" && rel != "owner" && rel != "system_admin" && rel != "any_admin" {
				continue
			}
			effects := p.bundle.CompileDirect(granteffect.Direct{SourceID: "admin-primitive:" + string(source.Binding.ID), ObjectType: scope.Type, ObjectID: scope.ID, Relation: rel, Recipient: source.Recipient})
			if !effects.Complete() {
				continue
			}
			for _, effect := range effects.Effects() {
				if effect.Kind == granteffect.ScopeAdmin {
					if len(out) >= granteffect.MaxEffects {
						return nil, kaname.ErrSourceReadLimit
					}
					out = append(out, effect)
				}
			}
		}
	}
	return out, nil
}
