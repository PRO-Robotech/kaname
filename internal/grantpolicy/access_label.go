// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Право выдавать apply проверяется до административных сокращений и BindRole.
// Предлагаемые правила задают только вопрос; ответ берётся из прежних источников
// вызывающего и текущей проверки отношений. Роли без apply не добавляют чтений.
func requireProposedAccessLabelCapabilities(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, scope domain.ScopeAnchor, caps []domain.GrantCapabilityRule) error {
	if _, supportsNativeSource := w.(kaname.AccessLabelSourceReader); supportsNativeSource {
		var definitions []domain.AccessLabelDefinitionID
		var seen map[domain.AccessLabelDefinitionID]bool
		for _, cap := range caps {
			if cap.Kind != domain.GrantCapabilityApplyAccessLabel || seen[cap.DefinitionID] {
				continue
			}
			if seen == nil {
				seen = make(map[domain.AccessLabelDefinitionID]bool)
			}
			seen[cap.DefinitionID] = true
			definitions = append(definitions, cap.DefinitionID)
		}
		if len(definitions) == 0 {
			return nil
		}
		index, err := collectAccessLabelSourceIndex(ctx, w, p, scope, definitions)
		if err != nil {
			return err
		}
		for _, definition := range definitions {
			ok, err := index.check(ctx, definition)
			if err != nil {
				return err
			}
			if !ok {
				return p.insufficient()
			}
		}
		return nil
	}
	var witnessed map[domain.AccessLabelDefinitionID]bool
	for _, cap := range caps {
		if cap.Kind != domain.GrantCapabilityApplyAccessLabel {
			continue
		}
		if witnessed == nil {
			if !p.valid(w) || !p.effects.Complete() || p.effects.Identity() != p.bundle.Identity() {
				return unavailable()
			}
			witnessed = make(map[domain.AccessLabelDefinitionID]bool)
			for _, effect := range p.effects.Effects() {
				if effect.Kind == granteffect.ApplyAccessLabel && effect.Anchor == scope && effect.Condition == (granteffect.Condition{}) {
					witnessed[effect.DefinitionID] = false
				}
			}
		}
		checked, found := witnessed[cap.DefinitionID]
		if !found {
			return p.insufficient()
		}
		if checked {
			continue
		}
		ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: cap.Kind, Anchor: scope, DefinitionID: cap.DefinitionID})
		if err != nil {
			return err
		}
		ok, err := check(ctx, w, p.census.Actor, ref.Relation, ref.Object())
		if err != nil {
			return err
		}
		if !ok {
			return p.insufficient()
		}
		witnessed[cap.DefinitionID] = true
	}
	return nil
}
