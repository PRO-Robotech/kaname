// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"
	"encoding/hex"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

const maxAccessLabelSourceCandidates = 4096

// Один индекс на область для всех запрошенных определений. Формируется
// из подтверждённых привязок этой же попытки до проверки каждого вопроса.
type accessLabelSourceIndex struct {
	reader     kaname.AccessLabelSourceReader
	proof      WitnessedLowerBound
	requested  map[domain.AccessLabelDefinitionID]bool
	candidates map[domain.AccessLabelDefinitionID][]kaname.AccessLabelSourceCandidate
}

type accessLabelSourceKey struct {
	binding    domain.AccessBindingID
	recipient  domain.Subject
	role       domain.RoleID
	definition domain.AccessLabelDefinitionID
	ruleFP     string
}

func collectAccessLabelSourceIndex(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, scope domain.ScopeAnchor, definitions []domain.AccessLabelDefinitionID) (*accessLabelSourceIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	index := &accessLabelSourceIndex{proof: p}
	// Обычная роль не проверяет optional port и ничего не читает/начисляет.
	if len(definitions) == 0 {
		return index, nil
	}
	reader, ok := w.(kaname.AccessLabelSourceReader)
	if !ok || !p.valid(w) || !p.census.DecisionAt.Equal(p.at) || !p.effects.Complete() || p.effects.Identity() != p.bundle.Identity() {
		return nil, unavailable()
	}
	actor := p.census.Actor
	if actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, unavailable()
	}
	if len(definitions) > maxAccessLabelSourceCandidates {
		return nil, kaname.ErrSourceReadLimit
	}
	index.reader = reader
	index.requested = make(map[domain.AccessLabelDefinitionID]bool, len(definitions))
	index.candidates = make(map[domain.AccessLabelDefinitionID][]kaname.AccessLabelSourceCandidate)
	for _, definition := range definitions {
		if err := reader.ChargeSourceRead(kaname.SourceReadCost{Rows: 1}); err != nil {
			return nil, err
		}
		if _, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityApplyAccessLabel, Anchor: scope, DefinitionID: definition}); err != nil {
			return nil, err
		}
		index.requested[definition] = true
	}
	seen := make(map[accessLabelSourceKey]bool)
	for _, compiled := range p.census.Bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := reader.ChargeSourceRead(kaname.SourceReadCost{Rows: 1}); err != nil {
			return nil, err
		}
		source := compiled.Source
		anchor := domain.ScopeAnchor{Type: string(source.Binding.ResourceType), ID: source.Binding.ResourceID}
		if anchor != scope {
			continue
		}
		effects := compiled.Effects.Effects()
		if err := reader.ChargeSourceRead(kaname.SourceReadCost{Rows: len(effects)}); err != nil {
			return nil, err
		}
		validated := false
		for _, effect := range effects {
			if effect.Kind != granteffect.ApplyAccessLabel || effect.Anchor != scope || !index.requested[effect.DefinitionID] || effect.Condition != (granteffect.Condition{}) {
				continue
			}
			// Неполный совпавший witness не заменяется другим удобным источником.
			if source.Role == nil || source.CapabilityVersion != 1 || !compiled.Effects.Complete() || compiled.Effects.Identity() != p.bundle.Identity() || source.BindingSnapshot == nil || source.RoleSnapshot == nil {
				return nil, kaname.ErrSourceUnconfirmed
			}
			checkpoint, confirmed := p.census.RoleCheckpoints[source.Role.ID]
			if !confirmed || !creatorSourceSupported(*source.Role, source.Recipient) || source.RoleSnapshot.RoleID != source.Role.ID || source.RoleSnapshot.Checkpoint != checkpoint {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if source.Recipient.Validate() != nil || source.Recipient.ID == "*" || (source.Recipient.Type != domain.SubjectTypeGroup && source.Recipient != actor) {
				return nil, unavailable()
			}
			if !validated {
				if err := source.BindingSnapshot.Validate(w, actor, p.at, source.Binding, source.CapabilityVersion); err != nil {
					return nil, err
				}
				snapshot := source.BindingSnapshot.Snapshot()
				if snapshot.BindingID != source.Binding.ID || snapshot.RoleID != source.Role.ID || snapshot.CapabilityVersion != 1 || snapshot.RowXmin == "" || snapshot.RowCTID == "" || source.RoleSnapshot.RowXmin == "" || source.RoleSnapshot.RowCTID == "" {
					return nil, kaname.ErrSourceUnconfirmed
				}
				validated = true
			}
			origin := effect.Provenance
			fp, err := hex.DecodeString(origin.AuthoredRuleFP)
			if source.Binding.ID == "" || source.Binding.RoleID != source.Role.ID || origin.SourceID != string(source.Binding.ID) || origin.RoleID != source.Role.ID || origin.Primitive != "explicit_meta" || err != nil || len(fp) != 32 || hex.EncodeToString(fp) != origin.AuthoredRuleFP || origin.ProjectedRuleFP != origin.AuthoredRuleFP || checkpoint.ModelID != p.bundle.Identity().ModelID || checkpoint.AuthoredID == "" || checkpoint.ProjectionID == "" || checkpoint.RelevantCatalogID == "" || checkpoint.ProjectorVersion != granteffect.ProjectorVersion {
				return nil, unavailable()
			}
			key := accessLabelSourceKey{source.Binding.ID, source.Recipient, source.Role.ID, effect.DefinitionID, origin.AuthoredRuleFP}
			if seen[key] {
				continue
			}
			if len(seen) >= maxAccessLabelSourceCandidates {
				return nil, kaname.ErrSourceReadLimit
			}
			if err := reader.ChargeSourceRead(kaname.SourceReadCost{Rows: 1}); err != nil {
				return nil, err
			}
			seen[key] = true
			index.candidates[effect.DefinitionID] = append(index.candidates[effect.DefinitionID], kaname.AccessLabelSourceCandidate{
				Binding: source.Binding, BindingSnapshot: source.BindingSnapshot, RoleSnapshot: *source.RoleSnapshot,
				BindingID: source.Binding.ID, Recipient: source.Recipient, RoleID: source.Role.ID, Checkpoint: checkpoint,
				Provenance: origin, Scope: scope, DefinitionID: effect.DefinitionID,
			})
		}
	}
	return index, ctx.Err()
}

func (index *accessLabelSourceIndex) check(ctx context.Context, definition domain.AccessLabelDefinitionID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if index == nil || index.reader == nil || !index.requested[definition] || !index.proof.valid(index.reader) {
		return false, unavailable()
	}
	for _, candidate := range index.candidates[definition] {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		// Reader снова проверяет receipt этой попытки и pre-DML состояние. Отрицательный
		// exact source допускает следующий; ошибка или бюджет прерывают всю попытку.
		allowed, cost, readErr := index.reader.CheckAccessLabelSource(ctx, index.proof.census.Actor, index.proof.at, candidate)
		if cost.Rows < 0 || cost.Reads < 0 || (readErr == nil && (cost.Rows < kaname.AccessLabelSourceMinimumRows || cost.Reads != kaname.AccessLabelSourceReads)) {
			return false, kaname.ErrCanonicalSourceInvalid
		}
		if err := index.reader.ChargeSourceRead(cost); err != nil {
			return false, err
		}
		if readErr != nil {
			return false, readErr
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}
