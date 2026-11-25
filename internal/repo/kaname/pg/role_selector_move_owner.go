// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type roleSelectorMoveOwnerInput struct {
	Role           domain.RoleID          `json:"role_id"`
	Version        string                 `json:"version"`
	Physical       json.RawMessage        `json:"physical"`
	Moves          []selectorMovePosition `json:"moves"`
	ProposedRules  json.RawMessage        `json:"proposed_rules"`
	CopyCandidates json.RawMessage        `json:"copy_candidates"`
}

// Вызывается после сверки RR под оградами записывающей транзакции, перед
// получением финальных часов. SQL сам сравнивает физический образ и правила.
func (s *roleSelectorMoveStage) ownerInput(ctx context.Context, w *authorityWriteTx) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source := s.grantCapture()
	if source == nil || !source.lifetime.beforeDecision(w) || w.producerBudget != source.budget ||
		s.captured.proof.role != s.replay.role.ID || s.captured.proof.version != s.replay.version {
		return nil, kaname.ErrSourceUnconfirmed
	}
	key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(s.replay.role.ID)}
	old := source.entries[key]
	if len(old) != 1 || len(s.captured.proof.moves) == 0 ||
		!json.Valid([]byte(old[0].state)) || !json.Valid(s.replay.image) || !json.Valid(s.replay.copyPlan) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(old[0].state)+len(s.replay.image)+len(s.replay.copyPlan) > granteffect.MaxInputBytes {
		return nil, kaname.ErrSourceReadLimit
	}
	input := roleSelectorMoveOwnerInput{
		Role: s.replay.role.ID, Version: s.replay.version, Physical: json.RawMessage(old[0].state),
		Moves: s.captured.proof.moves, ProposedRules: s.replay.image, CopyCandidates: s.replay.copyPlan,
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(raw) > granteffect.MaxInputBytes {
		return nil, kaname.ErrSourceReadLimit
	}
	return raw, ctx.Err()
}

type roleSelectorMoveOwnerDecision struct {
	move   *roleSelectorMoveStage
	writer *authorityWriteTx
	at     time.Time
	copies json.RawMessage
}

// Копии фиксируются после проверки v_update и права выдавать. Программа
// владельца затем проверяет удержанные источники apply для оставшихся ключей.
func (s *roleSelectorMoveStage) recordOwnerDecision(
	ctx context.Context, w *semanticAuthorityWriteTx, copies accessLabelMoveCopies,
) (*roleSelectorMoveOwnerDecision, error) {
	source := s.grantCapture()
	if source == nil || w == nil || copies == nil || !source.lifetime.valid(w.authorityWriteTx, w.bundle) || w.producerBudget != source.budget {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var raw []byte
	raw = append(raw, '[')
	for i, ref := range sortedRefs(slices.Collect(maps.Keys(copies))) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		labels := copies[ref]
		if _, declared := s.replay.updates[ref]; !declared || len(labels) == 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err := chargeNativePolicyBudget(source.budget, 1+len(labels), 0); err != nil {
			return nil, err
		}
		item, err := json.Marshal(accessLabelMoveCopyProposal{Type: ref.Type, ID: ref.ID, NewLabels: labels})
		if err != nil {
			return nil, err
		}
		if len(item)+2 > granteffect.MaxInputBytes-len(raw) {
			return nil, kaname.ErrSourceReadLimit
		}
		if i != 0 {
			raw = append(raw, ',')
		}
		raw = append(raw, item...)
	}
	raw = append(raw, ']')
	return &roleSelectorMoveOwnerDecision{move: s, writer: w.authorityWriteTx, at: w.fence.decisionAt, copies: raw}, ctx.Err()
}

func (d *roleSelectorMoveOwnerDecision) copyInput(w *semanticAuthorityWriteTx) (json.RawMessage, error) {
	if d == nil || w == nil || w.authorityWriteTx == nil || w.authorityWriteTx != d.writer || !d.at.Equal(w.fence.decisionAt) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	source := d.move.grantCapture()
	if source == nil || !source.lifetime.valid(w.authorityWriteTx, w.bundle) || w.producerBudget != source.budget {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return slices.Clone(d.copies), nil
}
