// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

type accessLabelMoveObjectUpdates map[domain.ResourceRef]string

// До удержания плана объявляем вопросы по всем возможным физическим копиям.
// Модельный тип и объектный update подтверждаются тем же снимком каталога.
func (p *resourceParentCapture) captureAccessLabelMoveObjectUpdates(
	ctx context.Context, facts *catalog.Facts, overlay map[domain.ResourceRef]domain.MirrorObject,
) (accessLabelMoveObjectUpdates, error) {
	updates := make(accessLabelMoveObjectUpdates, len(overlay))
	for _, ref := range sortedRefs(slices.Collect(maps.Keys(overlay))) {
		if err := p.source.budget.Charge(1, 0); err != nil {
			return nil, err
		}
		module, resource, ok := strings.Cut(ref.Type, ".")
		if !ok || strings.Contains(resource, ".") || !nativeQuestionToken(module) || !nativeQuestionToken(resource) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if _, supported := metadataBindingRoot(ref.Type); !supported {
			continue
		}
		catalogType, err := p.catalog(ctx, ref.Type)
		if err != nil {
			return nil, err
		}
		row, found := catalogType.selected()
		if !found || !row.live {
			continue
		}
		model, known := facts.FGAObjectType(ref.Type)
		if !known || model != row.identity.ObjectType || row.identity.Dotted != ref.Type || row.identity.Module != module ||
			!nativeQuestionToken(model) || grantcapability.IsInternalObjectType(model) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceRoleMoveObjectUpdate, typ: module, id: resource})
		if err != nil {
			return nil, err
		}
		switch len(rows) {
		case 0:
			// Отсутствие действия тоже сверяется после удержания.
		case 1:
			updates[ref] = model
		default:
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	return updates, ctx.Err()
}

func (updates accessLabelMoveObjectUpdates) declare(
	ctx context.Context, questions *nativePolicyQuestions, actor domain.Subject, budget *relverdict.AdministrativeReadBudget,
) error {
	if updates == nil || budget == nil {
		return kaname.ErrSourceUnconfirmed
	}
	for _, ref := range sortedRefs(slices.Collect(maps.Keys(updates))) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := budget.Charge(1, 0); err != nil {
			return err
		}
		if err := questions.add(actor, "v_update", updates[ref], ref.ID); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Только фактические копии требуют объектного разрешения. Вызов следует
// после финальных часов писателя, до применения меток или изменения роли.
func (updates accessLabelMoveObjectUpdates) require(
	ctx context.Context, checker kaname.RelationChecker, actor domain.Subject, copies accessLabelMoveCopies,
) error {
	if updates == nil || copies == nil || checker == nil || actor.Validate() != nil ||
		(actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) ||
		!nativeQuestionToken(string(actor.ID)) {
		return kaname.ErrSourceUnconfirmed
	}
	for _, ref := range sortedRefs(slices.Collect(maps.Keys(copies))) {
		if err := ctx.Err(); err != nil {
			return err
		}
		model, declared := updates[ref]
		if !declared || !nativeQuestionToken(model) || !nativeQuestionToken(ref.ID) {
			return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Access label move requires object update authority")
		}
		allowed, err := checker.Check(ctx, subjectPolicyKey(actor), "v_update", model+":"+ref.ID)
		if err != nil {
			return err
		}
		if !allowed {
			return iamerr.Wrapf(iamerr.ErrPermissionDenied, "Access label move requires object update authority")
		}
	}
	return ctx.Err()
}

func (s *accessLabelMoveSourceReplay) requireObjectUpdates(
	ctx context.Context, w *semanticAuthorityWriteTx, actor domain.Subject, copies accessLabelMoveCopies,
) error {
	if s == nil || s.parents == nil || s.parents.source == nil || w == nil ||
		!s.parents.source.lifetime.valid(w.authorityWriteTx, w.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	return s.updates.require(ctx, w.SemanticRelationChecker(), actor, copies)
}
