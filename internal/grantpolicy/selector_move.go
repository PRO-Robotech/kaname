// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"
	"errors"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// SelectorMoveEffect — эффект удержанного носителя одного получателя, отдельно
// для общих правил, точного фокуса или физического пересечения. Пустой Before
// без модели означает, что у этого фрагмента нет подтверждённого OLD.
type SelectorMoveEffect struct {
	Carrier     MetadataBinding
	Delta       granteffect.MetadataDelta
	Focal       domain.ResourceRef
	Physical    bool
	UnboundRole bool
}

// RequireSelectorMoveGrants проверяет расширение на прежних фактах автора.
// Писатель до вызова подтверждает полноту и версии источников. Роль,
// чьи правила меняются, не может сама предоставить право на эту правку через
// BindRole. Для неизменённых чужих ролей остаётся обычная политика metadata.
func RequireSelectorMoveGrants(
	ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject,
	moved domain.RoleID, effects []SelectorMoveEffect,
) error {
	if w == nil || w.SemanticBundle() == nil || w.AuthorityFence() == nil || w.AuthorityFence().DecisionAt().IsZero() ||
		moved == "" || actor.Validate() != nil || actor.ID == "*" ||
		(actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return unavailable()
	}
	if len(effects) > granteffect.MaxEffects {
		return kaname.ErrSourceReadLimit
	}
	at, identity := w.AuthorityFence().DecisionAt(), w.SemanticBundle().Identity()
	work := granteffect.NewProofBudget()
	groups := make(map[domain.Subject][]SelectorMoveEffect)
	var wanted []SelectorMoveEffect
	totalEffects, totalBytes := 0, 0
	for _, effect := range effects {
		if err := ctx.Err(); err != nil {
			return err
		}
		carrier := effect.Carrier
		if carrier.ExpiresAt != nil && !carrier.ExpiresAt.After(at) {
			continue
		}
		binding := carrier.Binding
		subjects, err := domain.NormalizeSubjects(binding.Subjects, "", "")
		if err != nil || !slices.Contains(subjects, binding.Recipient) {
			return unavailable()
		}
		if _, err = validateProposed(binding); err != nil {
			return err
		}
		before, after := effect.Delta.Before, effect.Delta.After
		bc, bb, bs := before.Cost()
		ac, ab, as := after.Cost()
		totalEffects += bc + ac
		totalBytes += bb + ab
		if totalEffects > granteffect.MaxEffects || totalBytes > granteffect.MaxInputBytes || !work.Charge(1+bs+as) {
			return kaname.ErrSourceReadLimit
		}
		absent := before.Identity() == (grantcoverage.Identity{}) && bc == 0 && bb == 0 && bs == 0 && len(before.Obligations()) == 0
		if (effect.Focal.Type == "") != (effect.Focal.ID == "") ||
			((effect.Physical || effect.UnboundRole) && (effect.Focal != (domain.ResourceRef{}) || !absent)) ||
			(effect.UnboundRole && (effect.Physical || binding.Role.ID != moved)) {
			return unavailable()
		}
		if (!absent && (!before.Complete() || before.Identity() != identity)) ||
			(carrier.Changes && (!after.Complete() || after.Identity() != identity)) {
			return denied()
		}
		if bc > 0 {
			groups[binding.Recipient] = append(groups[binding.Recipient], effect)
		}
		if carrier.Changes && ac > 0 {
			wanted = append(wanted, effect)
		}
	}

	var proof *WitnessedLowerBound
	for _, effect := range wanted {
		if err := ctx.Err(); err != nil {
			return err
		}
		previous, err := selectorMoveOldEffects(work, groups[effect.Carrier.Binding.Recipient], effect)
		if err != nil {
			return err
		}
		size, _, _ := previous.Cost()
		if size > 0 {
			proved, err := selectorMoveCoverage(work, previous, effect.Delta.After)
			if err != nil {
				return err
			}
			if proved {
				continue
			}
		}
		if proof == nil {
			p, err := CollectWitnessedLowerBound(ctx, w, actor)
			if err != nil {
				return err
			}
			proof = &p
		}
		if err := requireSelectorMoveExpansion(ctx, w, *proof, moved, work, effect, previous); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func selectorMoveOldEffects(work *granteffect.ProofBudget, source []SelectorMoveEffect, wanted SelectorMoveEffect) (granteffect.Set, error) {
	// Физический остаток уже сверен с прежними кортежами носителей.
	// У роли без носителей прежняя выдача отсутствует.
	if wanted.Physical || wanted.UnboundRole {
		return granteffect.Set{}, nil
	}
	if !work.Charge(len(source)) {
		return granteffect.Set{}, kaname.ErrSourceReadLimit
	}
	var old granteffect.UnionBuilder
	for _, prior := range source {
		// Условия, снятые в известном фокусе, верны только для этой
		// координаты в текущем снимке, включая конечную цель привязки.
		if (prior.Focal != (domain.ResourceRef{}) && prior.Focal != wanted.Focal) ||
			!metadataOldCoverageEligible(prior.Carrier, wanted.Carrier) {
			continue
		}
		count, _, _ := prior.Delta.Before.Cost()
		if !work.Charge(count) {
			return granteffect.Set{}, kaname.ErrSourceReadLimit
		}
		if err := old.Add(prior.Delta.Before); err != nil {
			return granteffect.Set{}, errors.Join(kaname.ErrSourceReadLimit, err)
		}
	}
	return old.Build(), nil
}

func requireSelectorMoveExpansion(
	ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound,
	moved domain.RoleID, work *granteffect.ProofBudget, effect SelectorMoveEffect, old granteffect.Set,
) error {
	if !p.valid(w) {
		return unavailable()
	}
	binding := effect.Carrier.Binding
	var explicit bool
	var err error
	if binding.Role.ID == moved {
		caps, err := validateProposed(binding)
		if err != nil {
			return err
		}
		if err = requireProposedAccessLabelCapabilities(ctx, w, p, binding.Scope, caps); err != nil {
			return err
		}
		explicit, err = administrative(ctx, w, p, binding.Scope)
		if err != nil || explicit {
			return err
		}
	} else {
		explicit, err = bindingAuthority(ctx, w, p, binding)
		if err != nil || explicit {
			return err
		}
	}

	oldCount, oldBytes, _ := old.Cost()
	actorCount, actorBytes, _ := p.effects.Cost()
	coverage := p.effects
	if oldCount > 0 {
		if oldCount+actorCount > granteffect.MaxEffects || oldBytes+actorBytes > granteffect.MaxInputBytes ||
			!work.Charge(oldCount+actorCount) {
			return kaname.ErrSourceReadLimit
		}
		if actorCount > 0 {
			coverage = granteffect.Union(old, p.effects)
		} else {
			coverage = old
		}
	}
	proved, err := selectorMoveCoverage(work, coverage, effect.Delta.After)
	if err != nil {
		return err
	}
	if !proved {
		return p.insufficient()
	}
	return nil
}

func selectorMoveCoverage(work *granteffect.ProofBudget, old, next granteffect.Set) (bool, error) {
	proof := work.Prove(old, next)
	if proof.Reason == grantcoverage.ReasonWorkLimit || proof.Reason == grantcoverage.ReasonLimit {
		return false, kaname.ErrSourceReadLimit
	}
	return proof.Status == grantcoverage.Proved, nil
}
