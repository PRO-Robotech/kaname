// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// MetadataBinding — подтверждённая привязка из закрытого снимка той же
// транзакции. Полный список субъектов хранится в Binding.Subjects.
type MetadataBinding struct {
	Binding   granteffect.Binding
	Changes   bool
	Pending   bool
	ExpiresAt *time.Time
}

type metadataEffect struct {
	carrier MetadataBinding
	delta   granteffect.MetadataDelta
}

// RequireMetadataGrant проверяет расширение эффекта отдельно у каждого
// получателя. Писатель удерживает источники и сверяет их с RR до общего времени
// решения. Эффекты старой редакции можно использовать только в пределах их срока.
func RequireMetadataGrant(ctx context.Context, w kaname.SemanticAuthorityWriter, actor domain.Subject, old, next granteffect.MetadataObject, bindings []MetadataBinding) error {
	if w == nil || w.SemanticBundle() == nil || w.AuthorityFence() == nil || w.AuthorityFence().DecisionAt().IsZero() {
		return unavailable()
	}
	at := w.AuthorityFence().DecisionAt()
	bundle := w.SemanticBundle()
	perRecipient := make(map[domain.Subject][]metadataEffect)
	work := granteffect.NewProofBudget()
	var orderedRecipients []domain.Subject
	n, totalEffects, totalBytes := 0, 0, 0
	for _, carrier := range bindings {
		if err := ctx.Err(); err != nil {
			return err
		}
		if carrier.ExpiresAt != nil && !carrier.ExpiresAt.After(at) {
			continue
		}
		b := carrier.Binding
		recipients, err := domain.NormalizeSubjects(b.Subjects, "", "")
		if err != nil || len(recipients) == 0 {
			return unavailable()
		}
		for _, recipient := range recipients {
			n++
			if n > granteffect.MaxEffects || !work.Charge(1) {
				return kaname.ErrSourceReadLimit
			}
			b.Recipient = recipient
			b.Subjects = recipients
			if _, err := validateProposed(b); err != nil {
				return err
			}
			delta := bundle.CompileMetadataDelta(b, old, next)
			beforeEffects, beforeBytes, beforeSteps := delta.Before.Cost()
			afterEffects, afterBytes, afterSteps := delta.After.Cost()
			totalEffects += beforeEffects + afterEffects
			totalBytes += beforeBytes + afterBytes
			if totalEffects > granteffect.MaxEffects || totalBytes > granteffect.MaxInputBytes || !work.Charge(beforeSteps+afterSteps) {
				return kaname.ErrSourceReadLimit
			}
			if !delta.Before.Complete() || !delta.After.Complete() {
				if carrier.Changes {
					return denied()
				}
				// Неизменившийся источник не обязан доказывать выдачу.
				// Без полной компиляции его OLD не служит покрытием.
				continue
			}
			carrier.Binding = b
			if _, ok := perRecipient[recipient]; !ok {
				orderedRecipients = append(orderedRecipients, recipient)
			}
			perRecipient[recipient] = append(perRecipient[recipient], metadataEffect{carrier, delta})
		}
	}

	var proof *WitnessedLowerBound
	for _, recipient := range orderedRecipients {
		effects := perRecipient[recipient]
		for _, wanted := range effects {
			if err := ctx.Err(); err != nil {
				return err
			}
			count, _, _ := wanted.delta.After.Cost()
			if !wanted.carrier.Changes || count == 0 {
				continue
			}
			previous, err := metadataOldEffects(work, effects, wanted.carrier)
			if err != nil {
				return err
			}
			coverage := work.Prove(previous, wanted.delta.After)
			if coverage.Status == grantcoverage.Proved {
				continue
			}
			if coverage.Reason == grantcoverage.ReasonWorkLimit {
				return kaname.ErrSourceReadLimit
			}
			if proof == nil {
				p, err := CollectWitnessedLowerBound(ctx, w, actor)
				if err != nil {
					return err
				}
				proof = &p
			}
			if err := requireMetadataExpansion(ctx, w, *proof, work, wanted, previous); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func metadataOldEffects(work *granteffect.ProofBudget, effects []metadataEffect, wanted MetadataBinding) (granteffect.Set, error) {
	if !work.Charge(len(effects)) {
		return granteffect.Set{}, kaname.ErrSourceReadLimit
	}
	var old granteffect.UnionBuilder
	for _, prior := range effects {
		// До активации чужая PENDING-привязка ещё ничего не гарантирует.
		if prior.carrier.Pending && prior.carrier.Binding.SourceID != wanted.Binding.SourceID {
			continue
		}
		expires := prior.carrier.ExpiresAt
		if expires != nil && (wanted.ExpiresAt == nil || expires.Before(*wanted.ExpiresAt)) {
			continue
		}
		count, _, _ := prior.delta.Before.Cost()
		if !work.Charge(count) {
			return granteffect.Set{}, kaname.ErrSourceReadLimit
		}
		if err := old.Add(prior.delta.Before); err != nil {
			return granteffect.Set{}, err
		}
	}
	return old.Build(), nil
}

func requireMetadataExpansion(ctx context.Context, w kaname.SemanticAuthorityWriter, p WitnessedLowerBound, work *granteffect.ProofBudget, change metadataEffect, old granteffect.Set) error {
	explicit, err := bindingAuthority(ctx, w, p, change.carrier.Binding)
	if err != nil || explicit {
		return err
	}
	oldCount, _, _ := old.Cost()
	callerCount, _, _ := p.effects.Cost()
	if !work.Charge(oldCount + callerCount) {
		return kaname.ErrSourceReadLimit
	}
	coverage := work.Prove(granteffect.Union(old, p.effects), change.delta.After)
	if coverage.Reason == grantcoverage.ReasonWorkLimit {
		return kaname.ErrSourceReadLimit
	}
	if coverage.Status != grantcoverage.Proved {
		return p.insufficient()
	}
	return nil
}
