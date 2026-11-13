// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func (b *sourceBudget) chargeCost(cost kaname.SourceReadCost) bool {
	if cost.Reads < 0 || cost.Rows < 0 || cost.Reads > maxBindingSourcePages-b.pages || cost.Rows > maxBindingSourceRows-b.rows {
		return false
	}
	b.pages += cost.Reads
	b.rows += cost.Rows
	return true
}

// collectActorProvenance не принимает готовых строк или флага полноты извне.
// Canonical reader обязан быть тем же semantic writer; результат compiler и
// read-time checkpoint связываются точной identity и authored digest.
func collectActorProvenance(ctx context.Context, w kaname.SemanticSourceReader, bundle *granteffect.Bundle, actor domain.Subject, bindings []CompiledBinding, budget *sourceBudget, builder *granteffect.UnionBuilder) ([]kaname.ProducerSource, map[domain.RoleID]granteffect.ProjectionCheckpoint, []granteffect.Obligation, error) {
	fail := func(err error) ([]kaname.ProducerSource, map[domain.RoleID]granteffect.ProjectionCheckpoint, []granteffect.Obligation, error) {
		return nil, nil, nil, err
	}
	proofs := map[domain.RoleID]granteffect.ProjectionCheckpoint{}
	issues := []granteffect.Obligation{{Code: "legacy_producer_receipt_census", Detail: "legacy sources without accepted receipt require bounded cutover census; no absence-of-grant inference"}}
	seen := map[domain.RoleID]bool{}
	for _, b := range bindings {
		if b.Source.Role == nil {
			continue
		}
		role := b.Source.Role
		if seen[role.ID] {
			continue
		}
		seen[role.ID] = true
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if !budget.pageAvailable() {
			return fail(ErrBindingSourceLimit)
		}
		checkpoint, cost, err := w.RoleProjectionCheckpoint(ctx, role.ID)
		if !budget.chargeCost(cost) {
			return fail(ErrBindingSourceLimit)
		}
		if errors.Is(err, kaname.ErrSourceReadLimit) {
			return fail(ErrBindingSourceLimit)
		}
		if err != nil && !errors.Is(err, kaname.ErrSourceUnconfirmed) {
			return fail(err)
		}
		want, e := bundle.Projection(*role)
		if err != nil || e != nil || checkpoint != want.Checkpoint {
			issues = append(issues, granteffect.Obligation{Code: "role_projection_checkpoint", Detail: string(role.ID)})
			continue
		}
		proofs[role.ID] = checkpoint
		// Создатель не переименовывается в actor. Сейчас authoritative creator
		// producer существует для service account; прочий manifest selector остаётся
		// явно недоказанным, даже если модель допускает нужный синтаксис.
		for _, rule := range role.Rules {
			if rule.CreatedBySubject {
				if b.Source.Recipient.Type != domain.SubjectTypeServiceAccount || rule.Module != "iam" || len(rule.Resources) != 1 || rule.Resources[0] != "serviceAccount" {
					issues = append(issues, granteffect.Obligation{Code: "creator_source_unsupported", Detail: string(role.ID)})
				}
			}
		}
	}
	token := ""
	tokens := map[string]bool{"": true}
	sources := []kaname.ProducerSource{}
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if !budget.pageAvailable() {
			return fail(ErrStructuralSourceLimit)
		}
		page, next, err := w.ProducerSources(ctx, kaname.CanonicalSourceFilter{Actor: actor, After: token, Limit: kaname.MaxCanonicalSourcePage})
		if err != nil {
			return fail(err)
		}
		if page.Cost.Reads < 1 || page.Cost.Rows < len(page.Sources) {
			return fail(kaname.ErrCanonicalSourceInvalid)
		}
		if !budget.chargeCost(page.Cost) {
			return fail(ErrStructuralSourceLimit)
		}
		for _, s := range page.Sources {
			if s.Identity != bundle.Identity() || s.Receipt.Validate() != nil {
				return fail(kaname.ErrSemanticIdentityUnavailable)
			}
			r := s.Receipt
			if r.Kind == domain.RegistrationOwnerReceipt && r.Subject != actor {
				return fail(kaname.ErrCanonicalSourceInvalid)
			}
			if s.Issue != "" {
				issues = append(issues, granteffect.Obligation{Code: s.Issue, Detail: r.ObjectType + ":" + r.ObjectID})
				sources = append(sources, s)
				continue
			}
			effect := bundle.CompileDirect(granteffect.Direct{SourceID: fmt.Sprintf("%s:%s:%s:%s:%s:%s", r.Kind, r.Module, r.ObjectType, r.ObjectID, r.Subject.Type, r.Subject.ID), ObjectType: r.ObjectType, ObjectID: r.ObjectID, Relation: r.Relation, Recipient: r.Subject, Condition: granteffect.Condition{Name: r.ConditionName, Parameters: r.ConditionParameters}})
			if err = builder.Add(effect); err != nil {
				return fail(fmt.Errorf("%w: %w", ErrStructuralSourceLimit, err))
			}
			sources = append(sources, s)
		}
		if next == "" {
			break
		}
		if tokens[next] {
			return fail(kaname.ErrCanonicalSourceInvalid)
		}
		tokens[next] = true
		token = next
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return sources, proofs, issues, nil
}
