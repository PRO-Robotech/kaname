// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Роль, точные фокусы и физическое пересечение проверяются независимо.
// Отсутствие существующих потомков не убирает условие будущей выдачи.
func (s *roleSelectorMoveStage) requireGrantEffects(
	ctx context.Context, w *semanticAuthorityWriteTx, projected roleSelectorMoveGrantProjections,
	changes roleSelectorMoveChanges,
) error {
	bindings, err := s.grantBindingSources(ctx, w, projected, changes.access.Bindings)
	if err != nil {
		return err
	}
	effects, err := s.selectorMoveGrantEffects(ctx, w.bundle, bindings, changes)
	if err != nil {
		return err
	}
	return grantpolicy.RequireSelectorMoveGrants(ctx, w, s.actor, s.captured.Before.ID, effects)
}

type selectorMoveGrantKey struct {
	bindingID string
	recipient domain.Subject
}

type selectorMoveMetadataPair struct {
	old, next granteffect.MetadataObject
	object    domain.MirrorObject
}

func (s *roleSelectorMoveStage) selectorMoveGrantEffects(
	ctx context.Context, bundle *granteffect.Bundle, bindings []roleSelectorMoveBindingSource,
	changes roleSelectorMoveChanges,
) ([]grantpolicy.SelectorMoveEffect, error) {
	foci, ownFoci, err := s.selectorMoveGrantFoci(ctx, changes.copies)
	if err != nil {
		return nil, err
	}
	budget := s.budget()
	var effects []grantpolicy.SelectorMoveEffect
	effectCount, effectBytes := 0, 0
	add := func(effect grantpolicy.SelectorMoveEffect) error {
		before, beforeBytes, beforeSteps := effect.Delta.Before.Cost()
		after, afterBytes, afterSteps := effect.Delta.After.Cost()
		effectCount += before + after
		effectBytes += beforeBytes + afterBytes
		if len(effects) >= granteffect.MaxEffects || effectCount > granteffect.MaxEffects || effectBytes > granteffect.MaxInputBytes {
			return kaname.ErrSourceReadLimit
		}
		if err := chargeNativePolicyBudget(budget, 1+before+after+beforeSteps+afterSteps, 0); err != nil {
			return err
		}
		effects = append(effects, effect)
		return nil
	}

	moved := s.captured.Before.ID
	movedHasCarriers := false
	exact := make(map[selectorMoveGrantKey]grantpolicy.MetadataBinding, len(bindings))
	for _, source := range bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		carrier := grantpolicy.MetadataBinding{Binding: source.After, Changes: source.Changes, Pending: source.Pending, ExpiresAt: source.ExpiresAt}
		key := selectorMoveGrantKey{bindingID: source.After.SourceID, recipient: source.After.Recipient}
		if _, duplicate := exact[key]; duplicate || source.Changes != (source.After.Role.ID == moved) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		exact[key] = carrier
		movedHasCarriers = movedHasCarriers || source.Changes
		delta := granteffect.MetadataDelta{Before: bundle.Compile(source.Before)}
		if source.Changes {
			delta.After = bundle.Compile(source.After)
		}
		if err := add(grantpolicy.SelectorMoveEffect{Carrier: carrier, Delta: delta}); err != nil {
			return nil, err
		}
		// У чужой роли общего изменения правил нет. Но копия может дать
		// ей права на будущих потомков именно этого удержанного предка.
		refs := foci[domain.AccessBindingID(source.After.SourceID)]
		if source.Changes {
			refs = sortedRefs(slices.Concat(refs, ownFoci[domain.AccessBindingID(source.After.SourceID)]))
		}
		carrier.Changes = true
		for _, ref := range refs {
			focal, ok := s.selectorMoveMetadataPair(ref, changes.copies[ref])
			if !ok {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if !focal.object.IsContainedIn(source.After.Scope) {
				continue
			}
			delta := bundle.CompileSelectorMoveDelta(source.Before, source.After, focal.old, focal.next)
			if err := add(grantpolicy.SelectorMoveEffect{Carrier: carrier, Delta: delta, Focal: ref}); err != nil {
				return nil, err
			}
		}
	}
	if !movedHasCarriers {
		// Невыданная роль не подтверждает никакого OLD для получателя.
		// Сохраняем обычную проверку авторства в области определения.
		next := s.captured.Before
		next.Rules = s.captured.ProposedRules
		anchor, err := accessLabelMoveRoleScope(next)
		if err != nil {
			return nil, err
		}
		projection, err := s.facts.ProjectRoleMutationRules(next.Rules, domain.PolicyOfRole(next.IsSystem, next.OwnerModule))
		if err != nil {
			return nil, err
		}
		next.Permissions = projection.Permissions
		binding := granteffect.Binding{SourceID: "proposed-role:" + string(moved), Role: next, Scope: anchor,
			Target: domain.AccessTarget{AllInScope: true}, Recipient: s.actor, Subjects: []domain.Subject{s.actor}, CapabilityVersion: 1}
		if err := add(grantpolicy.SelectorMoveEffect{Carrier: grantpolicy.MetadataBinding{Binding: binding, Changes: true},
			Delta: granteffect.MetadataDelta{After: bundle.Compile(binding)}, UnboundRole: true}); err != nil {
			return nil, err
		}
	}
	for _, grant := range changes.grants {
		key := selectorMoveGrantKey{bindingID: string(grant.BindingID), recipient: grant.Recipient}
		carrier, ok := exact[key]
		if !ok || carrier.Pending != grant.Pending || carrier.Binding.Role.ID != grant.RoleID ||
			carrier.Binding.Scope != grant.Scope || !selectorMoveSameExpiry(carrier.ExpiresAt, grant.ExpiresAt) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		carrier.Changes = true
		if err := add(grantpolicy.SelectorMoveEffect{Carrier: carrier, Delta: granteffect.MetadataDelta{After: grant.model}, Physical: true}); err != nil {
			return nil, err
		}
	}
	return effects, ctx.Err()
}

// Для соседних привязок используем уже прочитанные в RR предикаты
// изменения. Для переносимой роли добавляем координаты её новой раскладки.
func (s *roleSelectorMoveStage) selectorMoveGrantFoci(
	ctx context.Context, copies accessLabelMoveCopies,
) (map[domain.AccessBindingID][]domain.ResourceRef, map[domain.AccessBindingID][]domain.ResourceRef, error) {
	source := s.grantCapture()
	if source == nil {
		return nil, nil, kaname.ErrSourceUnconfirmed
	}
	foci := make(map[domain.AccessBindingID][]domain.ResourceRef)
	if err := chargeNativePolicyBudget(source.budget, len(source.entries), 0); err != nil {
		return nil, nil, err
	}
	for key, rows := range source.entries {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if key.kind != resourceSourceMetadataBindings && key.kind != resourceSourceMetadataAuthoredBindings {
			continue
		}
		ref := domain.ResourceRef{Type: key.typ, ID: key.id}
		if _, copied := copies[ref]; !copied {
			continue
		}
		if err := chargeNativePolicyBudget(source.budget, len(rows), 0); err != nil {
			return nil, nil, err
		}
		for _, row := range rows {
			var hit struct {
				ID      domain.AccessBindingID `json:"binding_id"`
				Changes *bool                  `json:"changes"`
			}
			if json.Unmarshal(row.value, &hit) != nil || !nativeQuestionToken(string(hit.ID)) || hit.Changes == nil {
				return nil, nil, kaname.ErrSourceUnconfirmed
			}
			if *hit.Changes {
				foci[hit.ID] = append(foci[hit.ID], ref)
			}
		}
	}
	for id, refs := range foci {
		foci[id] = sortedRefs(refs)
	}
	own := make(map[domain.AccessBindingID][]domain.ResourceRef, len(s.captured.Carriers))
	for _, scope := range s.captured.Carriers {
		if err := chargeNativePolicyBudget(source.budget, len(scope.Coordinates), 0); err != nil {
			return nil, nil, err
		}
		for _, ref := range scope.Coordinates {
			if _, copied := copies[ref]; copied {
				id := scope.Carrier.Binding.ID
				own[id] = append(own[id], ref)
			}
		}
	}
	return foci, own, ctx.Err()
}

func (s *roleSelectorMoveStage) selectorMoveMetadataPair(ref domain.ResourceRef, nextLabels map[string]string) (selectorMoveMetadataPair, bool) {
	graph, captured := s.captured.Graphs[ref]
	typ, recognized := s.facts.FGAObjectType(ref.Type)
	if !captured || !graph.Present || !recognized || graph.Object.ObjectType != ref.Type || graph.Object.ObjectID != ref.ID {
		return selectorMoveMetadataPair{}, false
	}
	old := granteffect.MetadataObject{Type: typ, ID: ref.ID, CatalogType: ref.Type,
		Labels: selectorMoveDomainLabels(graph.Object.Labels), AccessLabels: selectorMoveDomainLabels(graph.Object.AccessLabels)}
	if ref.Type == "iam.serviceAccount" {
		old.CreatorKnown = true
		if graph.Object.CreatedBy != "" {
			kind, id, ok := strings.Cut(graph.Object.CreatedBy, ":")
			if !ok || !nativeQuestionToken(id) || (kind != "user" && kind != "service_account") {
				return selectorMoveMetadataPair{}, false
			}
			old.Creator = domain.Subject{Type: domain.SubjectType(kind), ID: domain.SubjectID(id)}
		}
	}
	next := old
	next.AccessLabels = selectorMoveDomainLabels(nextLabels)
	return selectorMoveMetadataPair{old: old, next: next, object: graph.Object}, true
}

func selectorMoveDomainLabels(raw map[string]string) domain.Labels {
	out := make(domain.Labels, len(raw))
	for key, value := range raw {
		out[domain.LabelKey(key)] = domain.LabelVal(value)
	}
	return out
}

func selectorMoveSameExpiry(a, b *time.Time) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.Equal(*b))
}
