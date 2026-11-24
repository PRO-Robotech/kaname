// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Сертификат — только вход проверки. SQL обязан сопоставить selector, target,
// creator и parent-путь с held canonical rows, проверить каждый tuple mapping
// и покрытие старых holders. Ни kind, ни fingerprint не являются разрешением.
type resourceObjectEffectProposal struct {
	AuditIDs []string                        `json:"audit_ids"`
	Bindings []resourceObjectBindingProposal `json:"bindings"`
	Parents  []resourceEffectSourceRef       `json:"parents"`
}
type resourceEffectSourceRef struct {
	Kind resourceSourceKind `json:"kind"`
	Type string             `json:"type"`
	ID   string             `json:"id"`
}
type resourceDesiredEffectWitness struct {
	Desired  reconcile.DesiredMember `json:"desired"`
	Selector resourceEffectSourceRef `json:"selector"`
	Object   resourceEffectSourceRef `json:"object"`
}
type resourceObjectBindingProposal struct {
	Binding   domain.AccessBindingID         `json:"binding"`
	Active    bool                           `json:"active"`
	Additive  bool                           `json:"additive"`
	ExpiresAt *time.Time                     `json:"expires_at"`
	Desired   []resourceDesiredEffectWitness `json:"desired"`
	Live      []reconcile.BindingCommand     `json:"live"`
	Expired   []reconcile.BindingCommand     `json:"expired"`
}

// Ветви компилируются по отдельным binding, а не как два aggregate diff.
// Когда один носитель истекает между RR и final clock, исчезает его write claim
// в общем collector: другой носитель может теперь выпустить ранее подавленный
// delete. Объединение индивидуальных ветвей заранее включает такой physical
// эффект без экспоненциального перебора комбинаций TTL. Итоговый body по-прежнему
// получает проверенные команды прежнего CompileCapturedObjectDiff; private
// server program выбирает TTL-ветви и применяет тот же общий collector.
func compileResourceObjectEffectProposal(ctx context.Context, p *resourceObjectPreparation) (*resourceObjectEffectProposal, error) {
	if p == nil || p.source == nil || p.source.sealed || p.root == nil || p.source.budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	out := &resourceObjectEffectProposal{Bindings: make([]resourceObjectBindingProposal, 0, len(p.inputs)), Parents: []resourceEffectSourceRef{}}
	for key := range p.source.entries {
		if key.kind == resourceSourceParentEdges {
			out.Parents = append(out.Parents, resourceEffectSourceRef{Kind: key.kind, Type: key.typ, ID: key.id})
		}
	}
	slices.SortFunc(out.Parents, func(a, b resourceEffectSourceRef) int {
		if v := cmp.Compare(a.Type, b.Type); v != 0 {
			return v
		}
		return cmp.Compare(a.ID, b.ID)
	})
	seen := make(map[domain.AccessBindingID]bool, len(p.inputs))
	for _, input := range p.inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binding, ok := p.root.bindings[string(input.Binding.BindingID)]
		if !ok || binding.ID == "" || seen[binding.ID] || string(binding.RoleID) != input.Binding.RoleID {
			return nil, kaname.ErrSourceUnconfirmed
		}
		seen[binding.ID] = true
		item := resourceObjectBindingProposal{Binding: binding.ID, Active: input.Binding.Active, Additive: input.Additive,
			Desired: make([]resourceDesiredEffectWitness, 0, len(input.Desired)), Live: []reconcile.BindingCommand{}, Expired: []reconcile.BindingCommand{}}
		if binding.ExpiresAt != nil {
			at := binding.ExpiresAt.UTC()
			item.ExpiresAt = &at
		}
		selector := resourceEffectSourceRef{Kind: resourceSourceRoleSelectors, Type: "role", ID: string(binding.RoleID)}
		if binding.RoleID == "" && len(input.Desired) > 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if _, ok := p.source.entries[resourceSourceKey{kind: selector.Kind, typ: selector.Type, id: selector.ID}]; binding.RoleID != "" && !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		for _, desired := range input.Desired {
			switch desired.Derivation {
			case "ordinary", "nested", "container", "scope_self", "public_reader", "child_registration":
			default:
				return nil, kaname.ErrSourceUnconfirmed
			}
			kind := resourceSourceMirror
			if domain.FeedSourceForType(desired.ObjectType) == domain.FeedIAMDirect {
				kind = resourceSourceIAMObject
			}
			object := resourceEffectSourceRef{Kind: kind, Type: desired.ObjectType, ID: desired.ObjectID}
			if _, ok := p.source.entries[resourceSourceKey{kind: kind, typ: object.Type, id: object.ID}]; !ok {
				return nil, kaname.ErrSourceUnconfirmed
			}
			desired.Tuples = slices.Clone(desired.Tuples)
			item.Desired = append(item.Desired, resourceDesiredEffectWitness{Desired: desired, Selector: selector, Object: object})
		}
		live, err := reconcile.CompileCapturedObjectDiff(ctx, []reconcile.CapturedObjectDiff{input})
		if err != nil {
			return nil, err
		}
		inactive := input
		inactive.Binding.Active = false
		expired, err := reconcile.CompileCapturedObjectDiff(ctx, []reconcile.CapturedObjectDiff{inactive})
		if err != nil {
			return nil, err
		}
		if err = p.source.budget.Charge(len(item.Desired)+len(live)+len(expired), 0); err != nil {
			return nil, err
		}
		for _, commands := range [][]reconcile.BindingCommand{live, expired} {
			for _, command := range commands {
				switch command.Kind {
				case "members", "record", "forget", "write", "delete", "member_delete", "audit":
				default:
					return nil, kaname.ErrSourceUnconfirmed
				}
			}
		}
		item.Live = append(item.Live, live...)
		item.Expired = append(item.Expired, expired...)
		out.Bindings = append(out.Bindings, item)
	}
	slices.SortFunc(out.Bindings, func(a, b resourceObjectBindingProposal) int { return cmp.Compare(string(a.Binding), string(b.Binding)) })
	// Случайные ID возникают до RC waits/final clock. Они не дают права на
	// audit: сервер сам сопоставляет их проверенным командам и резервирует
	// actual PK под общим guard всех audit INSERT/смены ID.
	out.AuditIDs = []string{}
	for _, item := range out.Bindings {
		for _, command := range item.Live {
			if command.Kind == "audit" {
				out.AuditIDs = append(out.AuditIDs, newAuditEventID())
			}
		}
	}
	if err := p.source.budget.Charge(len(out.AuditIDs), 0); err != nil {
		return nil, err
	}
	return out, ctx.Err()
}
