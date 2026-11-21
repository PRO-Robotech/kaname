// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// Значения передают результат существующего pure withdrawal compiler. SQL
// сверяет их с полным captured/current graph и закрытым intent; ни before,
// ни сохранённая hierarchy, ни binding_refuses сами не удостоверяют допуска.
type resourceRegistrationEffectProposal struct {
	WithdrawalAuditIDs []string                              `json:"withdrawal_audit_ids,omitempty"`
	AuditID            string                                `json:"audit_id"`
	Row                service.ResourceMirrorRow             `json:"row"`
	OldScopes          []domain.ContainerScope               `json:"old_scopes"`
	NewScopes          []domain.ContainerScope               `json:"new_scopes"`
	Hierarchies        []domain.ParentHierarchy              `json:"hierarchies"`
	BindingRefuses     bool                                  `json:"binding_refuses"`
	Root               *resourceUnregisteredObjectProposal   `json:"root,omitempty"`
	Descendants        []resourceUnregisteredObjectProposal  `json:"descendants"`
	Withdrawal         *resourceeffect.WithdrawalPlan        `json:"withdrawal,omitempty"`
	Retained           []resourceWithdrawalRetentionProposal `json:"retained"`
}
type resourceUnregisteredObjectProposal struct {
	CatalogType string                    `json:"catalog_type"`
	ModelType   string                    `json:"model_type"`
	ID          string                    `json:"id"`
	Present     bool                      `json:"present"`
	DropAll     bool                      `json:"drop_all"`
	Version     time.Time                 `json:"version"`
	Pointers    []resourcePointerProposal `json:"pointers"`
}
type resourcePointerProposal struct {
	Tuple       service.RelationTuple `json:"tuple"`
	Version     time.Time             `json:"version"`
	Active      bool                  `json:"active"`
	Versionless bool                  `json:"versionless"`
}
type resourceWithdrawalRetentionProposal struct {
	Step  int                          `json:"step"`
	Role  domain.RoleID                `json:"role"`
	Rules []domain.GrantCapabilityRule `json:"rules"`
}

func makeResourceRegistrationEffectProposal(stage *resourceRegistrationStage) (*resourceRegistrationEffectProposal, error) {
	if stage == nil || stage.registration == nil || stage.source == nil || stage.source.sealed ||
		stage.registration.parents == nil || stage.registration.parents.source != stage.source {
		return nil, kaname.ErrSourceUnconfirmed
	}
	p := stage.registration
	out := &resourceRegistrationEffectProposal{Row: p.row, OldScopes: p.oldScopes, NewScopes: p.newScopes,
		Hierarchies: p.hierarchies, BindingRefuses: p.bindingRefuses,
		Descendants: []resourceUnregisteredObjectProposal{}, Retained: []resourceWithdrawalRetentionProposal{}}
	// ID создаётся до RC/prewait; semantic compiler сам решает, нужен ли audit.
	// Идентификатор не разрешает ни событие, ни его payload.
	if p.input.Action == kaname.ResourceDecisionRegister || p.input.Action == kaname.ResourceDecisionUnregister {
		if err := stage.source.budget.Charge(1, 0); err != nil {
			return nil, err
		}
		out.AuditID = newAuditEventID()
	}
	if stage.unregistration == nil {
		if p.input.Action == kaname.ResourceDecisionUnregister {
			return nil, kaname.ErrSourceUnconfirmed
		}
		return out, nil
	}
	u := stage.unregistration
	if p.input.Action != kaname.ResourceDecisionUnregister || u.registration != p {
		return nil, kaname.ErrSourceUnconfirmed
	}
	root, err := makeResourceUnregisteredObjectProposal(u.root)
	if err != nil {
		return nil, err
	}
	out.Root = &root
	for _, child := range u.descendants {
		item, err := makeResourceUnregisteredObjectProposal(child)
		if err != nil {
			return nil, err
		}
		out.Descendants = append(out.Descendants, item)
	}
	if u.withdrawal != nil {
		if u.withdrawal.preparation != p {
			return nil, kaname.ErrSourceUnconfirmed
		}
		out.Withdrawal = &u.withdrawal.plan
		// Полный набор ID резервируется в RR; SQL заново выводит число и
		// порядок audit effects, а prewait удостоверяет каждый unique key.
		for _, step := range u.withdrawal.plan.Steps {
			for _, change := range step.Bindings {
				if err := stage.source.budget.Charge(len(change.Audits), 0); err != nil {
					return nil, err
				}
				for range change.Audits {
					out.WithdrawalAuditIDs = append(out.WithdrawalAuditIDs, newAuditEventID())
				}
			}
			if err := stage.source.budget.Charge(len(step.Roles), 0); err != nil {
				return nil, err
			}
			for range step.Roles {
				out.WithdrawalAuditIDs = append(out.WithdrawalAuditIDs, newAuditEventID())
			}
		}
		// Отсутствующая запись отличается от доказанно пустой retained projection.
		for index, step := range u.withdrawal.plan.Steps {
			for _, change := range step.Roles {
				if change.Retain == nil {
					continue
				}
				key := resourceWithdrawalRoleStep{step: index, role: change.ID}
				rules, ok := u.withdrawal.retained[key]
				if !ok {
					return nil, kaname.ErrSourceUnconfirmed
				}
				out.Retained = append(out.Retained, resourceWithdrawalRetentionProposal{Step: index, Role: change.ID, Rules: rules})
			}
		}
		if len(out.Retained) != len(u.withdrawal.retained) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		slices.SortFunc(out.Retained, func(a, b resourceWithdrawalRetentionProposal) int {
			if v := cmp.Compare(a.Step, b.Step); v != 0 {
				return v
			}
			return cmp.Compare(a.Role, b.Role)
		})
	}
	return out, nil
}
func makeResourceUnregisteredObjectProposal(in resourceUnregisteredObject) (resourceUnregisteredObjectProposal, error) {
	if in.catalog.identity.Dotted == "" || in.catalog.identity.ObjectType != in.modelType || in.id == "" {
		return resourceUnregisteredObjectProposal{}, kaname.ErrSourceUnconfirmed
	}
	out := resourceUnregisteredObjectProposal{CatalogType: in.catalog.identity.Dotted, ModelType: in.modelType, ID: in.id,
		Present: in.present, DropAll: in.dropAll, Version: in.version, Pointers: []resourcePointerProposal{}}
	for _, p := range in.pointers {
		out.Pointers = append(out.Pointers, resourcePointerProposal{Tuple: p.tuple, Version: p.version, Active: p.active, Versionless: p.versionless})
	}
	return out, nil
}
