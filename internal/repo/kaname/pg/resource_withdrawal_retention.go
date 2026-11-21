// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// RR компиляция автоматического сужения meta-проекции. Результат сохраняет
// только существовавшие строки и законные живые ссылки; их exact witnesses
// затем перечитывает общий RC preflight под заранее полученными замками.
// Последующие шаги той же роли видят результат предыдущего шага, как старый
// последовательный WithdrawTx, а не повторно исходную проекцию RR.
func (c *resourceWithdrawalCapture) compileRetention(ctx context.Context, parents *resourceParentCapture, plan resourceeffect.WithdrawalPlan) (map[resourceWithdrawalRoleStep][]domain.GrantCapabilityRule, error) {
	if c == nil || parents == nil || parents.source != c.source || c.source.sealed {
		return nil, kaname.ErrSourceUnconfirmed
	}
	out := make(map[resourceWithdrawalRoleStep][]domain.GrantCapabilityRule)
	actualByRole := make(map[domain.RoleID][]domain.GrantCapabilityRule)
	refs := make(map[domain.RoleID]rolerepo.GrantReference)
	axes := make(map[domain.GrantCapabilityKind]bool)
	axesLoaded := false
	for index, step := range plan.Steps {
		for _, change := range step.Roles {
			if change.Retain == nil {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if !axesLoaded {
				for _, axis := range []struct {
					kind           domain.GrantCapabilityKind
					resource, verb string
				}{
					{domain.GrantCapabilityCreateBinding, "accessBinding", "create"}, {domain.GrantCapabilityBindRole, "role", "bind"},
				} {
					rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceGrantAxis, typ: axis.resource, id: axis.verb})
					if err != nil {
						return nil, err
					}
					var live []struct {
						Live bool `json:"live"`
					}
					live, err = resourceDecodeRows[struct {
						Live bool `json:"live"`
					}](rows)
					if err != nil {
						return nil, err
					}
					if len(live) > 1 {
						return nil, kaname.ErrSourceUnconfirmed
					}
					axes[axis.kind] = len(live) == 1 && live[0].Live
				}
				axesLoaded = true
			}
			owner, ok := refs[change.ID]
			if !ok {
				var err error
				owner, err = c.captureReference(ctx, parents, change.ID)
				if err != nil {
					return nil, err
				}
				refs[change.ID] = owner
			}
			if !owner.Live || owner.Role.ID != change.ID {
				return nil, kaname.ErrSourceUnconfirmed
			}
			targets := make(map[domain.RoleID]bool)
			for _, capability := range change.Retain.After {
				if capability.Kind != domain.GrantCapabilityBindRole {
					continue
				}
				target, ok := refs[capability.BoundRoleID]
				if !ok {
					var err error
					target, err = c.captureReference(ctx, parents, capability.BoundRoleID)
					if err != nil {
						return nil, err
					}
					refs[capability.BoundRoleID] = target
				}
				targets[capability.BoundRoleID] = target.Live && rolerepo.CommonGrantAnchor(owner.Role, owner.AccountID, target.Role, target.AccountID)
			}
			actual, ok := actualByRole[change.ID]
			if !ok {
				var err error
				actual, err = c.capturedCapabilities(change.ID)
				if err != nil {
					return nil, err
				}
			}
			retained, err := resourceRetainedCapabilities(actual, change.Retain.Before, change.Retain.After, axes, targets)
			if err != nil {
				return nil, err
			}
			actualByRole[change.ID] = retained
			out[resourceWithdrawalRoleStep{step: index, role: change.ID}] = retained
		}
	}
	return out, nil
}

func (c *resourceWithdrawalCapture) captureReference(ctx context.Context, parents *resourceParentCapture, id domain.RoleID) (rolerepo.GrantReference, error) {
	var ref rolerepo.GrantReference
	rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(id)})
	if err != nil {
		return ref, err
	}
	if len(rows) == 0 {
		return ref, nil
	}
	if len(rows) != 1 {
		return ref, kaname.ErrSourceUnconfirmed
	}
	ref.Role, err = resourceCapturedRole(rows[0].value)
	if err != nil {
		return ref, err
	}
	var live struct {
		Live bool `json:"live"`
	}
	if err = json.Unmarshal(rows[0].value, &live); err != nil {
		return ref, err
	}
	ref.Live = live.Live
	if ref.Role.ID != id {
		return ref, kaname.ErrSourceUnconfirmed
	}
	if ref.Role.IsSystem {
		return ref, nil
	}
	key := resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: string(ref.Role.AccountID)}
	if ref.Role.ProjectID != "" {
		key = resourceSourceKey{kind: resourceSourceProject, typ: "project", id: string(ref.Role.ProjectID)}
	}
	scope, err := c.source.read(ctx, parents.tx, key)
	if err != nil {
		return ref, err
	}
	if len(scope) != 1 {
		return ref, kaname.ErrSourceUnconfirmed
	}
	var owner struct {
		ID      string `json:"id"`
		Account string `json:"account_id"`
	}
	if err = json.Unmarshal(scope[0].value, &owner); err != nil {
		return ref, err
	}
	if owner.ID != key.id {
		return ref, kaname.ErrSourceUnconfirmed
	}
	if key.kind == resourceSourceAccount {
		ref.AccountID = domain.AccountID(owner.ID)
	} else {
		ref.AccountID = domain.AccountID(owner.Account)
	}
	if ref.AccountID == "" {
		return ref, kaname.ErrSourceUnconfirmed
	}
	return ref, nil
}

func (c *resourceWithdrawalCapture) capturedCapabilities(id domain.RoleID) ([]domain.GrantCapabilityRule, error) {
	var out []domain.GrantCapabilityRule
	for _, kind := range []resourceSourceKind{resourceSourceRoleCreateRules, resourceSourceRoleBindRules} {
		rows, ok := c.source.entries[resourceSourceKey{kind: kind, typ: "role", id: string(id)}]
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		type meta struct {
			Role  string        `json:"role_id"`
			FP    string        `json:"rule_fp"`
			Bound domain.RoleID `json:"bound_role_id"`
		}
		values, err := resourceDecodeRows[meta](rows)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			if v.Role != string(id) || v.FP == "" {
				return nil, kaname.ErrSourceUnconfirmed
			}
			cap := domain.GrantCapabilityRule{RuleFP: v.FP, Kind: domain.GrantCapabilityCreateBinding}
			if kind == resourceSourceRoleBindRules {
				cap.Kind = domain.GrantCapabilityBindRole
				cap.BoundRoleID = v.Bound
				if v.Bound == "" {
					return nil, kaname.ErrSourceUnconfirmed
				}
			}
			out = append(out, cap)
		}
	}
	if len(out) > domain.MaxCompiledPermissions {
		return nil, kaname.ErrSourceReadLimit
	}
	return out, nil
}

func resourceRetainedCapabilities(actual, before, after []domain.GrantCapabilityRule, axes map[domain.GrantCapabilityKind]bool, targets map[domain.RoleID]bool) ([]domain.GrantCapabilityRule, error) {
	if len(actual) > domain.MaxCompiledPermissions || len(before) > domain.MaxCompiledPermissions || len(after) > domain.MaxCompiledPermissions {
		return nil, kaname.ErrSourceReadLimit
	}
	type edge struct {
		kind   domain.GrantCapabilityKind
		target domain.RoleID
	}
	present := make(map[domain.GrantCapabilityRule]bool, len(actual))
	for _, c := range actual {
		present[c] = true
	}
	allowed := make(map[edge]bool)
	for _, c := range before {
		if c.Kind != domain.GrantCapabilityCreateBinding && c.Kind != domain.GrantCapabilityBindRole {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if present[c] && axes[c.Kind] && (c.Kind == domain.GrantCapabilityCreateBinding || targets[c.BoundRoleID]) {
			allowed[edge{c.Kind, c.BoundRoleID}] = true
		}
	}
	out := make([]domain.GrantCapabilityRule, 0, len(after))
	for _, c := range after {
		if c.Kind != domain.GrantCapabilityCreateBinding && c.Kind != domain.GrantCapabilityBindRole {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if allowed[edge{c.Kind, c.BoundRoleID}] {
			out = append(out, c)
		}
	}
	return out, nil
}
