// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// Закрытый compiler одной полной координаты использует captured members и
// ledger всех её holders. Выбор кандидатов и расширение nested container до
// полного binding выполняет stage до этого вызова; функция не объявляет census
// полным и не выбирает новый DB predicate из результата чистого compiler.
func (c *resourceOutputCapture) coordinateDiffInputs(ctx context.Context, parents *resourceParentCapture, facts *catalog.Facts, object domain.MirrorObject, present bool, ancestors []domain.MirrorObject, additive bool) ([]reconcile.CapturedObjectDiff, error) {
	if c == nil || c.selected == nil || parents == nil || parents.source == nil || parents.source.sealed || parents.source.budget == nil || facts == nil || object.ObjectType != c.object.Type || object.ObjectID != c.object.ID {
		return nil, kaname.ErrSourceUnconfirmed
	}
	memberRows, ok := parents.source.entries[resourceSourceKey{kind: resourceSourceObjectMembers, typ: c.object.Type, id: c.object.ID}]
	if !ok {
		return nil, kaname.ErrSourceUnconfirmed
	}
	ledgerRows, ok := parents.source.entries[resourceSourceKey{kind: resourceSourceObjectLedger, typ: c.object.Type, id: c.object.ID}]
	if !ok {
		return nil, kaname.ErrSourceUnconfirmed
	}
	members := make(map[string][]domain.TargetMember)
	for _, captured := range memberRows {
		var row struct {
			BindingID  domain.AccessBindingID    `json:"binding_id"`
			RoleID     domain.RoleID             `json:"role_id"`
			RuleFP     string                    `json:"rule_fp"`
			ObjectType string                    `json:"object_type"`
			ObjectID   string                    `json:"object_id"`
			Status     domain.VerificationStatus `json:"verification_status"`
		}
		if err := json.Unmarshal(captured.value, &row); err != nil {
			return nil, err
		}
		if _, ok := c.bindings[string(row.BindingID)]; !ok || row.RuleFP == "" || row.ObjectType != c.object.Type || row.ObjectID != c.object.ID {
			return nil, kaname.ErrSourceUnconfirmed
		}
		members[string(row.BindingID)] = append(members[string(row.BindingID)], domain.TargetMember{BindingID: row.BindingID, RoleID: row.RoleID, RuleFP: row.RuleFP, ObjectType: row.ObjectType, ObjectID: row.ObjectID, VerificationStatus: row.Status})
	}
	ledger := make(map[string][]reconcile.LedgerRow)
	for _, captured := range ledgerRows {
		var row struct {
			BindingID  string `json:"binding_id"`
			ObjectType string `json:"member_object_type"`
			ObjectID   string `json:"member_object_id"`
			User       string `json:"fga_user"`
			Relation   string `json:"relation"`
			Object     string `json:"object"`
		}
		if err := json.Unmarshal(captured.value, &row); err != nil {
			return nil, err
		}
		if _, ok := c.bindings[row.BindingID]; !ok || row.ObjectType != c.object.Type || row.ObjectID != c.object.ID || row.User == "" || row.Relation == "" || row.Object == "" {
			return nil, kaname.ErrSourceUnconfirmed
		}
		ledger[row.BindingID] = append(ledger[row.BindingID], reconcile.LedgerRow{Member: reconcile.MemberCoord{ObjectType: row.ObjectType, ObjectID: row.ObjectID}, Tuple: domain.MembershipTuple{User: row.User, Relation: row.Relation, Object: row.Object}})
	}
	ids := c.selected
	for id := range ids {
		if _, known := c.bindings[id]; !known {
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	var inputs []reconcile.CapturedObjectDiff
	for _, id := range resourceSortedSet(ids) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binding := c.bindings[id]
		role, capturedRole := c.roles[string(binding.RoleID)]
		if binding.RoleID != "" && !capturedRole {
			return nil, kaname.ErrSourceUnconfirmed
		}
		bs := bindingScopeFrom(facts, binding, role)
		input := reconcile.CapturedObjectDiff{Binding: bs, Current: members[id], Ledger: ledger[id], Additive: additive,
			Live: map[reconcile.MemberCoord]bool{{ObjectType: object.ObjectType, ObjectID: object.ObjectID}: present}}
		if present && bs.Active {
			desired, err := resourceeffect.CompileObjectDesired(facts, resourceeffect.ObjectBinding{BindingID: bs.BindingID, RoleID: bs.RoleID, Scope: bs.Scope, Subjects: bs.Subjects, Policy: bs.Policy, Selectors: bs.Selectors, ScopeSelfVerbs: bs.ScopeSelfVerbs, Target: bs.Target, Active: bs.Active}, object, ancestors)
			if err != nil {
				return nil, err
			}
			charge := len(desired)
			for _, member := range desired {
				charge += len(member.Tuples)
			}
			if err = parents.source.budget.Charge(charge, 0); err != nil {
				return nil, err
			}
			for _, member := range desired {
				input.Desired = append(input.Desired, reconcile.DesiredMember{Derivation: member.Derivation, RuleFP: member.RuleFP, ObjectType: member.ObjectType, ObjectID: member.ObjectID, Status: member.Status, Tuples: member.Tuples})
			}
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}
