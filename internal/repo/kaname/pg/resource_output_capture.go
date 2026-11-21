// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Fold читает holders, кроме явно переписываемого источника. Поэтому объектный
// снимок захватывает их корни даже при удалении одного owner/pointer. Это ещё
// описание зависимостей: оно не заменяет вычисление mutation accounts или
// подтверждение всех этих predicates под held RC guards.
type resourceOutputCapture struct {
	object    domain.ResourceRef
	modelType string
	bindings  map[string]domain.AccessBinding
	selected  map[string]bool
	roles     map[string]domain.Role
}

func captureResourceOutput(ctx context.Context, parents *resourceParentCapture, cat resourceCatalogRow, id string) (*resourceOutputCapture, error) {
	if parents == nil || parents.source == nil || parents.source.sealed || !nativeQuestionToken(id) || cat.identity.Dotted == "" || cat.identity.ObjectType == "" {
		return nil, kaname.ErrSourceUnconfirmed
	}
	out := &resourceOutputCapture{object: domain.ResourceRef{Type: cat.identity.Dotted, ID: id}, modelType: cat.identity.ObjectType, bindings: make(map[string]domain.AccessBinding), roles: make(map[string]domain.Role), selected: make(map[string]bool)}
	bindingIDs := map[string]bool{}
	for _, kind := range []resourceSourceKind{resourceSourcePointerFacts, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceRegistrationPointers, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceFactLedgerHolders} {
		typ := cat.identity.ObjectType
		if kind == resourceSourceObjectMembers || kind == resourceSourceObjectLedger {
			typ = cat.identity.Dotted
		}
		rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: kind, typ: typ, id: id})
		if err != nil {
			return nil, err
		}
		if kind == resourceSourceObjectPublication && len(rows) > 1 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if kind != resourceSourceObjectMembers && kind != resourceSourceObjectLedger && kind != resourceSourceFactLedgerHolders {
			continue
		}
		for _, captured := range rows {
			var carrier struct {
				Binding string `json:"binding_id"`
			}
			if err = json.Unmarshal(captured.value, &carrier); err != nil {
				return nil, err
			}
			if !nativeQuestionToken(carrier.Binding) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			bindingIDs[carrier.Binding] = true
			if kind == resourceSourceObjectMembers {
				out.selected[carrier.Binding] = true
			}
		}
	}
	if cat.identity.ObjectType == "cluster" {
		if _, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceClusterFactHolders, typ: "cluster", id: id}); err != nil {
			return nil, err
		}
	}
	if err := out.captureBindings(ctx, parents, bindingIDs); err != nil {
		return nil, err
	}

	return out, nil
}

func (c *resourceOutputCapture) addFootprint(ctx context.Context, p *resourceParentCapture, f *resourceFootprint) error {
	if c == nil || p == nil || f == nil {
		return kaname.ErrSourceUnconfirmed
	}
	if err := f.addObject(c.object); err != nil {
		return err
	}
	if err := c.addObjectScopes(ctx, p, f); err != nil {
		return err
	}
	ids := make(map[string]bool, len(c.bindings))
	for id := range c.bindings {
		ids[id] = true
	}
	for _, id := range resourceSortedSet(ids) {
		if err := p.addBindingFootprint(ctx, f, c.bindings[id]); err != nil {
			return err
		}
	}
	// Прочитанные роли здесь не переписываются; их SOURCE guards устанавливает
	// общий preflight, не расширяя mutation область общим кластерным якорем.
	return nil
}

func (out *resourceOutputCapture) captureBindings(ctx context.Context, parents *resourceParentCapture, bindingIDs map[string]bool) error {
	if out == nil || parents == nil || out.bindings == nil || out.roles == nil {
		return kaname.ErrSourceUnconfirmed
	}
	for _, id := range resourceSortedSet(bindingIDs) {
		rows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id})
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return kaname.ErrSourceUnconfirmed
		}
		binding, err := resourceCapturedBinding(rows[0].value)
		if err != nil {
			return err
		}
		if string(binding.ID) != id {
			return kaname.ErrSourceUnconfirmed
		}
		subjectRows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: id})
		if err != nil {
			return err
		}
		binding.Subjects, err = resourceCapturedSubjects(binding, subjectRows)
		if err != nil {
			return err
		}
		out.bindings[id] = binding
		if binding.RoleID == "" {
			continue
		}
		roleID := string(binding.RoleID)
		if _, ok := out.roles[roleID]; ok {
			continue
		}
		roleRows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: roleID})
		if err != nil {
			return err
		}
		if len(roleRows) != 1 {
			return kaname.ErrSourceUnconfirmed
		}
		selectorRows, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRoleSelectors, typ: "role", id: roleID})
		if err != nil {
			return err
		}
		role, err := resourceCapturedMaterializingRole(roleRows[0].value, selectorRows)
		if err != nil {
			return err
		}
		if role.ID != binding.RoleID {
			return kaname.ErrSourceUnconfirmed
		}
		out.roles[roleID] = role
	}
	return nil
}
