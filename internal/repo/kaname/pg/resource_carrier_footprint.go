// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Область носителя берётся из его persistent якоря. Субъекты и домашний аккаунт
// сервисной учётки здесь не участвуют: они являются shared SOURCE, а не областью
// OUTPUT. Дополнительные координаты эффекта collector добавляет отдельно.
func (p *resourceParentCapture) addBindingFootprint(ctx context.Context, f *resourceFootprint, b domain.AccessBinding) error {
	if p == nil || p.source == nil || p.source.sealed || f == nil || !nativeQuestionToken(string(b.ID)) || !nativeQuestionToken(b.ResourceID) {
		return kaname.ErrSourceUnconfirmed
	}
	switch b.Scope {
	case domain.ScopeCluster:
		if string(b.ResourceType) != "cluster" {
			return kaname.ErrSourceUnconfirmed
		}
		return f.addGlobalCarrier("binding", string(b.ID))
	case domain.ScopeAccount:
		if string(b.ResourceType) != "account" {
			return kaname.ErrSourceUnconfirmed
		}
		if err := p.captureAccount(ctx, b.ResourceID); err != nil {
			return err
		}
		return f.addCarrier("binding", string(b.ID), []domain.AccountID{domain.AccountID(b.ResourceID)})
	case domain.ScopeProject:
		if string(b.ResourceType) != "project" {
			return kaname.ErrSourceUnconfirmed
		}
		scope, err := p.project(ctx, b.ResourceID)
		if err != nil {
			return err
		}
		if !scope.Registered || !nativeQuestionToken(scope.AccountID) {
			return kaname.ErrSourceUnconfirmed
		}
		if err = p.captureAccount(ctx, scope.AccountID); err != nil {
			return err
		}
		f.owners[kaname.AuthorityOwnerRef{Kind: "project", ID: b.ResourceID}] = struct{}{}
		return f.addCarrier("binding", string(b.ID), []domain.AccountID{domain.AccountID(scope.AccountID)})
	default:
		return kaname.ErrSourceUnconfirmed
	}
}

// Только переписываемая роль расширяет mutation footprint. Общая системная
// роль, которую объектный compiler лишь читает, не переводит локальный OUTPUT
// в GLOBAL и не добавляет эксклюзивный замок её общего якоря.
func (p *resourceParentCapture) addRoleMutationFootprint(ctx context.Context, f *resourceFootprint, r domain.Role) error {
	if p == nil || p.source == nil || p.source.sealed || f == nil || !nativeQuestionToken(string(r.ID)) {
		return kaname.ErrSourceUnconfirmed
	}
	if r.IsSystem {
		if !nativeQuestionToken(string(r.ClusterID)) || r.AccountID != "" || r.ProjectID != "" {
			return kaname.ErrSourceUnconfirmed
		}
		return f.addGlobalCarrier("role", string(r.ID))
	}
	if r.ClusterID != "" {
		return kaname.ErrSourceUnconfirmed
	}
	account := r.AccountID
	if r.ProjectID != "" {
		scope, err := p.project(ctx, string(r.ProjectID))
		if err != nil {
			return err
		}
		if !scope.Registered || !nativeQuestionToken(scope.AccountID) {
			return kaname.ErrSourceUnconfirmed
		}
		if account != "" && string(account) != scope.AccountID {
			return kaname.ErrSourceUnconfirmed
		}
		account = domain.AccountID(scope.AccountID)
		f.owners[kaname.AuthorityOwnerRef{Kind: "project", ID: string(r.ProjectID)}] = struct{}{}
	}
	if err := p.captureAccount(ctx, string(account)); err != nil {
		return err
	}
	return f.addCarrier("role", string(r.ID), []domain.AccountID{account})
}

func (p *resourceParentCapture) captureAccount(ctx context.Context, id string) error {
	if p == nil || p.source == nil || p.source.sealed || !nativeQuestionToken(id) {
		return kaname.ErrSourceUnconfirmed
	}
	rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: id})
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return kaname.ErrSourceUnconfirmed
	}
	var row struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(rows[0].value, &row); err != nil {
		return err
	}
	if row.ID != id {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

func (c *resourceWithdrawalCapture) addFootprint(ctx context.Context, p *resourceParentCapture, f *resourceFootprint) error {
	if c == nil || p == nil || c.source != p.source || c.source.sealed || f == nil {
		return kaname.ErrSourceUnconfirmed
	}
	ids := make(map[string]bool, len(c.bindings))
	for id := range c.bindings {
		ids[id] = true
	}
	for _, id := range resourceSortedSet(ids) {
		rows := c.bindings[id]
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
		if err = p.addBindingFootprint(ctx, f, binding); err != nil {
			return err
		}
	}
	for _, id := range resourceSortedSet(c.rewriteRoles) {
		rows := c.roles[id]
		if len(rows) != 1 {
			return kaname.ErrSourceUnconfirmed
		}
		role, err := resourceCapturedRole(rows[0].value)
		if err != nil {
			return err
		}
		if string(role.ID) != id {
			return kaname.ErrSourceUnconfirmed
		}
		if err = p.addRoleMutationFootprint(ctx, f, role); err != nil {
			return err
		}
	}
	return nil
}
