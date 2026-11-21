// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// RR population снятия: целевые выдачи и носители переписываемых ролей.
// Здесь нет native решения и нет записи. Compiler обязан отдельно вывести
// эффект из этих строк, расширить OLD+NEW ownership и подготовить preflight.
// Сам перечень не даёт разрешения вызвать live withdrawal после final clock.
type resourceWithdrawalCapture struct {
	source         *resourceSourceCapture
	bindings       map[string][]resourceSourceRow
	roles          map[string][]resourceSourceRow
	rewriteRoles   map[string]bool
	targetBindings map[string]bool
}

func captureResourceWithdrawal(ctx context.Context, parents *resourceParentCapture, keys []domain.ResourceRef) (*resourceWithdrawalCapture, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if parents == nil || parents.source == nil || parents.source.sealed || len(keys) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	c := &resourceWithdrawalCapture{source: parents.source, bindings: make(map[string][]resourceSourceRow), roles: make(map[string][]resourceSourceRow), rewriteRoles: make(map[string]bool), targetBindings: make(map[string]bool)}
	// Дубликаты входа не расходуют повторный SQL, но каждый независимый объект
	// остаётся отдельным predicate witness для обнаружения новых носителей.
	seen := make(map[domain.ResourceRef]bool)
	for _, key := range keys {
		if !nativeQuestionToken(key.Type) || !nativeQuestionToken(key.ID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBindingsNamingObject, typ: key.Type, id: key.ID})
		if err != nil {
			return nil, err
		}
		bindings, err := resourceDecodeRows[resourceCarrierID](rows)
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if !nativeQuestionToken(binding.ID) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			c.targetBindings[binding.ID] = true
		}
		rows, err = c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceSelectorsNamingObject, typ: key.Type, id: key.ID})
		if err != nil {
			return nil, err
		}
		selectors, err := resourceDecodeRows[resourceCarrierID](rows)
		if err != nil {
			return nil, err
		}
		for _, selector := range selectors {
			if !nativeQuestionToken(selector.RoleID) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			c.rewriteRoles[selector.RoleID] = true
		}
	}
	ids := resourceSortedSet(c.rewriteRoles)
	allBindings := make(map[string]bool, len(c.targetBindings))
	for id := range c.targetBindings {
		allBindings[id] = true
	}
	for _, role := range ids {
		if err := c.captureRole(ctx, parents, role); err != nil {
			return nil, err
		}
		rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRoleBindings, typ: "role", id: role})
		if err != nil {
			return nil, err
		}
		carriers, err := resourceDecodeRows[resourceCarrierID](rows)
		if err != nil {
			return nil, err
		}
		// Не фильтруем по текущему времени, status или account: полный эффект
		// удаления/перекомпиляции роли включает прежние materialized rows.
		for _, carrier := range carriers {
			if !nativeQuestionToken(carrier.ID) || carrier.RoleID != role {
				return nil, kaname.ErrSourceUnconfirmed
			}
			allBindings[carrier.ID] = true
		}
	}
	for _, id := range resourceSortedSet(allBindings) {
		rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id})
		if err != nil {
			return nil, err
		}
		bindings, err := resourceDecodeRows[resourceCarrierID](rows)
		if err != nil {
			return nil, err
		}
		if len(bindings) != 1 || bindings[0].ID != id {
			return nil, kaname.ErrSourceUnconfirmed
		}
		c.bindings[id] = rows
		if role := bindings[0].RoleID; role != "" {
			if !nativeQuestionToken(role) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err = c.captureRole(ctx, parents, role); err != nil {
				return nil, err
			}
		}
		for _, kind := range []resourceSourceKind{resourceSourceBindingSubjects, resourceSourceBindingMembers, resourceSourceBindingLedger} {
			if _, err = c.source.read(ctx, parents.tx, resourceSourceKey{kind: kind, typ: "binding", id: id}); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

type resourceCarrierID struct {
	ID     string `json:"id"`
	RoleID string `json:"role_id"`
}

func resourceSortedSet(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for id := range set {
		result = append(result, id)
	}
	slices.Sort(result)
	return result
}
func (c *resourceWithdrawalCapture) captureRole(ctx context.Context, parents *resourceParentCapture, id string) error {
	if _, ok := c.roles[id]; ok {
		return nil
	}
	rows, err := c.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: id})
	if err != nil {
		return err
	}
	roles, err := resourceDecodeRows[resourceCarrierID](rows)
	if err != nil {
		return err
	}
	if len(roles) != 1 || roles[0].ID != id {
		return kaname.ErrSourceUnconfirmed
	}
	c.roles[id] = rows
	for _, kind := range []resourceSourceKind{resourceSourceRoleSelectors, resourceSourceRoleVerbs, resourceSourceRoleRuleRefs, resourceSourceRoleCreateRules, resourceSourceRoleBindRules, resourceSourceRolePendingVerbs} {
		if _, err = c.source.read(ctx, parents.tx, resourceSourceKey{kind: kind, typ: "role", id: id}); err != nil {
			return err
		}
	}
	return nil
}
