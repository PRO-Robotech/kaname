// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package resourceeffect строит закрытые изменения из уже прочитанного снимка.
// План не удостоверяет полноту снимка, права или допустимость записи в БД.
package resourceeffect

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

var ErrInvalidSnapshot = errors.New("invalid resource withdrawal snapshot")

// Субъекты и весь реестр выпущенного читаются вместе с исходной выдачей.
// Пустой Subjects сохраняет историческую одиночную пару из Binding.
type WithdrawalBinding struct {
	Binding  domain.AccessBinding
	Subjects []domain.Subject
	Emitted  []abrepo.RelationTuple
}

type WithdrawalSnapshot struct {
	Bindings []WithdrawalBinding
	Roles    []domain.Role
}

type BindingAction uint8

const (
	BindingRevoke BindingAction = iota + 1
	BindingNarrow
)

// Before-поля — проверяемые предусловия применения, не свидетельство допуска.
// SQL-владелец назначает время и сохраняет CAS revoked_at IS NULL.
type BindingWithdrawal struct {
	ID               domain.AccessBindingID
	Action           BindingAction
	BeforeStatus     domain.AccessBindingStatus
	BeforeTarget     domain.AccessTarget
	Target           domain.AccessTarget
	RevocationReason domain.RevocationReason
	TupleDeletes     []abrepo.RelationTuple
	SubjectChanges   []abrepo.SubjectChangeEvent
	Audits           []abrepo.AuditEvent
}

// Удержание проекции не создаёт новые управляющие полномочия. Фактические
// старые строки, живость ссылок и допустимость удержания проверяет PG-владелец.
type CapabilityRetention struct {
	Before []domain.GrantCapabilityRule
	After  []domain.GrantCapabilityRule
}

type RoleWithdrawal struct {
	ID          domain.RoleID
	BeforeRules domain.Rules
	Rules       domain.Rules
	Permissions domain.Permissions
	Selectors   []domain.RuleSelector
	Verbs       []domain.RoleVerb
	Refs        []domain.RoleRuleRef
	Retain      *CapabilityRetention
	Audit       outboxtypes.AuditEvent
}

// Порядок ключей значим: narrow(A из [A,B]) затем revoke(B) сохраняет B в
// отозванной цели. Внутри шага сначала идут выдачи, затем роли, каждый род по ID.
type WithdrawalStep struct {
	Key      domain.ResourceRef
	Bindings []BindingWithdrawal
	Roles    []RoleWithdrawal
}

type WithdrawalPlan struct{ Steps []WithdrawalStep }

type bindingState struct {
	row      domain.AccessBinding
	subjects []domain.Subject
	emitted  []abrepo.RelationTuple
	revoked  bool
}

// CompileWithdrawal воспроизводит обычное снятие регистрации без SQL, часов,
// callback или собственного решения о полномочиях. Вызывающий обязан доказать
// полный RR-снимок, удержать его корни и проверить план в той же writer TX.
func CompileWithdrawal(keys []domain.ResourceRef, actor string, snapshot WithdrawalSnapshot, facts *catalog.Facts) (WithdrawalPlan, error) {
	wanted := make(map[domain.ResourceRef]bool, len(keys))
	for _, key := range keys {
		if key.Type == "" || key.ID == "" {
			return WithdrawalPlan{}, fmt.Errorf("%w: incomplete resource key", ErrInvalidSnapshot)
		}
		wanted[key] = true
	}
	bindings := make(map[domain.AccessBindingID]*bindingState, len(snapshot.Bindings))
	for _, captured := range snapshot.Bindings {
		b := captured.Binding
		if b.ID == "" || bindings[b.ID] != nil {
			return WithdrawalPlan{}, fmt.Errorf("%w: duplicate or absent binding id", ErrInvalidSnapshot)
		}
		if err := b.Status.Validate(); err != nil {
			return WithdrawalPlan{}, fmt.Errorf("%w: binding status: %v", ErrInvalidSnapshot, err)
		}
		b.Target = cloneTarget(b.Target)
		bindings[b.ID] = &bindingState{row: b, subjects: slices.Clone(captured.Subjects), emitted: slices.Clone(captured.Emitted), revoked: b.RevokedAt != nil || b.Status == domain.AccessBindingStatusRevoked}
	}
	roles := make(map[domain.RoleID]domain.Role, len(snapshot.Roles))
	for _, role := range snapshot.Roles {
		if role.ID == "" {
			return WithdrawalPlan{}, fmt.Errorf("%w: absent role id", ErrInvalidSnapshot)
		}
		if _, exists := roles[role.ID]; exists {
			return WithdrawalPlan{}, fmt.Errorf("%w: duplicate role id", ErrInvalidSnapshot)
		}
		role.Rules = cloneRules(role.Rules)
		roles[role.ID] = role
	}
	orderedBindings := slices.Sorted(maps.Keys(bindings))
	orderedRoles := slices.Sorted(maps.Keys(roles))
	// Индексы строятся один раз по содержимому снимка. Большое снятие не
	// перебирает каждый binding и role заново для каждого ключа. Сужение не
	// добавляет новых имён: первоначальный индекс остаётся надмножеством.
	bindingsByKey := make(map[domain.ResourceRef][]domain.AccessBindingID)
	for _, id := range orderedBindings {
		seen := make(map[domain.ResourceRef]bool)
		for _, ref := range bindings[id].row.Target.Resources {
			if wanted[ref] && !seen[ref] {
				bindingsByKey[ref] = append(bindingsByKey[ref], id)
				seen[ref] = true
			}
		}
	}
	rolesByKey := make(map[domain.ResourceRef][]domain.RoleID)
	for _, id := range orderedRoles {
		seen := make(map[domain.ResourceRef]bool)
		indexRoleNames(roles[id].Rules, "", wanted, seen)
		for ref := range seen {
			rolesByKey[ref] = append(rolesByKey[ref], id)
		}
	}
	var plan WithdrawalPlan
	for _, key := range keys {
		step := WithdrawalStep{Key: key}
		for _, id := range bindingsByKey[key] {
			state := bindings[id]
			if state.revoked || !slices.Contains(state.row.Target.Resources, key) {
				continue
			}
			command, err := compileBinding(state, key, actor)
			if err != nil {
				return WithdrawalPlan{}, err
			}
			step.Bindings = append(step.Bindings, command)
		}
		for _, id := range rolesByKey[key] {
			role := roles[id]
			command, changed, err := compileRole(role, key, actor, facts)
			if err != nil {
				return WithdrawalPlan{}, err
			}
			if changed {
				step.Roles = append(step.Roles, command)
				role.Rules = cloneRules(command.Rules)
				roles[id] = role
			}
		}
		plan.Steps = append(plan.Steps, step)
	}
	return plan, nil
}

// Лишь точное имя типа участвует в WithoutOrdinaryResourceName; wildcard
// module/resource сам по себе конкретный ключ не называет. Meta-ссылка может
// дать лишнего кандидата, но compileRole сохранит её без ordinary изменения.
func indexRoleNames(rules domain.Rules, inheritedModule string, wanted, found map[domain.ResourceRef]bool) {
	for _, rule := range rules {
		module := rule.Module
		if module == "" {
			module = inheritedModule
		}
		for _, resource := range rule.Resources {
			if resource == "*" {
				continue
			}
			for _, id := range rule.ResourceNames {
				ref := domain.ResourceRef{Type: module + "." + resource, ID: id}
				if wanted[ref] {
					found[ref] = true
				}
			}
		}
		indexRoleNames(rule.Children, module, wanted, found)
	}
}

func compileBinding(state *bindingState, key domain.ResourceRef, actor string) (BindingWithdrawal, error) {
	b := state.row
	subjects := state.subjects
	if len(subjects) == 0 {
		subjects = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
	}
	for _, subject := range subjects {
		if err := subject.Validate(); err != nil {
			return BindingWithdrawal{}, fmt.Errorf("%w: binding subject: %v", ErrInvalidSnapshot, err)
		}
	}
	remaining := make([]domain.ResourceRef, 0, len(b.Target.Resources)-1)
	for _, ref := range b.Target.Resources {
		if ref != key {
			remaining = append(remaining, ref)
		}
	}
	command := BindingWithdrawal{ID: b.ID, BeforeStatus: b.Status, BeforeTarget: cloneTarget(b.Target)}
	eventType := abrepo.AuditEventType("iam.access_binding.resource_unregistered_narrowed")
	if len(remaining) == 0 {
		command.Action = BindingRevoke
		command.Target = cloneTarget(b.Target)
		command.RevocationReason = domain.RevocationReasonResourceUnregistered
		command.TupleDeletes = slices.Clone(state.emitted)
		eventType = "iam.access_binding.resource_unregistered_revoked"
		for _, subject := range subjects {
			command.SubjectChanges = append(command.SubjectChanges, abrepo.SubjectChangeEvent{SubjectID: string(subject.ID), SubjectType: string(subject.Type), EventType: "binding_revoke", Op: "binding_delete"})
		}
		state.revoked = true
	} else {
		command.Action = BindingNarrow
		command.Target = domain.AccessTarget{Resources: remaining}
		state.row.Target = cloneTarget(command.Target)
	}
	tenant := ""
	if b.ResourceType == "account" {
		tenant = b.ResourceID
	}
	for _, subject := range subjects {
		extra := map[string]any{"unregistered_resource": map[string]any{"type": key.Type, "id": key.ID}}
		if command.Action == BindingRevoke {
			extra["revocation_reason"] = "resource_unregistered"
		} else {
			extra["remaining_resource_count"] = len(remaining)
		}
		command.Audits = append(command.Audits, abrepo.AuditEvent{EventType: eventType, Actor: actor, SubjectType: string(subject.Type), SubjectID: string(subject.ID), ResourceType: string(b.ResourceType), ResourceID: b.ResourceID, RoleID: string(b.RoleID), BindingID: string(b.ID), TenantAccountID: tenant, ExtraPayload: extra})
	}
	return command, nil
}

func compileRole(role domain.Role, key domain.ResourceRef, actor string, facts *catalog.Facts) (RoleWithdrawal, bool, error) {
	rules, removed, changed := role.Rules.WithoutOrdinaryResourceName(key.Type, key.ID)
	if !changed {
		return RoleWithdrawal{}, false, nil
	}
	if facts == nil {
		return RoleWithdrawal{}, false, fmt.Errorf("%w: missing immutable catalog", ErrInvalidSnapshot)
	}
	ordinary, newCaps, err := domain.SplitGrantCapabilityRules(rules)
	if err != nil {
		ordinary = rules
	}
	command := RoleWithdrawal{ID: role.ID, BeforeRules: cloneRules(role.Rules), Rules: cloneRules(rules)}
	_, oldCaps, oldErr := domain.SplitGrantCapabilityRules(role.Rules)
	if oldErr == nil && len(oldCaps) > 0 {
		command.Retain = &CapabilityRetention{Before: slices.Clone(oldCaps), After: slices.Clone(newCaps)}
	}
	command.Permissions, err = domain.CompileRules(ordinary)
	if err != nil {
		return RoleWithdrawal{}, false, fmt.Errorf("compile narrowed rules of role %s: %w", role.ID, err)
	}
	selectors := ordinary.MaterializingSelectors()
	policy := domain.PolicyOfRole(role.IsSystem, role.OwnerModule)
	command.Selectors = facts.GrantSelectors(selectors, policy)
	command.Verbs = facts.RoleVerbsFromSelectors(selectors, policy)
	command.Refs = domain.RuleRefsOf(rules)
	command.Audit = outboxtypes.AuditEvent{EventType: "iam.role.resource_unregistered_narrowed", TenantAccountID: string(role.AccountID), Payload: map[string]any{"actor": actor, "resource_type": "role", "resource_id": string(role.ID), "role_id": string(role.ID), "unregistered_resource": map[string]any{"type": key.Type, "id": key.ID}, "removed_rule_count": removed, "remaining_rule_count": len(rules)}}
	return command, true, nil
}

func cloneTarget(target domain.AccessTarget) domain.AccessTarget {
	target.Resources = slices.Clone(target.Resources)
	return target
}

func cloneRules(rules domain.Rules) domain.Rules {
	if rules == nil {
		return nil
	}
	out := make(domain.Rules, len(rules))
	for i, rule := range rules {
		rule.Resources = slices.Clone(rule.Resources)
		rule.Verbs = slices.Clone(rule.Verbs)
		rule.ResourceNames = slices.Clone(rule.ResourceNames)
		rule.MatchLabels = maps.Clone(rule.MatchLabels)
		rule.Children = cloneRules(rule.Children)
		out[i] = rule
	}
	return out
}
