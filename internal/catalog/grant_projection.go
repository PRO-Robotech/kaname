// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// GrantProjection — только вычисленные строки producer, не authority/Ready.
// kaname#1034: исходные Rules остаются авторскими; ordinary fp — от остатка.
type GrantProjection struct {
	Ordinary     domain.Rules
	Capabilities []domain.GrantCapabilityRule
	Permissions  domain.Permissions
	Selectors    []domain.RuleSelector
	Verbs        []domain.RoleVerb
}

func (f *Facts) ProjectGrantRules(rules domain.Rules, policy domain.RulePolicy) (GrantProjection, error) {
	return f.projectGrantRules(rules, policy, false)
}

// ProjectRoleMutationRules подготавливает proposed image под signed role writer.
// Dedicated apply остаётся отдельной capability. Здесь вычисляются строки,
// live axis и полномочия до записи подтверждает сам writer.
func (f *Facts) ProjectRoleMutationRules(rules domain.Rules, policy domain.RulePolicy) (GrantProjection, error) {
	return f.projectGrantRules(rules, policy, true)
}

func (f *Facts) projectGrantRules(rules domain.Rules, policy domain.RulePolicy, roleMutation bool) (GrantProjection, error) {
	if f == nil {
		return GrantProjection{}, fmt.Errorf("catalog facts unavailable")
	}
	if err := rules.Validate(policy, f); err != nil {
		return GrantProjection{}, err
	}
	// Сохраняем прежний полный входной предел даже при чистом meta остатке.
	if _, err := domain.CompileRules(rules); err != nil {
		return GrantProjection{}, err
	}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(rules)
	if err != nil {
		return GrantProjection{}, err
	}
	for _, cap := range caps {
		switch cap.Kind {
		case domain.GrantCapabilityCreateBinding, domain.GrantCapabilityBindRole:
		case domain.GrantCapabilityApplyAccessLabel:
			if !roleMutation {
				return GrantProjection{}, fmt.Errorf("grant authoring axis is unavailable")
			}
		default:
			return GrantProjection{}, fmt.Errorf("grant authoring axis is unavailable")
		}
		ref, _ := cap.Kind.RuleRef()
		dotted, verb := ref.Module+"."+ref.Resource, ref.Verb
		if !f.GrantVerb(dotted, verb) {
			return GrantProjection{}, fmt.Errorf("grant authoring axis %s.%s is unavailable", dotted, verb)
		}
	}
	permissions, err := domain.CompileRules(ordinary)
	if err != nil {
		return GrantProjection{}, err
	}
	selectors := f.GrantSelectors(f.MaterializingSelectors(ordinary), policy)
	return GrantProjection{Ordinary: ordinary, Capabilities: caps, Permissions: permissions, Selectors: selectors, Verbs: f.RoleVerbsFromSelectors(selectors, policy)}, nil
}
