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
		dotted, verb := "iam.accessBinding", "create"
		if cap.Kind == domain.GrantCapabilityBindRole {
			dotted, verb = "iam.role", "bind"
		}
		if !f.GrantVerb(dotted, verb) {
			return GrantProjection{}, fmt.Errorf("grant authoring axis %s.%s is unavailable", dotted, verb)
		}
	}
	permissions, err := domain.CompileRules(ordinary)
	if err != nil {
		return GrantProjection{}, err
	}
	selectors := f.GrantSelectors(ordinary.MaterializingSelectors(), policy)
	return GrantProjection{Ordinary: ordinary, Capabilities: caps, Permissions: permissions, Selectors: selectors, Verbs: f.RoleVerbsFromSelectors(selectors, policy)}, nil
}
