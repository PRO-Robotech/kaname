// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_codec.go — the single source of truth for the roles.rules JSONB codec.
//
// A Rule is persisted in the roles.rules JSONB column in the snake_case, SCALAR-module
// shape the within-DB CHECK iam_rules_valid enforces (migration 0025 + scalar-module
// replace 0033). The codec lives in the domain (pure stdlib) so BOTH the repo adapter
// (role_repo scan/insert) AND the seed layer (system-role selector projection) decode
// the SAME shape — no drift between two hand-rolled DTOs.

import (
	"encoding/json"
	"fmt"
)

// ruleJSON is the on-disk JSON shape of a Rule. The module is a SCALAR
// (`modules:[m]` array tombstoned by migration 0033); omitempty keeps anchor rules
// lean (no empty selector keys).
type ruleJSON struct {
	Module        string            `json:"module"`
	Resources     []string          `json:"resources"`
	Verbs         []string          `json:"verbs"`
	ResourceNames []string          `json:"resource_names,omitempty"`
	MatchLabels   map[string]string `json:"match_labels,omitempty"`
	// Children — вложенные правила (kaname#874). Ключа нет у правила без
	// вложенных: хранимая форма прежних ролей не меняется ни на байт.
	Children []childRuleJSON `json:"children,omitempty"`
	// CreatedBySubject — селектор создателя (kaname#1003, Р2а). Ключа нет у правила
	// без селектора: хранимая форма прежних ролей не меняется ни на байт, а «нет»
	// выражено одним способом — отсутствием ключа.
	CreatedBySubject bool `json:"created_by_subject,omitempty"`
}

// childRuleJSON — хранимая форма ВЛОЖЕННОГО правила. Модуля и своих вложенных у
// неё нет by construction: модуль берётся у владельца, глубину выражает тип
// (страж базы `kaname.iam_rules_valid` отвергает оба ключа у вложенного).
type childRuleJSON struct {
	Resources     []string          `json:"resources"`
	Verbs         []string          `json:"verbs"`
	ResourceNames []string          `json:"resource_names,omitempty"`
	MatchLabels   map[string]string `json:"match_labels,omitempty"`
}

// DecodeRules decodes the roles.rules JSONB payload into domain Rules. An empty/nil
// payload yields nil (a legacy permissions-only role, rules='[]').
func DecodeRules(raw []byte) (Rules, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var in []ruleJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	out := make(Rules, 0, len(in))
	for _, r := range in {
		rule := Rule{
			Module:           r.Module,
			Resources:        r.Resources,
			Verbs:            r.Verbs,
			ResourceNames:    r.ResourceNames,
			MatchLabels:      r.MatchLabels,
			CreatedBySubject: r.CreatedBySubject,
		}
		if len(r.Children) > 0 {
			rule.Children = make([]Rule, 0, len(r.Children))
			for _, c := range r.Children {
				rule.Children = append(rule.Children, Rule{
					Resources:     c.Resources,
					Verbs:         c.Verbs,
					ResourceNames: c.ResourceNames,
					MatchLabels:   c.MatchLabels,
				})
			}
		}
		out = append(out, rule)
	}
	return out, nil
}

// EncodeRules encodes domain Rules to the roles.rules JSONB payload shape.
func EncodeRules(rs Rules) ([]byte, error) {
	out := make([]ruleJSON, 0, len(rs))
	for _, r := range rs {
		rj := ruleJSON{
			Module:           r.Module,
			Resources:        r.Resources,
			Verbs:            r.Verbs,
			ResourceNames:    r.ResourceNames,
			MatchLabels:      r.MatchLabels,
			CreatedBySubject: r.CreatedBySubject,
		}
		for _, c := range r.Children {
			rj.Children = append(rj.Children, childRuleJSON{
				Resources:     c.Resources,
				Verbs:         c.Verbs,
				ResourceNames: c.ResourceNames,
				MatchLabels:   c.MatchLabels,
			})
		}
		out = append(out, rj)
	}
	return json.Marshal(out)
}
