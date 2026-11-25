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
	"strings"
)

// ruleJSON is the on-disk JSON shape of a Rule. The module is a SCALAR
// (`modules:[m]` array tombstoned by migration 0033); omitempty keeps anchor rules
// lean (no empty selector keys).
type ruleJSON struct {
	Module            string            `json:"module"`
	Resources         []string          `json:"resources"`
	Verbs             []string          `json:"verbs"`
	ResourceNames     []string          `json:"resource_names,omitempty"`
	MatchLabels       map[string]string `json:"match_labels,omitempty"`
	MatchAccessLabels map[string]string `json:"match_access_labels,omitempty"`
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
	Resources         []string          `json:"resources"`
	Verbs             []string          `json:"verbs"`
	ResourceNames     []string          `json:"resource_names,omitempty"`
	MatchLabels       map[string]string `json:"match_labels,omitempty"`
	MatchAccessLabels map[string]string `json:"match_access_labels,omitempty"`
}

// DecodeRules decodes the roles.rules JSONB payload into domain Rules. An empty/nil
// payload yields nil (a legacy permissions-only role, rules='[]').
func DecodeRules(raw []byte) (Rules, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if err := validateRawAccessLabelCodec(raw); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	var in []ruleJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("decode rules: %w", err)
	}
	out := make(Rules, 0, len(in))
	for _, r := range in {
		rule := Rule{
			Module:            r.Module,
			Resources:         r.Resources,
			Verbs:             r.Verbs,
			ResourceNames:     r.ResourceNames,
			MatchLabels:       r.MatchLabels,
			MatchAccessLabels: r.MatchAccessLabels,
			CreatedBySubject:  r.CreatedBySubject,
		}
		if len(r.Children) > 0 {
			rule.Children = make([]Rule, 0, len(r.Children))
			for _, c := range r.Children {
				rule.Children = append(rule.Children, Rule{
					Resources:         c.Resources,
					Verbs:             c.Verbs,
					ResourceNames:     c.ResourceNames,
					MatchLabels:       c.MatchLabels,
					MatchAccessLabels: c.MatchAccessLabels,
				})
			}
		}
		if err := validateAccessLabelCodec(rule); err != nil {
			return nil, fmt.Errorf("decode rules: %w", err)
		}
		out = append(out, rule)
	}
	return out, nil
}

// EncodeRules encodes domain Rules to the roles.rules JSONB payload shape.
func EncodeRules(rs Rules) ([]byte, error) {
	out := make([]ruleJSON, 0, len(rs))
	for _, r := range rs {
		if err := validateAccessLabelCodec(r); err != nil {
			return nil, fmt.Errorf("encode rules: %w", err)
		}
		rj := ruleJSON{
			Module:            r.Module,
			Resources:         r.Resources,
			Verbs:             r.Verbs,
			ResourceNames:     r.ResourceNames,
			MatchLabels:       r.MatchLabels,
			MatchAccessLabels: r.MatchAccessLabels,
			CreatedBySubject:  r.CreatedBySubject,
		}
		for _, c := range r.Children {
			rj.Children = append(rj.Children, childRuleJSON{
				Resources:         c.Resources,
				Verbs:             c.Verbs,
				ResourceNames:     c.ResourceNames,
				MatchLabels:       c.MatchLabels,
				MatchAccessLabels: c.MatchAccessLabels,
			})
		}
		out = append(out, rj)
	}
	return json.Marshal(out)
}

// Старый codec не был валидатором правил. Сохраняем его legacy-поведение,
// но новый selector не теряется при omitempty и не смешивается с прежним.
func validateAccessLabelCodec(r Rule) error {
	return validateAccessLabelCodecDepth(r, 0)
}

func validateAccessLabelCodecDepth(r Rule, depth int) error {
	if r.MatchAccessLabels != nil {
		if depth > 1 || (depth == 1 && (r.Module != "" || r.Children != nil)) {
			return fmt.Errorf("invalid matchAccessLabels child shape")
		}
		if len(r.MatchAccessLabels) == 0 || len(r.MatchAccessLabels) > maxMatchLabels || r.MatchLabels != nil || len(r.ResourceNames) > 0 || r.CreatedBySubject || r.hasAnyWildcard() {
			return fmt.Errorf("invalid matchAccessLabels selector")
		}
		for k, v := range r.MatchAccessLabels {
			if err := LabelKey(k).Validate(); err != nil {
				return err
			}
			if err := LabelVal(v).Validate(); err != nil {
				return err
			}
		}
	}
	for _, child := range r.Children {
		if err := validateAccessLabelCodecDepth(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Проверяем наличие нового ключа до typed decode: null не означает отсутствие
// ограничения, а неизвестные поля вложенной формы не должны его стирать.
func validateRawAccessLabelCodec(raw []byte) error {
	var rules []json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil {
		return err
	}
	for _, rule := range rules {
		if err := validateRawAccessLabelRule(rule, 0); err != nil {
			return err
		}
	}
	return nil
}

func validateRawAccessLabelRule(raw json.RawMessage, depth int) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}

	// encoding/json сопоставляет имена без учёта регистра; raw-проверка должна
	// видеть ту же форму, иначе NULL под другим регистром стал бы якорем.
	normalized := make(map[string]json.RawMessage, len(fields))
	duplicate := false
	for key, value := range fields {
		key = strings.ToLower(key)
		if _, exists := normalized[key]; exists {
			duplicate = true
		}
		normalized[key] = value
	}
	fields = normalized
	if value, present := fields["match_access_labels"]; present {
		if duplicate {
			return fmt.Errorf("ambiguous matchAccessLabels rule keys")
		}

		var labels map[string]string
		if err := json.Unmarshal(value, &labels); err != nil {
			return err
		}
		if len(labels) == 0 {
			return fmt.Errorf("invalid empty matchAccessLabels selector")
		}
		if _, legacy := fields["match_labels"]; legacy {
			return fmt.Errorf("conflicting matchAccessLabels selector")
		}
		var creator bool
		if err := json.Unmarshal(fieldsOrNull(fields, "created_by_subject"), &creator); err != nil {
			return err
		}
		if creator {
			return fmt.Errorf("conflicting matchAccessLabels creator selector")
		}
		if depth > 1 {
			return fmt.Errorf("matchAccessLabels exceeds child rule depth")
		}
		if depth == 1 {
			if _, module := fields["module"]; module {
				return fmt.Errorf("matchAccessLabels child cannot declare module")
			}
			if _, children := fields["children"]; children {
				return fmt.Errorf("matchAccessLabels child cannot declare children")
			}
		}
	}
	if children, present := fields["children"]; present {
		var nested []json.RawMessage
		if err := json.Unmarshal(children, &nested); err != nil {
			return nil
		}
		for _, child := range nested {
			if err := validateRawAccessLabelRule(child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func fieldsOrNull(fields map[string]json.RawMessage, key string) json.RawMessage {
	if value, present := fields[key]; present {
		return value
	}
	return json.RawMessage("null")
}
