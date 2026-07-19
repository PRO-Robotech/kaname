// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
		out = append(out, Rule{
			Module:        r.Module,
			Resources:     r.Resources,
			Verbs:         r.Verbs,
			ResourceNames: r.ResourceNames,
			MatchLabels:   r.MatchLabels,
		})
	}
	return out, nil
}

// EncodeRules encodes domain Rules to the roles.rules JSONB payload shape.
func EncodeRules(rs Rules) ([]byte, error) {
	out := make([]ruleJSON, 0, len(rs))
	for _, r := range rs {
		out = append(out, ruleJSON{
			Module:        r.Module,
			Resources:     r.Resources,
			Verbs:         r.Verbs,
			ResourceNames: r.ResourceNames,
			MatchLabels:   r.MatchLabels,
		})
	}
	return json.Marshal(out)
}
