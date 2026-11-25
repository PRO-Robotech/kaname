// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const accessDefinitionA = "12345678-1234-1234-1234-123456789abc"
const accessDefinitionB = "abcdef01-2345-6789-abcd-0123456789ab"

func accessLabelApplyRule() domain.Rule {
	return domain.Rule{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{accessDefinitionA}}
}

func TestAccessLabelDefinitionIDCanonicalUUID(t *testing.T) {
	for _, id := range []string{accessDefinitionA, accessDefinitionB, "00000000-0000-0000-0000-000000000001", "ffffffff-ffff-ffff-ffff-ffffffffffff"} {
		if err := domain.AccessLabelDefinitionID(id).Validate(); err != nil {
			t.Fatalf("valid UUID %q: %v", id, err)
		}
	}
	for _, id := range []string{"", "*", "00000000-0000-0000-0000-000000000000", strings.ToUpper(accessDefinitionA), " " + accessDefinitionA, accessDefinitionA + " ", "{" + accessDefinitionA + "}", strings.ReplaceAll(accessDefinitionA, "-", ""), "urn:uuid:" + accessDefinitionA, "12345678_1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abg", "12345678-1234-1234-1234-123456789abя"} {
		if err := domain.AccessLabelDefinitionID(id).Validate(); err == nil {
			t.Fatalf("noncanonical UUID accepted: %q", id)
		}
	}
}

func TestGrantCapabilityAccessLabelDedicatedForm(t *testing.T) {
	ref, ok := domain.GrantCapabilityApplyAccessLabel.RuleRef()
	if !ok || ref != (domain.RoleRuleRef{Module: "iam", Resource: "accessLabel", Verb: "apply"}) {
		t.Fatalf("wrong catalogue coordinate: %+v %v", ref, ok)
	}
	original := accessLabelApplyRule()
	original.ResourceNames = []string{accessDefinitionB, accessDefinitionA, accessDefinitionA}
	reordered := accessLabelApplyRule()
	reordered.ResourceNames = []string{accessDefinitionA, accessDefinitionB}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(domain.Rules{original, reordered, original})
	if err != nil || len(ordinary) != 0 || len(caps) != 2 {
		t.Fatalf("split: ordinary=%+v caps=%+v err=%v", ordinary, caps, err)
	}
	seen := map[domain.AccessLabelDefinitionID]bool{}
	for _, capability := range caps {
		if capability.Kind != domain.GrantCapabilityApplyAccessLabel || capability.BoundRoleID != "" || len(capability.RuleFP) != 64 {
			t.Fatalf("wrong capability: %+v", capability)
		}
		if err := capability.DefinitionID.Validate(); err != nil {
			t.Fatal(err)
		}
		seen[capability.DefinitionID] = true
	}
	if !seen[domain.AccessLabelDefinitionID(accessDefinitionA)] || !seen[domain.AccessLabelDefinitionID(accessDefinitionB)] || caps[0].RuleFP != caps[1].RuleFP {
		t.Fatalf("lost canonical named projection: %+v", caps)
	}
	_, single, err := domain.SplitGrantCapabilityRules(domain.Rules{accessLabelApplyRule()})
	if err != nil || len(single) != 1 || single[0].RuleFP == caps[0].RuleFP {
		t.Fatalf("different authored set lost fingerprint: %+v %v", single, err)
	}
	if !reflect.DeepEqual(original.ResourceNames, []string{accessDefinitionB, accessDefinitionA, accessDefinitionA}) {
		t.Fatal("split mutated authored IDs")
	}
}

func TestGrantCapabilityAccessLabelRejectsMixedAndNestedForms(t *testing.T) {
	changes := map[string]func(*domain.Rule){
		"extra-resource":                  func(r *domain.Rule) { r.Resources = append(r.Resources, "group") },
		"duplicate-resource":              func(r *domain.Rule) { r.Resources = append(r.Resources, "accessLabel") },
		"explicit-resource-plus-wildcard": func(r *domain.Rule) { r.Resources = append(r.Resources, "*") },
		"extra-verb":                      func(r *domain.Rule) { r.Verbs = append(r.Verbs, "get") },
		"duplicate-verb":                  func(r *domain.Rule) { r.Verbs = append(r.Verbs, "apply") },
		"explicit-verb-plus-wildcard":     func(r *domain.Rule) { r.Verbs = append(r.Verbs, "*") },
		"noncanonical-verb":               func(r *domain.Rule) { r.Verbs = []string{"Apply"} },
		"create-mixed": func(r *domain.Rule) {
			r.Resources = append(r.Resources, "accessBinding")
			r.Verbs = append(r.Verbs, "create")
		},
		"bind-mixed":        func(r *domain.Rule) { r.Resources = append(r.Resources, "role"); r.Verbs = append(r.Verbs, "bind") },
		"no-names":          func(r *domain.Rule) { r.ResourceNames = nil },
		"empty-names":       func(r *domain.Rule) { r.ResourceNames = []string{} },
		"empty-id":          func(r *domain.Rule) { r.ResourceNames = []string{""} },
		"wildcard-id":       func(r *domain.Rule) { r.ResourceNames = []string{"*"} },
		"zero-id":           func(r *domain.Rule) { r.ResourceNames = []string{"00000000-0000-0000-0000-000000000000"} },
		"wrong-id-class":    func(r *domain.Rule) { r.ResourceNames = []string{"rol-not-definition"} },
		"invalid-second-id": func(r *domain.Rule) { r.ResourceNames = append(r.ResourceNames, "invalid") },
		"uppercase-id":      func(r *domain.Rule) { r.ResourceNames = []string{strings.ToUpper(accessDefinitionA)} },
		"too-many-names": func(r *domain.Rule) {
			r.ResourceNames = make([]string, 257)
			for i := range r.ResourceNames {
				r.ResourceNames[i] = accessDefinitionA
			}
		},
		"labels":              func(r *domain.Rule) { r.MatchLabels = map[string]string{"env": "prod"} },
		"empty-labels":        func(r *domain.Rule) { r.MatchLabels = map[string]string{} },
		"access-labels":       func(r *domain.Rule) { r.MatchAccessLabels = map[string]string{"env": "prod"} },
		"empty-access-labels": func(r *domain.Rule) { r.MatchAccessLabels = map[string]string{} },
		"creator":             func(r *domain.Rule) { r.CreatedBySubject = true },
		"children": func(r *domain.Rule) {
			r.Children = []domain.Rule{{Resources: []string{"group"}, Verbs: []string{"get"}}}
		},
		"empty-children": func(r *domain.Rule) { r.Children = []domain.Rule{} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			rule := accessLabelApplyRule()
			change(&rule)
			// Отказ атомарен: уже обработанное законное правило не выдаёт частичный результат.
			ordinary, caps, err := domain.SplitGrantCapabilityRules(domain.Rules{accessLabelApplyRule(), rule})
			if err == nil || ordinary != nil || caps != nil {
				t.Fatalf("unsafe form accepted: %+v %+v %v", ordinary, caps, err)
			}
		})
	}
	for _, explicitModule := range []bool{false, true} {
		child := accessLabelApplyRule()
		if !explicitModule {
			child.Module = ""
		}
		parent := domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, Children: []domain.Rule{child}}
		ordinary, caps, err := domain.SplitGrantCapabilityRules(domain.Rules{parent})
		if err == nil || ordinary != nil || caps != nil {
			t.Fatalf("nested apply accepted: %+v %+v %v", ordinary, caps, err)
		}
	}
}

func TestGrantCapabilityAccessLabelWildcardsDoNotAuthorize(t *testing.T) {
	for _, rule := range []domain.Rule{
		{Module: "*", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}},
		{Module: "iam", Resources: []string{"*"}, Verbs: []string{"apply"}},
		{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"*"}},
		{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}},
		{Module: "probe", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}},
	} {
		ordinary, caps, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
		if err != nil || len(caps) != 0 || !reflect.DeepEqual(ordinary, domain.Rules{rule}) {
			t.Fatalf("implicit apply appeared: %+v %+v %v", ordinary, caps, err)
		}
	}
}

func TestGrantCapabilityAccessLabelPreservesLegacyCapabilities(t *testing.T) {
	rule := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol-a"}}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
	if err != nil || len(ordinary) != 0 || len(caps) != 1 {
		t.Fatalf("legacy bind changed: %+v %+v %v", ordinary, caps, err)
	}
	if caps[0].RuleFP != "281b179a088967e008c95e4ff2eca7f527e182aec5ade7f595b48d027c0d175f" || caps[0].DefinitionID != "" {
		t.Fatalf("legacy fingerprint changed: %+v", caps)
	}
	encoded, err := json.Marshal(caps[0])
	want := `{"RuleFP":"281b179a088967e008c95e4ff2eca7f527e182aec5ade7f595b48d027c0d175f","Kind":"bind_role","BoundRoleID":"rol-a"}`
	if err != nil || string(encoded) != want {
		t.Fatalf("legacy JSON changed: %s %v", encoded, err)
	}
	create := domain.Rule{Module: "iam", Resources: []string{"accessBinding", "group"}, Verbs: []string{"create", "get"}}
	ordinary, caps, err = domain.SplitGrantCapabilityRules(domain.Rules{create})
	if err != nil || len(caps) != 1 || caps[0].Kind != domain.GrantCapabilityCreateBinding || caps[0].DefinitionID != "" || len(ordinary) != 2 {
		t.Fatalf("legacy create residual changed: %+v %+v %v", ordinary, caps, err)
	}
}

func TestGrantCapabilityAccessLabelRequiresAllInScope(t *testing.T) {
	rules := domain.Rules{accessLabelApplyRule()}
	if err := domain.ValidateGrantCapabilityTarget(rules, domain.AccessTarget{AllInScope: true}); err != nil {
		t.Fatal(err)
	}
	if err := domain.ValidateGrantCapabilityTarget(rules, domain.AccessTarget{}); err == nil {
		t.Fatal("named apply capability lost carrier constraint")
	}
}
