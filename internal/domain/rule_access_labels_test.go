// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func accessLabelRule() Rule {
	return Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"env": "prod"}}
}

// Прежние отпечатки фиксированы независимо от нового вычислителя.
func TestAccessLabelsLegacyFingerprintAndCodecFrozen(t *testing.T) {
	cases := []struct {
		name                 string
		rule                 Rule
		fingerprint, encoded string
	}{
		{"anchor", Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}}, "d29f9a3e4b5b541411139f1e43bbca17ab325faed9d98d6533e6e2dd7091e596", `[{"module":"iam","resources":["group"],"verbs":["get"]}]`},
		{"labels", Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}}, "4898c1505fceb0ab50ac7b63d9cb19c76ed759762e4b8d91798dd0b74a51c270", `[{"module":"iam","resources":["group"],"verbs":["get"],"match_labels":{"env":"prod"}}]`},
		{"names", Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, ResourceNames: []string{"grp-a"}}, "8e2cb08d7b810aec91a98b94a1218a84b52f1c1a79ab524368439013aabd958f", `[{"module":"iam","resources":["group"],"verbs":["get"],"resource_names":["grp-a"]}]`},
		{"creator", Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, CreatedBySubject: true}, "551986d19f7970c312085f2d3c25a966f7badb2b425b29a8dc30d50506c9da1e", `[{"module":"iam","resources":["serviceAccount"],"verbs":["get"],"created_by_subject":true}]`},
		{"nested", Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, Children: []Rule{{Resources: []string{"project"}, Verbs: []string{"get"}}}}, "daa3b1617357130390c20a73a03da122942ed935b360641d72623cb51b1aa50f", `[{"module":"iam","resources":["account"],"verbs":["get"],"children":[{"resources":["project"],"verbs":["get"]}]}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Fingerprint(); got != tc.fingerprint {
				t.Fatalf("fingerprint %s != %s", got, tc.fingerprint)
			}
			encoded, err := EncodeRules(Rules{tc.rule})
			if err != nil || string(encoded) != tc.encoded {
				t.Fatalf("encode %s, %v", encoded, err)
			}
			decoded, err := DecodeRules(encoded)
			if err != nil || !reflect.DeepEqual(decoded, Rules{tc.rule}) {
				t.Fatalf("round trip %+v, %v", decoded, err)
			}
		})
	}
	// Прямой JSON контейнера входит в checkpoint: новое отсутствующее поле
	// не меняет прежний вложенный digest.
	containerJSON, err := json.Marshal(ContainerSelector{Type: "iam.account", OwnerFP: "owner", Arm: ArmLabels, MatchLabels: map[string]string{"env": "prod"}})
	if err != nil || string(containerJSON) != `{"Type":"iam.account","OwnerFP":"owner","Arm":2,"ResourceNames":null,"MatchLabels":{"env":"prod"}}` {
		t.Fatalf("legacy container JSON %s, %v", containerJSON, err)
	}
	r := Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol-a"}}
	direct, err := json.Marshal(r)
	if err != nil || string(direct) != `{"Module":"iam","Resources":["role"],"Verbs":["bind"],"ResourceNames":["rol-a"],"MatchLabels":null,"Children":null,"CreatedBySubject":false}` {
		t.Fatalf("legacy direct JSON %s, %v", direct, err)
	}
	_, caps, err := SplitGrantCapabilityRules(Rules{r})
	if err != nil || len(caps) != 1 || caps[0].RuleFP != "281b179a088967e008c95e4ff2eca7f527e182aec5ade7f595b48d027c0d175f" {
		t.Fatalf("legacy capability %+v, %v", caps, err)
	}
}

func TestAccessLabelsDistinctArmAndNestedProjection(t *testing.T) {
	if ArmAnchor != 0 || ArmNames != 1 || ArmLabels != 2 || ArmAccessLabels != 3 {
		t.Fatal("legacy arm numbering changed")
	}
	r := accessLabelRule()
	if err := r.Validate(TenantPolicy(), fixtureModules()); err != nil {
		t.Fatal(err)
	}
	ordered := r
	ordered.MatchAccessLabels = map[string]string{"a": "one", "b": "two"}
	reordered := r
	reordered.MatchAccessLabels = map[string]string{"b": "two", "a": "one"}
	if ordered.Fingerprint() != reordered.Fingerprint() {
		t.Fatal("access selector order changed fingerprint")
	}
	legacy := r
	legacy.MatchLabels = legacy.MatchAccessLabels
	legacy.MatchAccessLabels = nil
	anchor := r
	anchor.MatchAccessLabels = nil
	if r.Arm() != ArmAccessLabels || r.Fingerprint() == legacy.Fingerprint() || r.Fingerprint() == anchor.Fingerprint() {
		t.Fatal("new selector aliases legacy")
	}
	r.Children = []Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "ops"}}}
	if err := r.Validate(TenantPolicy(), fixtureModules()); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRules(Rules{r})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), `"match_access_labels"`) != 2 || strings.Contains(string(encoded), `"match_labels"`) {
		t.Fatalf("selector lost: %s", encoded)
	}
	decoded, err := DecodeRules(encoded)
	if err != nil || !reflect.DeepEqual(decoded, Rules{r}) {
		t.Fatalf("round trip %+v, %v", decoded, err)
	}
	selectors := Rules{r}.MaterializingSelectors()
	if len(selectors) != 2 || selectors[0].Arm != ArmAccessLabels || selectors[1].Arm != ArmAccessLabels || selectors[1].Container == nil || selectors[1].Container.Arm != ArmAccessLabels {
		t.Fatalf("projection %+v", selectors)
	}
	if !reflect.DeepEqual(selectors[0].MatchAccessLabels, r.MatchAccessLabels) || !reflect.DeepEqual(selectors[1].MatchAccessLabels, r.Children[0].MatchAccessLabels) || !reflect.DeepEqual(selectors[1].Container.MatchAccessLabels, r.MatchAccessLabels) {
		t.Fatal("projection drops restriction")
	}
	selectors[0].MatchAccessLabels["env"] = "changed"
	selectors[1].MatchAccessLabels["team"] = "changed"
	selectors[1].Container.MatchAccessLabels["env"] = "changed"
	if r.MatchAccessLabels["env"] != "prod" || r.Children[0].MatchAccessLabels["team"] != "ops" {
		t.Fatal("projection aliases source")
	}
	before := r.Fingerprint()
	r.Children[0].MatchAccessLabels["team"] = "other"
	if r.Fingerprint() == before {
		t.Fatal("nested selector not fingerprinted")
	}
	if len((Rules{r}).LabelSelectors()) != 0 {
		t.Fatal("new arm leaked into legacy projection")
	}
	// Смешанные переходные формы сохраняют отдельную ось владельца и ребёнка.
	for _, ownerNew := range []bool{false, true} {
		mixed := accessLabelRule()
		mixed.Children = []Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "ops"}}}
		if !ownerNew {
			mixed.MatchLabels = mixed.MatchAccessLabels
			mixed.MatchAccessLabels = nil
			mixed.Children[0].MatchAccessLabels = mixed.Children[0].MatchLabels
			mixed.Children[0].MatchLabels = nil
		}
		got := Rules{mixed}.MaterializingSelectors()[1]
		if got.Arm != mixed.Children[0].Arm() || got.Container.Arm != mixed.Arm() {
			t.Fatal("mixed axes collapsed")
		}
	}
}

func TestAccessLabelsValidationAndNoAuthorityWidening(t *testing.T) {
	mutations := map[string]func(*Rule){
		"empty":         func(r *Rule) { r.MatchAccessLabels = map[string]string{} },
		"legacy":        func(r *Rule) { r.MatchLabels = map[string]string{"env": "prod"} },
		"empty legacy":  func(r *Rule) { r.MatchLabels = map[string]string{} },
		"names":         func(r *Rule) { r.ResourceNames = []string{"acc-a"} },
		"creator":       func(r *Rule) { r.CreatedBySubject = true },
		"wild module":   func(r *Rule) { r.Module = "*" },
		"wild resource": func(r *Rule) { r.Resources = []string{"*"} },
		"wild verb":     func(r *Rule) { r.Verbs = []string{"*"} },
		"bad key":       func(r *Rule) { r.MatchAccessLabels = map[string]string{"": "prod"} },
		"too many": func(r *Rule) {
			for i := 0; i < 17; i++ {
				r.MatchAccessLabels[strings.Repeat("a", i+1)] = "v"
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			r := accessLabelRule()
			mutate(&r)
			if r.Arm() != ArmAccessLabels {
				t.Fatal("invalid new arm became anchor/name")
			}
			if err := r.Validate(TenantPolicy(), fixtureModules()); err == nil {
				t.Fatal("invalid rule accepted")
			}
			if _, err := EncodeRules(Rules{r}); err == nil {
				t.Fatal("invalid selector encoded")
			}
		})
	}
	unfed := accessLabelRule()
	unfed.Module = "probe"
	unfed.Resources = []string{"object"}
	if err := unfed.Validate(TenantPolicy(), fixtureModules()); err == nil {
		t.Fatal("unfed type accepted access selector")
	}
	r := accessLabelRule()
	compiled, err := CompileRules([]Rule{r})
	if err != nil || len(compiled) != 0 {
		t.Fatalf("flat permissions widened: %v, %v", compiled, err)
	}
	if got := (Rules{r}).ScopeSelfVerbs("account", []string{"get"}); len(got) != 0 {
		t.Fatalf("anchor widened: %v", got)
	}
	if r.ReadsWholeType("iam.account") {
		t.Fatal("selector became whole-type public read")
	}
	for _, resource := range []string{"accessBinding", "role"} {
		capability := accessLabelRule()
		capability.Resources = []string{resource}
		if resource == "role" {
			capability.Verbs = []string{"bind"}
			capability.ResourceNames = []string{"rol-a"}
		} else {
			capability.Verbs = []string{"create"}
		}
		if _, _, err := SplitGrantCapabilityRules(Rules{capability}); err == nil {
			t.Fatalf("%s capability widened", resource)
		}
	}
	ordinary, _, err := SplitGrantCapabilityRules(Rules{r})
	if err != nil {
		t.Fatal(err)
	}
	ordinary[0].MatchAccessLabels["env"] = "changed"
	if r.MatchAccessLabels["env"] != "prod" {
		t.Fatal("capability split aliases new selector")
	}
}

func TestAccessLabelsCodecRejectsErasedRestrictions(t *testing.T) {
	cases := []string{
		`[{"module":"iam","resources":["account"],"verbs":["get"],"match_access_labels":null}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"match_access_labels":{}}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"match_access_labels":{"env":"prod"},"match_labels":null}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"match_access_labels":{"env":"prod"},"resource_names":["acc-a"]}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"children":[{"resources":["project"],"verbs":["get"],"match_access_labels":null}]}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"children":[{"resources":["project"],"verbs":["get"],"match_access_labels":{"env":"prod"},"created_by_subject":true}]}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"children":[{"module":"vpc","resources":["project"],"verbs":["get"],"match_access_labels":{"env":"prod"}}]}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"children":[{"resources":["project"],"verbs":["get"],"children":[{"resources":["group"],"verbs":["get"],"match_access_labels":{"env":"prod"}}]}]}]`,
	}
	for _, raw := range cases {
		if got, err := DecodeRules([]byte(raw)); err == nil {
			t.Fatalf("erased selector accepted: %s => %+v", raw, got)
		}
	}
	// Регистр ключей не позволяет обойти проверку присутствующего NULL.
	for _, raw := range []string{
		`[{"module":"iam","resources":["account"],"verbs":["get"],"MATCH_ACCESS_LABELS":null}]`,
		`[{"module":"iam","resources":["account"],"verbs":["get"],"CHILDREN":[{"resources":["project"],"verbs":["get"],"MATCH_ACCESS_LABELS":null}]}]`,
	} {
		if _, err := DecodeRules([]byte(raw)); err == nil {
			t.Fatalf("case-folded restriction erased: %s", raw)
		}
	}
	// Старый codec по-прежнему не служит общим валидатором legacy-полей.
	for _, raw := range []string{`[{"module":"iam","resources":["group"],"verbs":["get"],"match_labels":null}]`, `[{"module":"iam","resources":["group"],"verbs":["get"],"match_labels":{}}]`} {
		if _, err := DecodeRules([]byte(raw)); err != nil {
			t.Fatalf("legacy decode changed: %v", err)
		}
	}
}
