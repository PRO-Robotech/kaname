// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"reflect"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestGrantCapability_ExtractsOnlyExplicitPairs(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule domain.Rule
		want domain.GrantCapabilityKind
	}{
		{"create", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}, domain.GrantCapabilityCreateBinding},
		{"bind", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol1"}}, domain.GrantCapabilityBindRole},
		{"ordinary_wildcard", domain.Rule{Module: "iam", Resources: []string{"role", "accessBinding"}, Verbs: []string{"*"}}, ""},
		{"other_module", domain.Rule{Module: "probe", Resources: []string{"role"}, Verbs: []string{"bind"}}, ""},
		{"other_resource", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"create"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ordinary, capabilities, err := domain.SplitGrantCapabilityRules(domain.Rules{tc.rule})
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if len(capabilities) != 0 || !reflect.DeepEqual(domain.Rules{tc.rule}, ordinary) {
					t.Fatalf("обычное правило стало управляющим: ordinary=%+v capabilities=%+v", ordinary, capabilities)
				}
				return
			}
			if len(ordinary) != 0 || len(capabilities) != 1 || capabilities[0].Kind != tc.want || len(capabilities[0].RuleFP) != 64 {
				t.Fatalf("неполная управляющая проекция: ordinary=%+v capabilities=%+v", ordinary, capabilities)
			}
		})
	}
}

func TestGrantCapability_PreservesTheResidualCartesianProduct(t *testing.T) {
	rules := domain.Rules{{Module: "iam", Resources: []string{"accessBinding", "role", "group"}, Verbs: []string{"get", "create"}}}
	ordinary, capabilities, err := domain.SplitGrantCapabilityRules(rules)
	if err != nil || len(capabilities) != 1 {
		t.Fatalf("не выделено create: %+v %v", capabilities, err)
	}
	got := map[string]bool{}
	for _, rule := range ordinary {
		for _, resource := range rule.Resources {
			for _, verb := range rule.Verbs {
				got[resource+"/"+verb] = true
			}
		}
	}
	want := map[string]bool{"accessBinding/get": true, "role/get": true, "role/create": true, "group/get": true, "group/create": true}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("при выделении meta потеряны или добавлены обычные права: got=%v want=%v", got, want)
	}
}

func TestGrantCapability_BindRetainsNamedOrdinaryRights(t *testing.T) {
	rule := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "bind"}, ResourceNames: []string{"rolA", "rolB"}}
	ordinary, capabilities, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
	if err != nil || len(ordinary) != 1 || len(capabilities) != 2 {
		t.Fatalf("неполное разбиение: %+v %+v %v", ordinary, capabilities, err)
	}
	rule.Verbs = []string{"get"}
	if !reflect.DeepEqual(ordinary[0], rule) || capabilities[0].BoundRoleID != "rolA" || capabilities[1].BoundRoleID != "rolB" {
		t.Fatalf("изменены названные права: %+v %+v", ordinary, capabilities)
	}
}

func TestGrantCapability_WildcardIsNotExpandedIntoFiniteVerbs(t *testing.T) {
	rule := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"*", "bind"}, ResourceNames: []string{"rolA"}}
	ordinary, capabilities, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
	if err != nil || len(ordinary) != 1 || len(capabilities) != 1 || !reflect.DeepEqual(ordinary[0].Verbs, []string{"*"}) {
		t.Fatalf("символический остаток потерян: %+v %+v %v", ordinary, capabilities, err)
	}
}

func TestGrantCapability_RejectsAmbiguousControlSelectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule domain.Rule
	}{
		{"create_names", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}, ResourceNames: []string{"rolA"}}},
		{"bind_without_names", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}}},
		{"bind_star_name", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"*"}}},
		{"bind_empty_name", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{""}}},
		{"bind_labels", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rolA"}, MatchLabels: map[string]string{"env": "prod"}}},
		{"bind_creator", domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rolA"}, CreatedBySubject: true}},
		{"create_children", domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}, Children: []domain.Rule{{Resources: []string{"role"}, Verbs: []string{"get"}}}}},
		{"nested_bind", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, Children: []domain.Rule{{Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rolA"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ordinary, capabilities, err := domain.SplitGrantCapabilityRules(domain.Rules{tc.rule})
			if err == nil || ordinary != nil || capabilities != nil {
				t.Fatalf("неоднозначный управляющий ввод не отклонён целиком: %+v %+v %v", ordinary, capabilities, err)
			}
		})
	}
}

func TestGrantCapability_CanonicalSourceFingerprint(t *testing.T) {
	a := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "bind"}, ResourceNames: []string{"rolA", "rolB"}}
	b := domain.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind", "get"}, ResourceNames: []string{"rolB", "rolA"}, MatchLabels: map[string]string{}}
	_, capabilities, err := domain.SplitGrantCapabilityRules(domain.Rules{a, b, a})
	if err != nil || len(capabilities) != 2 || capabilities[0].RuleFP != capabilities[1].RuleFP {
		t.Fatalf("порядок или дубликат изменил полномочия/источник: %+v %v", capabilities, err)
	}
	c := a
	c.ResourceNames = []string{"rolC"}
	_, changed, err := domain.SplitGrantCapabilityRules(domain.Rules{c})
	if err != nil || len(changed) != 1 || changed[0].RuleFP == capabilities[0].RuleFP {
		t.Fatalf("смена целевой роли потеряна в источнике: %+v %v", changed, err)
	}
}

func TestGrantCapability_OrdinaryOutputDoesNotAliasTheInput(t *testing.T) {
	rule := domain.Rule{Module: "probe", Resources: []string{"box"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}, Children: []domain.Rule{{Resources: []string{"item"}, Verbs: []string{"get"}}}}
	ordinary, _, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
	if err != nil {
		t.Fatal(err)
	}
	ordinary[0].Resources[0] = "other"
	ordinary[0].Verbs[0] = "update"
	ordinary[0].MatchLabels["env"] = "dev"
	ordinary[0].Children[0].Resources[0] = "other"
	if rule.Resources[0] != "box" || rule.Verbs[0] != "get" || rule.MatchLabels["env"] != "prod" || rule.Children[0].Resources[0] != "item" {
		t.Fatal("нормализация изменила авторское правило")
	}
}

func TestGrantCapability_TheWholeCarrierRequiresTheScopeTarget(t *testing.T) {
	capability := domain.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}
	ordinary := domain.Rule{Module: "probe", Resources: []string{"box"}, Verbs: []string{"get"}}
	named := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.box", ID: "x"}}}
	for _, target := range []domain.AccessTarget{{}, named, {AllInScope: true, Resources: named.Resources}} {
		if err := domain.ValidateGrantCapabilityTarget(domain.Rules{ordinary, capability}, target); err == nil {
			t.Fatalf("носитель управляющего права принял цель %+v", target)
		}
	}
	if err := domain.ValidateGrantCapabilityTarget(domain.Rules{ordinary, capability}, domain.AccessTarget{AllInScope: true}); err != nil {
		t.Fatal(err)
	}
	if err := domain.ValidateGrantCapabilityTarget(domain.Rules{ordinary}, named); err != nil {
		t.Fatalf("обычная объектная выдача изменилась: %v", err)
	}
}
