// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestRuleTypeProjection_ProducerScopeAndWildcardTwins(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rule       Rule
		scope      Scope
		kind       RuleTypeWildcard
		module     string
		suppressed bool
		want       []string
	}{
		{name: "all-account", rule: Rule{Module: "*", Resources: []string{"*"}}, scope: ScopeAccount, kind: RuleTypeWildcardAllModules, module: "*", want: AllMaterializableTypes()},
		{name: "all-project", rule: Rule{Module: "*", Resources: []string{"*"}}, scope: ScopeProject, kind: RuleTypeWildcardAllModules, module: "*", want: AllMaterializableTypes()},
		{name: "all-cluster-suppressed", rule: Rule{Module: "*", Resources: []string{"*"}}, scope: ScopeCluster, kind: RuleTypeWildcardAllModules, module: "*", suppressed: true},
		{name: "all-unspecified-suppressed", rule: Rule{Module: "*", Resources: []string{"*"}}, scope: ScopeUnspecified, kind: RuleTypeWildcardAllModules, module: "*", suppressed: true},
		{name: "module-project", rule: Rule{Module: "registry", Resources: []string{"*"}}, scope: ScopeProject, kind: RuleTypeWildcardModuleResources, module: "registry", want: []string{"registry.registries", "registry.repositories"}},
		{name: "module-cluster-suppressed", rule: Rule{Module: "registry", Resources: []string{"*"}}, scope: ScopeCluster, kind: RuleTypeWildcardModuleResources, module: "registry", suppressed: true},
		{name: "mixed-cluster-preserves-explicit", rule: Rule{Module: "registry", Resources: []string{"registries", "*", "repositories"}}, scope: ScopeCluster, kind: RuleTypeWildcardModuleResources, module: "registry", suppressed: true, want: []string{"registry.registries", "registry.repositories"}},
		{name: "mixed-project-replaces-explicit", rule: Rule{Module: "registry", Resources: []string{"madeUp", "*", "registries"}}, scope: ScopeProject, kind: RuleTypeWildcardModuleResources, module: "registry", want: []string{"registry.registries", "registry.repositories"}},
		{name: "unknown-module-static-empty", rule: Rule{Module: "futureprobe", Resources: []string{"*"}}, scope: ScopeProject, kind: RuleTypeWildcardModuleResources, module: "futureprobe"},
		{name: "module-star-ignores-resource-filter", rule: Rule{Module: "*", Resources: []string{"network"}}, scope: ScopeProject, kind: RuleTypeWildcardAllModules, module: "*", want: AllMaterializableTypes()},
		{name: "explicit-future-type", rule: Rule{Module: "futureprobe", Resources: []string{"newType"}}, scope: ScopeCluster, want: []string{"futureprobe.newType"}},
		{name: "verb-star-is-not-type-star", rule: Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}, scope: ScopeProject, want: []string{"vpc.network"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.rule.MaterializedTypeProjection(tc.scope)
			if !slices.Equal(p.ObjectTypes, tc.want) || p.WildcardKind != tc.kind || p.WildcardModule != tc.module || p.WildcardSuppressed != tc.suppressed {
				t.Fatalf("projection=%+v, want types=%v kind=%v module=%q suppressed=%v", p, tc.want, tc.kind, tc.module, tc.suppressed)
			}
			if p.UsesStaticRegistry() != (tc.kind != RuleTypeWildcardNone && !tc.suppressed) {
				t.Fatalf("static provenance lost: %+v", p)
			}
			selectors := Rules{tc.rule}.MaterializingSelectorsInScope(tc.scope)
			if len(selectors) != 1 || !slices.Equal(selectors[0].ObjectTypes, tc.want) {
				t.Fatalf("actual selectors=%+v", selectors)
			}
		})
	}
}

func TestRuleTypeProjection_FullSelectorAndRoleIndexKeepAuthoredSemantics(t *testing.T) {
	for _, rule := range []Rule{
		{Module: "*", Resources: []string{"*"}, Verbs: []string{"get", "list"}},
		{Module: "registry", Resources: []string{"*"}, Verbs: []string{"get", "update"}},
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}, ResourceNames: []string{"n2", "n1"}},
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "a"}},
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, CreatedBySubject: true},
	} {
		for _, scope := range []Scope{ScopeAccount, ScopeProject, ScopeCluster} {
			sels := Rules{rule}.MaterializingSelectorsInScope(scope)
			if len(sels) != 1 {
				t.Fatalf("selectors=%+v", sels)
			}
			s := sels[0]
			if s.RuleFP != rule.Fingerprint() || s.Arm != rule.Arm() || !slices.Equal(s.Verbs, rule.Verbs) || !slices.Equal(s.ResourceNames, rule.ResourceNames) || !reflect.DeepEqual(s.MatchLabels, rule.MatchLabels) || s.CreatedBySubject != rule.CreatedBySubject {
				t.Fatalf("authored selector changed: %+v from %+v", s, rule)
			}
		}
		index := Rules{rule}.MaterializingSelectors()
		bounded := rule.MaterializedTypeProjection(ScopeProject)
		if len(index) != 1 || !slices.Equal(index[0].ObjectTypes, bounded.ObjectTypes) {
			t.Fatalf("role index no longer expands: %+v", index)
		}
	}
	rule := Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}, Children: []Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}}}
	sels := Rules{rule}.MaterializingSelectorsInScope(ScopeCluster)
	if len(sels) != 2 || sels[1].Container == nil || sels[1].Container.OwnerFP != rule.Fingerprint() || !slices.Equal(sels[1].ObjectTypes, []string{"registry.repositories"}) {
		t.Fatalf("concrete nested selector lost on cluster: %+v", sels)
	}
}

func TestRuleTypeProjection_FreshResultsDoNotMutateStaticRegistry(t *testing.T) {
	r := Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}}
	original := AllMaterializableTypes()
	p := r.MaterializedTypeProjection(ScopeProject)
	if len(p.ObjectTypes) == 0 {
		t.Fatal("empty control")
	}
	p.ObjectTypes[0] = "changed.by.caller"
	if got := r.MaterializedTypeProjection(ScopeProject); !slices.Equal(got.ObjectTypes, original) {
		t.Fatalf("registry mutation: %+v", got)
	}
	module := Rule{Module: "registry", Resources: []string{"*"}}
	for _, typ := range module.MaterializedTypeProjection(ScopeProject).ObjectTypes {
		if !strings.HasPrefix(typ, "registry.") {
			t.Fatalf("module wildcard leaked: %s", typ)
		}
	}
}

func TestRuleTypeProjection_FullRuleScopeSelfKeepsWildcardMarker(t *testing.T) {
	typeVerbs := []string{"get", "list", "update", "delete", "futureAction"}
	full := Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}
	named := Rules{{Module: "*", Resources: []string{"*"}, Verbs: typeVerbs}}
	fullVerbs := full.ScopeSelfVerbs("account", typeVerbs)
	namedVerbs := named.ScopeSelfVerbs("account", typeVerbs)
	_, fullTier := ResolveVerbsAndTier(fullVerbs, typeVerbs)
	_, namedTier := ResolveVerbsAndTier(namedVerbs, typeVerbs)
	if !slices.Contains(fullVerbs, "*") || !slices.Contains(fullVerbs, "futureAction") || fullTier != "admin" || slices.Contains(namedVerbs, "*") || namedTier == "admin" {
		t.Fatalf("full-rule marker lost: %v/%s versus %v/%s", fullVerbs, fullTier, namedVerbs, namedTier)
	}
	for _, half := range []Rule{{Module: "*", Resources: []string{"account"}, Verbs: []string{"*"}}, {Module: "iam", Resources: []string{"*"}, Verbs: []string{"*"}}} {
		if got := (Rules{half}).ScopeSelfVerbs("account", typeVerbs); len(got) != 0 {
			t.Fatalf("half wildcard gained scope self: %v", got)
		}
	}
}
