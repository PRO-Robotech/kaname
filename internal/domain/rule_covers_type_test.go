// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_covers_type_test.go — redesign-2026 F9 gate 3 (IAM-1-24): RoleCoversType.
// A per-object AccessBinding.target may only name a type that the role's authored
// rules grant verbs on. Rules.CoversType(dottedType) is the pure predicate.

import "testing"

func TestRules_CoversType(t *testing.T) {
	rules := Rules{
		{Module: "compute", Resources: []string{"instance", "disk"}, Verbs: []string{"get", "list"}},
		{Module: "vpc", Resources: []string{"*"}, Verbs: []string{"get"}},
	}
	covered := map[string]bool{
		"compute.instance": true,  // module+resource match
		"compute.disk":     true,  // module+resource match
		"vpc.network":      true,  // module match + resource wildcard
		"vpc.route_table":  true,  // wildcard covers multi-word resource
		"compute.snapshot": false, // module match, resource NOT listed
		"iam.user":         false, // module not present
		"unknown.thing":    false, // unknown
		"compute":          false, // not dotted
		"":                 false, // empty
	}
	for typ, want := range covered {
		if got := rules.CoversType(typ); got != want {
			t.Errorf("Rules.CoversType(%q) = %v, want %v", typ, got, want)
		}
	}

	// empty rules → covers nothing.
	if (Rules{}).CoversType("compute.instance") {
		t.Error("empty Rules must cover nothing")
	}
}
