// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_verbs_test.go — domain-level unit tests for Rules.ScopeSelfVerbs (review
// #13 / ban #12). ScopeSelfVerbs is a pure public domain function that projects a
// role's rules onto the binding's OWN scope object (account:<X>/project:<X>); it
// previously had only INDIRECT coverage via the slow testcontainers integration
// path (owner_role_seed_integration_test.go), which exercised ONLY the `*.*`
// wildcard branch. These fast pure-domain table cases cover the uncovered branches:
// direct `iam.<scopeResource>` match, the half-wildcard fail-closed shape, the
// content-only matched=false→nil path, and the union-of-verbs accumulation.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fullClosedVerbs is the closed CRUD verb-set a `*` verb expands to.
func fullClosedVerbs() []string {
	out := append([]string(nil), ClosedVerbs...)
	sort.Strings(out)
	return out
}

func TestRules_ScopeSelfVerbs(t *testing.T) {
	tests := []struct {
		name          string
		rules         Rules
		scopeResource string
		// want is the SORTED expected verb set; nil ⇒ expect a nil/empty result.
		want []string
	}{
		{
			// (a) FULL `*.*` superuser shape (seeded owner / cluster-admin) → full
			// closed verb-set on the scope object, regardless of scopeResource.
			name:          "full-wildcard *.* on account → full closed verb-set",
			rules:         Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}},
			scopeResource: "account",
			want:          fullClosedVerbs(),
		},
		{
			name:          "full-wildcard *.* on project → full closed verb-set",
			rules:         Rules{{Module: wildcard, Resources: []string{wildcard}, Verbs: []string{wildcard}}},
			scopeResource: "project",
			want:          fullClosedVerbs(),
		},
		{
			// (b) direct iam.account rule on an account-scoped binding → its authored
			// verbs land on the scope object itself (verb-bearing account anchor, D-6).
			name:          "iam.account rule on account scope → authored verbs",
			rules:         Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "update"}}},
			scopeResource: "account",
			want:          []string{"get", "update"},
		},
		{
			// (c) iam.project rule on an ACCOUNT scope must NOT match (resource mismatch)
			// → nil (fail-closed; the rule grants on projects, not on the account-self).
			name:          "iam.project rule on account scope → nil (resource mismatch)",
			rules:         Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}},
			scopeResource: "account",
			want:          nil,
		},
		{
			name:          "iam.project rule on project scope → authored verbs",
			rules:         Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get", "delete"}}},
			scopeResource: "project",
			want:          []string{"delete", "get"},
		},
		{
			// (d) content-only role (compute.instance) grants NOTHING on the scope
			// object itself → nil (only its content materializes, not scope-self).
			name:          "content-only compute.instance → nil",
			rules:         Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "create"}}},
			scopeResource: "account",
			want:          nil,
		},
		{
			// (e) half-wildcard shapes (`*.concrete` / `concrete.*`) are NOT a real seed
			// shape and never grant scope-self → fail-closed nil.
			name:          "half-wildcard *.account → nil (not a superuser shape)",
			rules:         Rules{{Module: wildcard, Resources: []string{"account"}, Verbs: []string{"get"}}},
			scopeResource: "account",
			want:          nil,
		},
		{
			name:          "half-wildcard iam.* → nil (not a superuser shape)",
			rules:         Rules{{Module: "iam", Resources: []string{wildcard}, Verbs: []string{"get"}}},
			scopeResource: "account",
			want:          nil,
		},
		{
			// (f) union accumulation: an iam.account rule PLUS a content rule — only the
			// scope-self rule's verbs count; verb `*` expands to the full closed set.
			name: "iam.account(*) + content rule → full closed verb-set (union of scope-self only)",
			rules: Rules{
				{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}},
				{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}},
			},
			scopeResource: "account",
			want:          fullClosedVerbs(),
		},
		{
			// (g) empty scopeResource (cluster — no per-resource iam rule) with a
			// non-wildcard iam rule → nil (only the `*.*` branch grants cluster-self).
			name:          "iam.account rule with empty scopeResource → nil",
			rules:         Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}},
			scopeResource: "",
			want:          nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rules.ScopeSelfVerbs(tt.scopeResource)
			if tt.want == nil {
				assert.Empty(t, got, "expected no scope-self verbs (fail-closed)")
				return
			}
			gotSorted := append([]string(nil), got...)
			sort.Strings(gotSorted)
			assert.Equal(t, tt.want, gotSorted)
		})
	}
}
