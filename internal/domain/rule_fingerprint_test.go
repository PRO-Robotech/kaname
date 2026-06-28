// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// rule_fingerprint_test.go — RBAC rules-model 2026, single-module form
// (Rule.module scalar).
//
// Per-rule membership is keyed by a CONTENT-HASH of the rule
// (rule_fp), NOT a positional index — a role's rules[] is mutable, so reordering or
// removing a rule must not desync the materialized membership. Rule.Fingerprint()
// is the pure-domain content-hash: stable across field-order permutations of the
// SAME rule, distinct for any semantic difference (module / verbs / matchLabels /
// types).
//
// Rules.LabelSelectors() projects a role's rules to the ARM_LABELS selectors the
// reconciler drives: one (fp, types, matchLabels, verbs) per ARM_LABELS rule —
// ARM_ANCHOR / ARM_NAMES rules are NOT reconciler-driven (they emit at Create /
// B-emit), so they are excluded. With a scalar module the projected ObjectTypes
// are `{module}.<resource>` over the rule's resources (no module unroll).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleFingerprint_StableAcrossFieldReorder(t *testing.T) {
	// Same rule, element lists in different orders + matchLabels iteration order
	// must hash to the SAME fingerprint (content-hash, not order-sensitive). The
	// module is scalar so it cannot be reordered — resources/verbs/labels do.
	a := Rule{
		Module:      "vpc",
		Resources:   []string{"subnet", "network"},
		Verbs:       []string{"create", "get"},
		MatchLabels: map[string]string{"env": "prod", "team": "payments"},
	}
	b := Rule{
		Module:      "vpc",
		Resources:   []string{"network", "subnet"},
		Verbs:       []string{"get", "create"},
		MatchLabels: map[string]string{"team": "payments", "env": "prod"},
	}
	fpA := a.Fingerprint()
	fpB := b.Fingerprint()
	require.NotEmpty(t, fpA, "fingerprint must be non-empty")
	assert.Equal(t, fpA, fpB, "reordered fields → same content-hash")
}

func TestRuleFingerprint_DistinctPerSemanticDifference(t *testing.T) {
	base := Rule{
		Module:      "vpc",
		Resources:   []string{"subnet"},
		Verbs:       []string{"create"},
		MatchLabels: map[string]string{"env": "prod"},
	}
	fpBase := base.Fingerprint()

	// different module
	diffModule := base
	diffModule.Module = "compute"
	assert.NotEqual(t, fpBase, diffModule.Fingerprint(), "different module → different fp")

	// different verb
	diffVerb := base
	diffVerb.Verbs = []string{"delete"}
	assert.NotEqual(t, fpBase, diffVerb.Fingerprint(), "different verb → different fp")

	// different matchLabels value
	diffLabelVal := base
	diffLabelVal.MatchLabels = map[string]string{"env": "staging"}
	assert.NotEqual(t, fpBase, diffLabelVal.Fingerprint(), "different label value → different fp")

	// different matchLabels key
	diffLabelKey := base
	diffLabelKey.MatchLabels = map[string]string{"tier": "prod"}
	assert.NotEqual(t, fpBase, diffLabelKey.Fingerprint(), "different label key → different fp")

	// different resource
	diffRes := base
	diffRes.Resources = []string{"network"}
	assert.NotEqual(t, fpBase, diffRes.Fingerprint(), "different resource → different fp")
}

func TestRuleFingerprint_ArmNamesVsArmLabels_Distinct(t *testing.T) {
	// A names-arm and a labels-arm over the same module/resources/verbs are
	// semantically different rules and must not collide.
	names := Rule{
		Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"},
		ResourceNames: []string{"sub-1"},
	}
	labels := Rule{
		Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"},
		MatchLabels: map[string]string{"id": "sub-1"},
	}
	assert.NotEqual(t, names.Fingerprint(), labels.Fingerprint(), "names vs labels arm → distinct fp")
}

func TestRulesLabelSelectors_OnlyArmLabels(t *testing.T) {
	rs := Rules{
		// ARM_ANCHOR — excluded
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}},
		// ARM_NAMES — excluded
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"}, ResourceNames: []string{"sub-1"}},
		// ARM_LABELS — included
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "delete"},
			MatchLabels: map[string]string{"env": "prod"}},
		// ARM_LABELS — included (2nd)
		{Module: "vpc", Resources: []string{"subnet"}, Verbs: []string{"create"},
			MatchLabels: map[string]string{"team": "net"}},
	}
	sels := rs.LabelSelectors()
	require.Len(t, sels, 2, "only the two ARM_LABELS rules are reconciler-driven selectors")

	// Each selector carries the rule's fp, dotted types, matchLabels and verbs.
	byFP := map[string]RuleLabelSelector{}
	for _, s := range sels {
		require.NotEmpty(t, s.RuleFP, "selector carries rule_fp")
		byFP[s.RuleFP] = s
	}
	require.Len(t, byFP, 2, "distinct fp per selector")

	// Find the compute.instance selector and assert its projection.
	var found bool
	for _, s := range sels {
		if len(s.ObjectTypes) == 1 && s.ObjectTypes[0] == "compute.instance" {
			found = true
			assert.Equal(t, map[string]string{"env": "prod"}, s.MatchLabels)
			assert.ElementsMatch(t, []string{"get", "delete"}, s.Verbs)
			assert.Equal(t, rs[2].Fingerprint(), s.RuleFP, "selector fp == rule fp")
		}
	}
	assert.True(t, found, "compute.instance label selector projected")
}

// TestRules_LabelSelectors_SingleModule (H-05): a label rule over ONE module ×
// multiple resources projects to `{module}.<resource>` for each resource (no
// module unroll — module is scalar).
func TestRules_LabelSelectors_SingleModule(t *testing.T) {
	rs := Rules{
		{Module: "vpc", Resources: []string{"subnet", "network"}, Verbs: []string{"get"},
			MatchLabels: map[string]string{"env": "prod"}},
	}
	sels := rs.LabelSelectors()
	require.Len(t, sels, 1)
	assert.ElementsMatch(t, []string{"vpc.subnet", "vpc.network"}, sels[0].ObjectTypes,
		"single module × resources → dotted types")
}
