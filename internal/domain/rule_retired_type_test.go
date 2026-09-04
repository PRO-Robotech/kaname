// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"strings"
	"testing"
)

// rule_retired_type_test.go — a rule may not name a resource the platform has
// retired, on ANY of the three arms.
//
// WHAT THIS IS ABOUT. `Rule.Validate` runs a type-vocabulary check on exactly one
// arm of three: the feed-gate fires only when `match_labels` is set (ARM_LABELS).
// ARM_ANCHOR and ARM_NAMES are checked for module membership and token grammar
// and nothing else, so a rule naming a retired resource is ACCEPTED and stored.
// It grants nothing — the reconciler materializes from a mirror that has no rows
// of that type, and it fails closed — but the caller is told the rule was taken
// and the role advertises a grant that can never take effect. That is
// accepted-and-ignored at the level of the permission contract.
//
// WHY THE OTHER TWO ARMS DO NOT GET THE FEED ALLOW-LIST. The arms have different
// consumers and therefore genuinely different vocabularies, and this was measured
// rather than assumed (revision bdafe2c4):
//
//	labelSelectableTypes      22 types   consumer: reconciler label-matching
//	materializableTypes       23 types   consumer: reconciler per-object materialization
//	catalog permission prefixes 82 pairs consumer: the method gate, via CompileRules
//
// The first two differ by exactly one deliberate entry (`registry.repositories`:
// materializable, not label-selectable — a repo has no own-table labels, yet the
// owner grant must still expand onto it). Against the rules actually seeded by
// migrations, EVERY one of those sets refuses at least one rule that works today:
// `iam.projects` is absent from both reconciler sets, and `loadbalancer.operations`
// is absent from all three. So an allow-list on ARM_ANCHOR/ARM_NAMES would not be
// "stricter" — it would be wrong, and would reject live seeded roles.
//
// What is knowable with certainty is the other direction: a type the platform has
// RETIRED must not be nameable anywhere. That set is closed, small and already
// code-owned. The gate is therefore a deny-list on all three arms, and it asserts
// nothing about the open part of the vocabulary.
//
// EVERY CASE IS PAIRED. "The retired name is rejected" is on its own
// indistinguishable from "the arm rejects everything" and from "Validate is
// broken". Each rejection below is therefore accompanied by a live type going
// through the SAME arm and being accepted, and `registry.repositories` is carried
// through all three arms to prove the fix did not collapse the two reconciler
// vocabularies into one.

// liveBothSets — a type present in every vocabulary. The positive control: it must
// pass all three arms, or the negative half below proves nothing.
const liveBothSets = "compute.instance"

// retiredDotted — the block-storage types iam no longer knows, in the dotted
// spelling a rule uses. Kept in lockstep with domain.RetiredTypes by
// TestRetiredTypeVocabularyIsTheProductionOne.
var retiredDotted = []string{"compute.disk", "compute.image", "compute.snapshot"}

// TestRetiredTypeVocabularyIsTheProductionOne — this file's table must be the set
// the validator actually consults. Without this, a fourth retired type added to
// production would be gated but untested, and one added here only would test a set
// nothing enforces.
func TestRetiredTypeVocabularyIsTheProductionOne(t *testing.T) {
	prod := RetiredTypes()
	if len(prod) == 0 {
		t.Fatal("RetiredTypes() is empty — validateRetirementGate would refuse nothing")
	}
	local := append([]string(nil), retiredDotted...)
	sortStringsForTest(local)
	if len(prod) != len(local) {
		t.Fatalf("RetiredTypes()=%v, this test's table=%v — they must name the same set", prod, local)
	}
	for i := range prod {
		if prod[i] != local[i] {
			t.Fatalf("RetiredTypes()=%v, this test's table=%v — they must name the same set", prod, local)
		}
	}
	// The retired names must not also be live: a type in both tables would make the
	// paired assertions above contradict each other.
	for _, ty := range prod {
		if ty == liveBothSets {
			t.Fatalf("%q is both the live control and retired — the pairing is meaningless", ty)
		}
		if IsLabelSelectableType(ty) {
			t.Errorf("%q is retired yet still label-selectable — the feed registry did not follow the retirement", ty)
		}
	}
	t.Logf("lockstep: %d retired types", len(prod))
}

func sortStringsForTest(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// splitType splits "compute.disk" into ("compute", "disk").
func splitType(t *testing.T, dotted string) (string, string) {
	t.Helper()
	i := strings.IndexByte(dotted, '.')
	if i <= 0 {
		t.Fatalf("malformed dotted type %q in this test's own table", dotted)
	}
	return dotted[:i], dotted[i+1:]
}

// ruleOnArm builds a rule naming `dotted` on the requested arm.
func ruleOnArm(t *testing.T, dotted string, arm Arm) Rule {
	t.Helper()
	module, resource := splitType(t, dotted)
	r := Rule{Module: module, Resources: []string{resource}, Verbs: []string{"get"}}
	switch arm {
	case ArmNames:
		r.ResourceNames = []string{"abc123"}
	case ArmLabels:
		r.MatchLabels = map[string]string{"team": "a"}
	case ArmAnchor:
	}
	if got := r.Arm(); got != arm {
		t.Fatalf("built rule for arm %v but Arm() reports %v — the test's own builder is wrong", arm, got)
	}
	return r
}

func armName(a Arm) string {
	switch a {
	case ArmNames:
		return "ARM_NAMES"
	case ArmLabels:
		return "ARM_LABELS"
	default:
		return "ARM_ANCHOR"
	}
}

// TestRetiredTypeIsRejectedOnEveryArm — the subject. A retired type must be
// refused on all three arms; a live type must be accepted on all three, through
// the same call.
func TestRetiredTypeIsRejectedOnEveryArm(t *testing.T) {
	if len(retiredDotted) == 0 {
		t.Fatal("empty retired table — this test would assert nothing")
	}
	arms := []Arm{ArmAnchor, ArmNames, ArmLabels}

	// Positive half FIRST: if the live control does not pass an arm, every
	// rejection on that arm below is meaningless.
	for _, arm := range arms {
		if err := ruleOnArm(t, liveBothSets, arm).Validate(TenantPolicy(), fixtureModules()); err != nil {
			t.Fatalf("%s: live control %q was rejected: %v — the negative half on this arm proves nothing",
				armName(arm), liveBothSets, err)
		}
	}
	t.Logf("positive control: %q accepted on all %d arms", liveBothSets, len(arms))

	// Negative half.
	for _, dotted := range retiredDotted {
		for _, arm := range arms {
			err := ruleOnArm(t, dotted, arm).Validate(TenantPolicy(), fixtureModules())
			if err == nil {
				t.Errorf("%s: rule naming retired type %q was ACCEPTED — the role advertises a grant "+
					"that can never take effect (no mirror rows of this type exist); kacho-storage owns these resources",
					armName(arm), dotted)
				continue
			}
			if !strings.Contains(err.Error(), dotted) {
				t.Errorf("%s: rule naming %q was rejected, but the message does not name the type: %v",
					armName(arm), dotted, err)
			}
		}
	}
}

// TestRetiredTypeGateDidNotCollapseTheTwoReconcilerVocabularies — the case that a
// blind "check the same vocabulary" fix would break.
//
// `registry.repositories` is materializable but deliberately NOT label-selectable.
// It must therefore pass ARM_ANCHOR and ARM_NAMES and be refused on ARM_LABELS —
// the pre-existing feed-gate, unchanged. If a future edit points all three arms at
// one set, this fails whichever way the collapse went.
func TestRetiredTypeGateDidNotCollapseTheTwoReconcilerVocabularies(t *testing.T) {
	const ty = "registry.repositories"
	if IsLabelSelectableType(ty) {
		t.Fatalf("%s became label-selectable — this test's premise is gone; either the "+
			"deliberate one-type difference was retired, or the feed registry drifted", ty)
	}
	for _, arm := range []Arm{ArmAnchor, ArmNames} {
		if err := ruleOnArm(t, ty, arm).Validate(TenantPolicy(), fixtureModules()); err != nil {
			t.Errorf("%s: %q was rejected: %v — the owner grant must still expand onto repositories, "+
				"otherwise the images are unreachable even for the owner", armName(arm), ty, err)
		}
	}
	if err := ruleOnArm(t, ty, ArmLabels).Validate(TenantPolicy(), fixtureModules()); err == nil {
		t.Errorf("ARM_LABELS: %q was accepted — a repo has no own-table labels, so a match_labels "+
			"selector on it is inapplicable and the feed-gate must still refuse it", ty)
	}
}

// TestLiveSeededRuleTypesStillValidate — the regression guard against tightening
// ARM_ANCHOR/ARM_NAMES into an allow-list. Every `<module>.<resource>` named by a
// rule that migrations actually seed must keep validating. Measured at bdafe2c4:
// `iam.projects` is in neither reconciler vocabulary and `loadbalancer.operations`
// is in none of the three, so any allow-list would refuse them.
func TestLiveSeededRuleTypesStillValidate(t *testing.T) {
	seeded := []string{
		"iam.projects",
		"loadbalancer.listeners",
		"loadbalancer.networkLoadBalancers",
		"loadbalancer.targetGroups",
		"loadbalancer.operations",
	}
	for _, dotted := range seeded {
		for _, arm := range []Arm{ArmAnchor, ArmNames} {
			if err := ruleOnArm(t, dotted, arm).Validate(TenantPolicy(), fixtureModules()); err != nil {
				t.Errorf("%s: seeded rule type %q no longer validates: %v — a system role that "+
					"migrations install would stop loading", armName(arm), dotted, err)
			}
		}
	}
	t.Logf("checked %d seeded rule types across 2 arms", len(seeded))
}
