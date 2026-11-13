// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"reflect"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func recipientFacts(t *testing.T, declared bool) *Facts {
	t.Helper()
	f, err := NewFacts(Halves{Live: Rows{
		Modules: []string{"probe", "other"},
		Resources: []ResourceRow{
			{Module: "probe", Resource: "boxes", ObjectType: "unusual_container", PublicReadToChildren: declared},
			{Module: "probe", Resource: "items", ObjectType: "unusual_child", ParentTypes: []string{"unusual_container"}},
			{Module: "probe", Resource: "tags", ObjectType: "unusual_grandchild", ParentTypes: []string{"unusual_child"}},
			{Module: "other", Resource: "items", ObjectType: "foreign_child", ParentTypes: []string{"unusual_container"}},
		},
		Verbs: []VerbRow{{Module: "probe", Resource: "boxes", Verb: "get", PerObject: true}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func recipientSelectors() []domain.RuleSelector {
	return []domain.RuleSelector{
		{RuleFP: "owner", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.boxes"}, Verbs: []string{"get", "list"}},
		{RuleFP: "child", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"get", "list"},
			Container: &domain.ContainerSelector{Type: "probe.boxes", OwnerFP: "owner", Arm: domain.ArmAnchor}},
	}
}

func TestPublicReaderEffect_ActualTypeAllClassesAndMemberKey(t *testing.T) {
	f := recipientFacts(t, true)
	subjects := []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: "anonymous"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated},
		{Type: domain.SubjectTypeServiceAccount, ID: "anonymous"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous},
		{Type: domain.SubjectTypeGroup, ID: "anonymous"},
	}
	selectors := recipientSelectors()
	second := selectors[1]
	second.RuleFP = "another-child"
	selectors = append(selectors, second)
	got, ok := f.PublicReaderEffect(selectors, subjects, "probe.boxes", map[string]bool{"owner": true})
	if !ok {
		t.Fatal("supported class effect missing")
	}
	wantKey := "public_reader:another-child,child@system_class:anonymous,system_class:authenticated"
	if got.FGAType != "unusual_container" || got.ObjectType != "probe.boxes" || got.Relation != domain.PublicReaderRelation || got.RuleFP != wantKey || !slices.Equal(got.ChildRuleFPs, []string{"another-child", "child"}) {
		t.Fatalf("effect: %+v", got)
	}
	wantSubjects := []domain.Subject{subjects[1], subjects[3]}
	if !reflect.DeepEqual(got.Recipients, wantSubjects) {
		t.Fatalf("class identity/order changed: %+v", got.Recipients)
	}
	wantTuples := []domain.MembershipTuple{
		{User: "system_class:authenticated", Relation: domain.PublicReaderRelation, Object: "unusual_container:b1"},
		{User: "system_class:anonymous", Relation: domain.PublicReaderRelation, Object: "unusual_container:b1"},
	}
	if !reflect.DeepEqual(got.Tuples("b1"), wantTuples) {
		t.Fatalf("tuples: %+v", got.Tuples("b1"))
	}
	slices.Reverse(subjects)
	slices.Reverse(selectors)
	permuted, ok := f.PublicReaderEffect(selectors, subjects, "probe.boxes", map[string]bool{"owner": true})
	if !ok || permuted.RuleFP != wantKey {
		t.Fatalf("permutation changed key: %+v", permuted)
	}
	single, ok := f.PublicReaderEffect(selectors, wantSubjects[:1], "probe.boxes", map[string]bool{"owner": true})
	if !ok || single.RuleFP == got.RuleFP || len(single.Recipients) != 1 {
		t.Fatalf("class removal did not change key: %+v", single)
	}
	removed, ok := f.PublicReaderEffect(recipientSelectors(), subjects, "probe.boxes", map[string]bool{"owner": true})
	if !ok || removed.RuleFP == got.RuleFP {
		t.Fatalf("child removal did not change key: %+v", removed)
	}
}

func TestPublicReaderEffect_PredicatePositiveAndNegativeTwins(t *testing.T) {
	cases := []struct {
		name   string
		change func([]domain.RuleSelector)
		want   bool
	}{
		{name: "whole-direct-child", want: true},
		{name: "read-filter-before-child-predicate", change: func(s []domain.RuleSelector) { s[1].Verbs = []string{"get", "list", "update", "*"} }, want: true},
		{name: "get-only", change: func(s []domain.RuleSelector) { s[1].Verbs = []string{"get"} }},
		{name: "list-only", change: func(s []domain.RuleSelector) { s[1].Verbs = []string{"list"} }},
		{name: "wildcard-only", change: func(s []domain.RuleSelector) { s[1].Verbs = []string{"*"} }},
		{name: "names", change: func(s []domain.RuleSelector) { s[1].Arm = domain.ArmNames; s[1].ResourceNames = []string{"x"} }},
		{name: "labels", change: func(s []domain.RuleSelector) {
			s[1].Arm = domain.ArmLabels
			s[1].MatchLabels = map[string]string{"team": "a"}
		}},
		{name: "grandchild", change: func(s []domain.RuleSelector) { s[1].ObjectTypes = []string{"probe.tags"} }},
		{name: "foreign-module", change: func(s []domain.RuleSelector) { s[1].ObjectTypes = []string{"other.items"} }},
		{name: "non-nested-child", change: func(s []domain.RuleSelector) { s[1].Container = nil }},
		{name: "wrong-container-type", change: func(s []domain.RuleSelector) { s[1].Container.Type = "probe.tags" }},
		{name: "other-owner", change: func(s []domain.RuleSelector) { s[1].Container.OwnerFP = "elsewhere" }},
		{name: "write-only-owner", change: func(s []domain.RuleSelector) { s[0].Verbs = []string{"update"} }},
		{name: "wildcard-owner", change: func(s []domain.RuleSelector) { s[0].Verbs = []string{"*"} }},
	}
	f := recipientFacts(t, true)
	subjects := []domain.Subject{{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := recipientSelectors()
			if tc.change != nil {
				tc.change(s)
			}
			before := append([]string(nil), s[1].Verbs...)
			got, ok := f.PublicReaderEffect(s, subjects, "probe.boxes", map[string]bool{"owner": true})
			if ok != tc.want {
				t.Fatalf("ok=%v want=%v, effect=%+v", ok, tc.want, got)
			}
			if !slices.Equal(s[1].Verbs, before) {
				t.Fatalf("authored child mutated: %+v", s[1])
			}
		})
	}
	for _, owners := range []map[string]bool{nil, {"owner": false}, {"other": true}} {
		if _, ok := f.PublicReaderEffect(recipientSelectors(), subjects, "probe.boxes", owners); ok {
			t.Fatalf("unselected owner accepted: %v", owners)
		}
	}
	if _, ok := recipientFacts(t, false).PublicReaderEffect(recipientSelectors(), subjects, "probe.boxes", map[string]bool{"owner": true}); ok {
		t.Fatal("undeclared container accepted")
	}
	if _, ok := f.PublicReaderEffect(recipientSelectors(), subjects, "unknown.boxes", map[string]bool{"owner": true}); ok {
		t.Fatal("unknown container accepted")
	}
	for _, kind := range []domain.SubjectType{domain.SubjectTypeUser, domain.SubjectTypeServiceAccount, domain.SubjectTypeGroup} {
		if _, ok := f.PublicReaderEffect(recipientSelectors(), []domain.Subject{{Type: kind, ID: "anonymous"}}, "probe.boxes", map[string]bool{"owner": true}); ok {
			t.Fatalf("non-class %s received public_reader", kind)
		}
	}
}
