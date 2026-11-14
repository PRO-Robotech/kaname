// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"reflect"
	"slices"
	"testing"
)

func TestRecipientVerbs_ClassBoundaryAndTypedNeighbours(t *testing.T) {
	verbs := []string{"get", "update", "*", "list", "get"}
	for _, kind := range []SubjectType{SubjectTypeUser, SubjectTypeServiceAccount, SubjectTypeGroup, SubjectTypeSystemClass} {
		for _, nested := range []bool{false, true} {
			subject := Subject{Type: kind, ID: "authenticated"}
			want := verbs
			if kind == SubjectTypeSystemClass {
				want = []string{"get", "list", "get"}
				if nested {
					want = nil
				}
			}
			if got := RecipientVerbs(subject, verbs, nested); !slices.Equal(got, want) {
				t.Fatalf("kind=%s nested=%v: got %v, want %v", kind, nested, got, want)
			}
		}
	}
	if got := RecipientVerbs(Subject{Type: SubjectTypeSystemClass, ID: ClassAnonymous}, []string{"*", "update"}, false); len(got) != 0 {
		t.Fatalf("wildcard/write widened class: %v", got)
	}
	if !slices.Equal(verbs, []string{"get", "update", "*", "list", "get"}) {
		t.Fatalf("authored verbs mutated: %v", verbs)
	}
}

func TestGrantRecipients_AllSubjectsAndNestedExclusion(t *testing.T) {
	subjects := []Subject{
		{Type: SubjectTypeSystemClass, ID: ClassAnonymous},
		{Type: SubjectTypeUser, ID: "same-id"},
		{Type: SubjectTypeSystemClass, ID: ClassAuthenticated},
		{Type: SubjectTypeServiceAccount, ID: "same-id"},
		{Type: SubjectTypeGroup, ID: "same-id"},
	}
	for _, reversed := range []bool{false, true} {
		if reversed {
			slices.Reverse(subjects)
		}
		for _, nested := range []bool{false, true} {
			got := GrantRecipients(subjects, []string{"get", "update"}, nested)
			var want []GrantRecipient
			for _, subject := range subjects {
				if subject.IsSystemClass() {
					if !nested {
						want = append(want, GrantRecipient{Subject: subject, Verbs: []string{"get"}})
					}
				} else {
					want = append(want, GrantRecipient{Subject: subject, Verbs: []string{"get", "update"}})
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("reversed=%v nested=%v: got %+v, want %+v", reversed, nested, got, want)
			}
		}
	}
	if got := GrantRecipients(subjects, nil, false); len(got) != 0 {
		t.Fatalf("empty branch: %+v", got)
	}
	classes := SystemClassSubjects(subjects)
	if len(classes) != 2 || HasNonClassSubject(classes) || !HasNonClassSubject(subjects) || HasNonClassSubject(nil) {
		t.Fatalf("class/non-class partition: %+v", classes)
	}
}

func TestPublicReaderOwnerRuleFPs_OnlyTopLevelClassRead(t *testing.T) {
	selectors := []RuleSelector{
		{RuleFP: "read", Verbs: []string{"get", "update"}},
		{RuleFP: "write", Verbs: []string{"update"}},
		{RuleFP: "wildcard", Verbs: []string{"*"}},
		{RuleFP: "empty"},
		{RuleFP: "nested", Verbs: []string{"get", "list"}, Container: &ContainerSelector{OwnerFP: "read"}},
	}
	want := map[string]bool{"read": true}
	if got := PublicReaderOwnerRuleFPs(selectors); !reflect.DeepEqual(got, want) {
		t.Fatalf("owners=%v, want %v", got, want)
	}
}
