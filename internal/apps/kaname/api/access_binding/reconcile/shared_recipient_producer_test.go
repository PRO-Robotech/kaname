// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"reflect"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestSharedRecipientProducer_MaterializesBothEffectsWithTypedRecipients(t *testing.T) {
	cat := ndFacts(t)
	rules := ndReaderRules(nil, nil, "items")
	rules[0].Verbs = []string{"get", "list", "update"}
	bs := sc65Scope("system_class", "anonymous", rules)
	bs.Subjects = []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: "same-id"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAuthenticated},
		{Type: domain.SubjectTypeServiceAccount, ID: "same-id"},
		{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous},
		{Type: domain.SubjectTypeGroup, ID: "same-id"},
	}
	members := desiredMembersForObject(cat, bs, sc65BoxObject(), nil)
	users := func(relation string) []string {
		var out []string
		for _, m := range members {
			for _, tuple := range m.Tuples {
				if tuple.Relation == relation {
					out = append(out, tuple.User)
				}
			}
		}
		slices.Sort(out)
		return out
	}
	if got := users("v_get"); !slices.Equal(got, []string{"group:same-id#member", "service_account:same-id", "system_class:anonymous", "system_class:authenticated", "user:same-id"}) {
		t.Fatalf("all top-level recipients: %v", got)
	}
	if got := users("v_update"); !slices.Equal(got, []string{"group:same-id#member", "service_account:same-id", "user:same-id"}) {
		t.Fatalf("write reached class or lost neighbour: %v", got)
	}
	if got := users(domain.PublicReaderRelation); !slices.Equal(got, []string{"system_class:anonymous", "system_class:authenticated"}) {
		t.Fatalf("public_reader class set: %v", got)
	}
	owners := domain.PublicReaderOwnerRuleFPs(bs.Selectors)
	effect, ok := cat.PublicReaderEffect(bs.Selectors, bs.Subjects, "probemod.boxes", owners)
	if !ok {
		t.Fatal("shared effect missing")
	}
	found := false
	for _, m := range members {
		if hasRelation(m, domain.PublicReaderRelation) {
			found = true
			if m.RuleFP != effect.RuleFP || !reflect.DeepEqual(m.Tuples, effect.Tuples(sc65Box)) {
				t.Fatalf("materializer diverged from shared source: %+v / %+v", m, effect)
			}
		}
	}
	if !found {
		t.Fatal("separate public_reader member missing")
	}
	for _, sel := range bs.Selectors {
		if sel.Container != nil {
			got := selectorGrantees(bs, sel)
			want := []grantee{
				{subject: "user:same-id", verbs: []string{"get", "list"}},
				{subject: "service_account:same-id", verbs: []string{"get", "list"}},
				{subject: "group:same-id#member", verbs: []string{"get", "list"}},
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("nested class exclusion: %+v", got)
			}
		}
	}
}

func TestSharedRecipientProducer_SelectedActiveOwnRuleRequired(t *testing.T) {
	cat := ndFacts(t)
	for _, tc := range []struct {
		name       string
		status     domain.VerificationStatus
		rule       string
		writeOwner bool
		want       bool
	}{
		{name: "active-own-rule", status: domain.VerificationActive, rule: "owner", want: true},
		{name: "pending-own-rule", status: domain.VerificationPending, rule: "owner"},
		{name: "rejected-own-rule", status: domain.VerificationRejected, rule: "owner"},
		{name: "other-read-rule", status: domain.VerificationActive, rule: "other"},
		{name: "scope-member", status: domain.VerificationActive, rule: "scope_self"},
		{name: "owner-selected-only-for-user-write", status: domain.VerificationActive, rule: "owner", writeOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ownerVerbs := []string{"get", "list"}
			if tc.writeOwner {
				ownerVerbs = []string{"update"}
			}
			bs := BindingScope{
				Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "u1"}, {Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}},
				Selectors: []domain.RuleSelector{
					{RuleFP: "owner", Arm: domain.ArmAnchor, ObjectTypes: []string{"probemod.boxes"}, Verbs: ownerVerbs},
					{RuleFP: "other", Arm: domain.ArmAnchor, ObjectTypes: []string{"probemod.boxes"}, Verbs: []string{"get", "list"}},
					{RuleFP: "child", Arm: domain.ArmAnchor, ObjectTypes: []string{"probemod.items"}, Verbs: []string{"get", "list"},
						Container: &domain.ContainerSelector{OwnerFP: "owner", Type: "probemod.boxes", Arm: domain.ArmAnchor}},
				},
			}
			members := []DesiredMember{{RuleFP: tc.rule, ObjectType: "probemod.boxes", ObjectID: "b1", Status: tc.status}}
			got := withPublicReaders(cat, bs, members)
			wantLen := 1
			if tc.want {
				wantLen = 2
			}
			if len(got) != wantLen {
				t.Fatalf("members=%+v, want length %d", got, wantLen)
			}
			if tc.want {
				want := domain.MembershipTuple{User: "system_class:anonymous", Relation: domain.PublicReaderRelation, Object: "probemod_box:b1"}
				if got[1].RuleFP != "public_reader:child@system_class:anonymous" || !reflect.DeepEqual(got[1].Tuples, []domain.MembershipTuple{want}) {
					t.Fatalf("public member: %+v", got[1])
				}
			}
		})
	}
}

func TestSharedRecipientProducer_TargetStillRestrictsContainer(t *testing.T) {
	cat := ndFacts(t)
	bs := sc65Scope("system_class", "anonymous", ndReaderRules(nil, nil, "items"))
	positive := desiredMembersForObject(cat, bs, sc65BoxObject(), nil)
	found := false
	for _, m := range positive {
		found = found || hasRelation(m, domain.PublicReaderRelation)
	}
	if !found {
		t.Fatal("positive selected container missing")
	}
	other := sc65BoxObject()
	other.ObjectID = "another-box"
	for _, m := range desiredMembersForObject(cat, bs, other, nil) {
		if hasRelation(m, domain.PublicReaderRelation) {
			t.Fatalf("unselected container received public_reader: %+v", m)
		}
	}
}
