// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func registrationLegacyFacts(t *testing.T, declared bool) *catalog.Facts {
	t.Helper()
	child := catalog.ResourceRow{Module: "probemod", Resource: "items", ObjectType: "probemod_item", ParentNames: []string{"parent"}, ParentTypes: []string{"probemod_box"}}
	if declared {
		child.ChildRegistration = &catalog.ChildRegistrationRule{Verb: "registerChild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60}
	}
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"probemod"},
		Resources: []catalog.ResourceRow{{Module: "probemod", Resource: "boxes", ObjectType: "probemod_box"}, child},
		Verbs: []catalog.VerbRow{
			{Module: "probemod", Resource: "boxes", Verb: "get", PerObject: true},
			{Module: "probemod", Resource: "items", Verb: "get", PerObject: true},
			{Module: "probemod", Resource: "items", Verb: "registerChild", ContainerParent: "probemod_box", ContainerRelation: "child_registrar"},
		},
	}})
	require.NoError(t, err)
	return facts
}

func registrationLegacyStore() *fakeStore {
	rules := domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get"},
		Children: []domain.Rule{{Resources: []string{"items"}, Verbs: []string{"registerChild"}}}}}
	f := ndStore("user", "human-a", rules, ndBoxTarget("b1"))
	delete(f.mirror, "probemod.items")
	delete(f.mirror, "probemod.tags")
	return f
}

func registrationLegacyMembers(all []DesiredMember) []DesiredMember {
	var result []DesiredMember
	for _, member := range all {
		if member.Derivation == "child_registration" {
			result = append(result, member)
		}
	}
	return result
}

type registrationLegacyProbe struct {
	ReconcileStore
	ids         [][]string
	descendants int
	labels      int
}

func (p *registrationLegacyProbe) MatchByIDs(ctx context.Context, types, ids []string) ([]domain.MirrorObject, error) {
	p.ids = append(p.ids, append([]string(nil), ids...))
	return p.ReconcileStore.MatchByIDs(ctx, types, ids)
}

func (p *registrationLegacyProbe) MatchDescendants(ctx context.Context, types []string, typ string, ids []string, protected bool, containerAccessLabels map[string]string) ([]domain.MirrorObject, error) {
	p.descendants++
	return p.ReconcileStore.MatchDescendants(ctx, types, typ, ids, protected, containerAccessLabels)
}

func (p *registrationLegacyProbe) MatchSelector(ctx context.Context, types []string, labels map[string]string) ([]domain.MirrorObject, error) {
	p.labels++
	return p.ReconcileStore.MatchSelector(ctx, types, labels)
}

func TestChildRegistrationLegacyFullMatchesObjectCompilerWithoutChildren(t *testing.T) {
	facts := registrationLegacyFacts(t, true)
	f := registrationLegacyStore()
	probe := &registrationLegacyProbe{ReconcileStore: f}
	r := New(fakeRunner{s: probe}, nil, catalog.Fixed{F: facts})
	bs, _, err := f.LoadBinding(context.Background(), "binding")
	require.NoError(t, err)
	full, err := r.desiredRuleMembers(context.Background(), probe, bs)
	require.NoError(t, err)
	parent := f.mirror["probemod.boxes"][0]
	object, err := desiredMembersForObject(facts, bs, parent, nil)
	require.NoError(t, err)
	registration := registrationLegacyMembers(full)
	require.Equal(t, registrationLegacyMembers(object), registration)
	require.Len(t, registration, 1)
	require.Equal(t, bs.Selectors[1].RuleFP, registration[0].RuleFP)
	require.Equal(t, []domain.MembershipTuple{{User: "user:human-a", Relation: "child_registrar", Object: "probemod_box:b1"}}, registration[0].Tuples)
	require.Zero(t, probe.descendants)
	require.Zero(t, f.matchAllCalls)
	require.Contains(t, f.mirrorLocks, MemberCoord{ObjectType: "probemod.boxes", ObjectID: "b1"})
	for _, ids := range probe.ids {
		require.Equal(t, []string{"b1"}, ids)
	}
	// Registration helper must not duplicate the top-level ordinary grant.
	getCount := 0
	for _, member := range full {
		for _, tuple := range member.Tuples {
			if tuple.Relation == "v_get" && tuple.Object == "probemod_box:b1" {
				getCount++
			}
		}
	}
	require.Equal(t, 1, getCount)
}

func TestChildRegistrationLegacyParentLookupRespectsTargetLabelsAndLiveness(t *testing.T) {
	for _, scenario := range []string{"labels", "other-label", "outside", "vanished", "service-account", "no-declaration"} {
		t.Run(scenario, func(t *testing.T) {
			f := registrationLegacyStore()
			facts := registrationLegacyFacts(t, scenario != "no-declaration")
			bs, _, err := f.LoadBinding(context.Background(), "binding")
			require.NoError(t, err)
			sel := bs.Selectors[1]
			sel.Container.Arm = domain.ArmLabels
			sel.Container.MatchLabels = map[string]string{"team": "a"}
			switch scenario {
			case "other-label":
				sel.Container.MatchLabels["team"] = "missing"
			case "outside":
				f.mirror["probemod.boxes"][0].ParentProjectID = "other-project"
			case "vanished":
				f.vanished = map[MemberCoord]bool{{ObjectType: "probemod.boxes", ObjectID: "b1"}: true}
			case "service-account":
				bs.Subjects = []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "human-a"}}
			}
			probe := &registrationLegacyProbe{ReconcileStore: f}
			r := New(fakeRunner{s: probe}, nil, catalog.Fixed{F: facts})
			members, err := r.childRegistrationParents(context.Background(), probe, facts, bs, sel)
			require.NoError(t, err)
			require.Equal(t, scenario == "labels", len(members) == 1)
			require.Zero(t, probe.labels, "finite parent target must use ID lookup, not global label search")
			require.Zero(t, f.matchAllCalls)
			require.Zero(t, probe.descendants)
		})
	}
}

func TestChildRegistrationLegacyObjectEventCreatesParentGrant(t *testing.T) {
	for _, forward := range []bool{false, true} {
		f := registrationLegacyStore()
		f.selectorBindings = []domain.AccessBindingID{"binding"}
		r := New(fakeRunner{s: f}, nil, catalog.Fixed{F: registrationLegacyFacts(t, true)})
		var err error
		if forward {
			err = r.ReconcileObjectForward(context.Background(), "probemod.boxes", "b1")
		} else {
			err = r.ReconcileObject(context.Background(), "probemod.boxes", "b1")
		}
		require.NoError(t, err)
		require.Contains(t, allWrites(f), domain.MembershipTuple{User: "user:human-a", Relation: "child_registrar", Object: "probemod_box:b1"})
	}
}

func TestChildRegistrationLegacyObjectEventRemovesOrReplacesSavedParentGrant(t *testing.T) {
	for _, scenario := range []string{"removed-parent", "moved-parent", "removed-rule", "removed-declaration", "replace-target"} {
		t.Run(scenario, func(t *testing.T) {
			f := registrationLegacyStore()
			old := domain.MembershipTuple{User: "user:human-a", Relation: "child_registrar", Object: "probemod_box:b1"}
			f.current = []domain.TargetMember{{BindingID: "binding", RuleFP: f.selectors[1].RuleFP, ObjectType: "probemod.boxes", ObjectID: "b1", VerificationStatus: domain.VerificationActive}}
			f.ledger = []LedgerRow{{Member: MemberCoord{ObjectType: "probemod.boxes", ObjectID: "b1"}, Tuple: old}}
			f.bindingsForObject = []domain.AccessBindingID{"binding"}
			switch scenario {
			case "removed-parent":
				f.mirror["probemod.boxes"] = f.mirror["probemod.boxes"][1:]
			case "moved-parent":
				f.mirror["probemod.boxes"][0].ParentProjectID = "other-project"
			case "removed-rule":
				f.selectors = f.selectors[:1]
			case "replace-target":
				f.target = ndBoxTarget("b2")
			}
			r := New(fakeRunner{s: f}, nil, catalog.Fixed{F: registrationLegacyFacts(t, scenario != "removed-declaration")})
			require.NoError(t, r.ReconcileObject(context.Background(), "probemod.boxes", "b1"))
			var deleted []domain.MembershipTuple
			for _, batch := range f.tdeletes {
				deleted = append(deleted, batch...)
			}
			require.Contains(t, deleted, old)
			require.NotContains(t, allWrites(f), old)
			if scenario == "replace-target" {
				require.Contains(t, allWrites(f), domain.MembershipTuple{User: "user:human-a", Relation: "child_registrar", Object: "probemod_box:b2"})
			}
		})
	}
}

func TestChildRegistrationLegacyMixedRuleRetainsOrdinaryChildRights(t *testing.T) {
	f := registrationLegacyStore()
	f.selectors[1].Verbs = []string{"registerChild", "get"}
	f.mirror["probemod.items"] = []domain.MirrorObject{ndObj("probemod.items", "i1", nil)}
	probe := &registrationLegacyProbe{ReconcileStore: f}
	facts := registrationLegacyFacts(t, true)
	r := New(fakeRunner{s: probe}, nil, catalog.Fixed{F: facts})
	bs, _, err := f.LoadBinding(context.Background(), "binding")
	require.NoError(t, err)
	members, err := r.desiredRuleMembers(context.Background(), probe, bs)
	require.NoError(t, err)
	require.Len(t, registrationLegacyMembers(members), 1)
	require.Equal(t, 1, probe.descendants)
	var tuples []domain.MembershipTuple
	for _, member := range members {
		tuples = append(tuples, member.Tuples...)
	}
	require.Contains(t, tuples, domain.MembershipTuple{User: "user:human-a", Relation: "v_get", Object: "probemod_item:i1"})
	require.Contains(t, tuples, domain.MembershipTuple{User: "user:human-a", Relation: "child_registrar", Object: "probemod_box:b1"})
	require.NotContains(t, tuples, domain.MembershipTuple{User: "user:human-a", Relation: "child_registrar", Object: "probemod_item:i1"})
}
