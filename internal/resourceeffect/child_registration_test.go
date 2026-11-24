// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resourceeffect_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationEffectSelectsParentBeforeAnyChildren(t *testing.T) {
	rows := catalog.Rows{
		Modules: []string{"probe"},
		Resources: []catalog.ResourceRow{
			{Module: "probe", Resource: "boxes", ObjectType: "odd_box"},
			{
				Module: "probe", Resource: "items", ObjectType: "odd_item",
				ParentTypes: []string{"odd_box"}, ParentNames: []string{"parent"},
				ChildRegistration: &catalog.ChildRegistrationRule{
					Verb: "registerchild", ParentSegments: 1, MaxChildren: 8, MaxCreates: 2, WindowSeconds: 60,
				},
			},
		},
		Verbs: []catalog.VerbRow{
			{Module: "probe", Resource: "items", Verb: "registerchild", ContainerParent: "odd_box", ContainerRelation: "child_registrar"},
		},
	}
	facts, err := catalog.NewFacts(catalog.Halves{Live: rows})
	require.NoError(t, err)
	binding := objectBinding()
	binding.Subjects = append(binding.Subjects,
		domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa"},
		domain.Subject{Type: domain.SubjectTypeGroup, ID: "team"},
	)
	binding.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probe.boxes", ID: "one"}}}
	binding.Selectors = []domain.RuleSelector{{
		RuleFP: "registration",
		Arm:    domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"registerChild"},
		Container: &domain.ContainerSelector{
			Type: "probe.boxes", Arm: domain.ArmLabels, MatchLabels: map[string]string{"team": "red"},
		},
	}}
	parent := capturedObject("probe.boxes", "one")
	members := objectDesired(t, facts, binding, parent)
	require.Equal(t, []resourceeffect.ObjectDesiredMember{{
		Derivation: "child_registration", RuleFP: "registration", ObjectType: "probe.boxes",
		ObjectID: "one", Status: domain.VerificationActive,
		Tuples: []domain.MembershipTuple{{User: "user:u", Object: "odd_box:one", Relation: "child_registrar"}},
	}}, members)
	require.Empty(t, objectDesired(t, facts, binding, capturedObject("probe.boxes", "two")))
	require.Empty(t, objectDesired(t, facts, binding, capturedObject("probe.items", "one/existing"), parent))

	parent.Labels = map[string]string{"team": "blue"}
	require.Empty(t, objectDesired(t, facts, binding, parent))
	parent = capturedObject("probe.boxes", "one")
	parent.ParentAccountIDs = []string{"another"}
	require.Empty(t, objectDesired(t, facts, binding, parent))
	parent = capturedObject("probe.boxes", "one")

	binding.Selectors[0].Verbs = []string{"*"}
	require.Empty(t, objectDesired(t, facts, binding, parent))
	binding.Selectors[0].Verbs = []string{"registerChild"}
	binding.Selectors[0].Arm = domain.ArmNames
	binding.Selectors[0].ResourceNames = []string{"one/only"}
	require.Empty(t, objectDesired(t, facts, binding, parent))
}
