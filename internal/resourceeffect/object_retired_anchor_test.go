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

func TestObjectDesiredRetiredScopeMappingStillHasContainerEffect(t *testing.T) {
	facts, err := catalog.NewFacts(catalog.Halves{
		Live:    catalog.Rows{Modules: []string{"probe"}, Resources: []catalog.ResourceRow{{Module: "probe", Resource: "items", ObjectType: "probe_item"}}, Verbs: []catalog.VerbRow{{Module: "probe", Resource: "items", Verb: "create", ContainerParent: "account", ContainerRelation: "item_creator"}}},
		Retired: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}}},
	})
	require.NoError(t, err)
	_, live := facts.FGAObjectType("iam.account")
	require.False(t, live)
	b := resourceeffect.ObjectBinding{Scope: domain.ScopeAnchor{Type: "account", ID: "a"}, Subjects: []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "sa"}}, Policy: domain.PolicyOfRole(false, ""), Target: domain.AccessTarget{AllInScope: true}, Selectors: []domain.RuleSelector{{RuleFP: "create", Arm: domain.ArmAnchor, ObjectTypes: []string{"probe.items"}, Verbs: []string{"create"}}}}
	result, err := resourceeffect.CompileObjectDesired(facts, b, domain.MirrorObject{ObjectType: "iam.account", ObjectID: "a", ParentAccountIDs: []string{"a"}}, nil)
	require.NoError(t, err)
	require.Equal(t, []resourceeffect.ObjectDesiredMember{{Derivation: "container", RuleFP: "create", ObjectType: "iam.account", ObjectID: "a", Status: domain.VerificationActive, Tuples: []domain.MembershipTuple{{User: "service_account:sa", Relation: "item_creator", Object: "account:a"}}}}, result)
}
