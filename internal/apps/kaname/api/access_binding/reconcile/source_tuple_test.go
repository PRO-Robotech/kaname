// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

func TestProducesObjectTupleUsesActualScopeProducerAndTypedRecipient(t *testing.T) {
	facts := catalogfixture.Facts()
	bs := BindingScope{Scope: domain.ScopeAnchor{Type: "account", ID: "acc_source"}, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "same"}}, ScopeSelfVerbs: []string{"*"}}
	object := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "acc_source", ParentAccountIDs: []string{"acc_source"}}
	tuple := domain.MembershipTuple{User: "user:same", Relation: "admin", Object: "account:acc_source"}
	found, err := ProducesObjectTuple(facts, bs, object, nil, tuple)
	require.NoError(t, err)
	if !found {
		t.Fatal("scope-self producer lost admin")
	}
	tuple.User = "service_account:same"
	found, err = ProducesObjectTuple(facts, bs, object, nil, tuple)
	require.NoError(t, err)
	if found {
		t.Fatal("typed recipient collision")
	}
	tuple.User = "user:same"
	object.ParentAccountIDs = []string{"acc_other"}
	found, err = ProducesObjectTuple(facts, bs, object, nil, tuple)
	require.NoError(t, err)
	if found {
		t.Fatal("foreign containment accepted")
	}
	object.ParentAccountIDs = []string{"acc_source"}
	bs.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.account", ID: "acc_other"}}}
	found, err = ProducesObjectTuple(facts, bs, object, nil, tuple)
	require.NoError(t, err)
	if found {
		t.Fatal("per-object target restored scope-self authority")
	}
}
