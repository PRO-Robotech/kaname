// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/stretchr/testify/require"
)

func TestCompileMaterializedTupleRetainsExactObjectAlongDerivedPaths(t *testing.T) {
	b := bundleCanon(t)
	group := domain.Subject{Type: domain.SubjectTypeGroup, ID: "team"}
	object := domain.ResourceRef{Type: "iam.account", ID: "acc-one"}
	tuple := domain.MembershipTuple{User: "group:team#member", Relation: "admin", Object: "account:acc-one"}
	s := complete(t, b.CompileMaterializedTuple("binding", object, group, tuple))
	require.Equal(t, b.Identity(), s.Identity())
	var onProject bool
	for _, e := range s.Effects() {
		require.Len(t, e.Constraints, 1)
		c := e.Constraints[0]
		require.Nil(t, c.Within)
		require.Equal(t, "account", c.Type)
		require.Equal(t, grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{"acc-one"}}, c.Region.Objects)
		if e.Type == "project" && e.Action == (grantcoverage.Action{Kind: grantcoverage.Relation, Name: "admin"}) {
			require.Equal(t, []authzmodel.EffectHop{{From: "project", Pointer: "account", To: "account"}}, c.Path)
			onProject = true
		}
	}
	require.True(t, onProject)
	actor := Direct{SourceID: "direct", ObjectType: "account", ObjectID: "acc-one", Relation: "admin", Recipient: domain.Subject{Type: domain.SubjectTypeUser, ID: "actor"}}
	proves(t, complete(t, b.CompileDirect(actor)), s, true)
	actor.ObjectID = "acc-two"
	proves(t, complete(t, b.CompileDirect(actor)), s, false)
}

func TestCompileMaterializedTupleChecksCatalogRecipientAndDeclaration(t *testing.T) {
	rows := bundleRows()
	rows.Live.Modules = append(rows.Live.Modules, "compute")
	rows.Live.Resources = append(rows.Live.Resources, catalog.ResourceRow{Module: "compute", Resource: "instance", ObjectType: "compute_instance"},
		catalog.ResourceRow{Module: "iam", Resource: "internal", ObjectType: "iam_grant_role"})
	b, err := NewBundle(t.Context(), authzmodel.DSL, rows, ProjectorVersion)
	require.NoError(t, err)
	user := domain.Subject{Type: domain.SubjectTypeUser, ID: "same"}
	sa := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "same"}
	group := domain.Subject{Type: domain.SubjectTypeGroup, ID: "same"}
	object := domain.ResourceRef{Type: "compute.instance", ID: "inst-one"}
	tuple := domain.MembershipTuple{Object: "compute_instance:inst-one", Relation: "ssh", User: "service_account:same"}
	complete(t, b.CompileMaterializedTuple("binding", object, sa, tuple))
	for _, tc := range []struct {
		name              string
		resource          domain.ResourceRef
		subject           domain.Subject
		user, object, rel string
	}{
		{"condition required", object, user, "user:same", tuple.Object, "ssh"},
		{"computed branch", object, sa, tuple.User, tuple.Object, "super_admin"},
		{"wrong subject type", object, user, tuple.User, tuple.Object, "viewer"},
		{"group without userset", object, group, "group:same", tuple.Object, "viewer"},
		{"wrong group userset", object, group, "group:same#owner", tuple.Object, "viewer"},
		{"wildcard subject", object, domain.Subject{Type: domain.SubjectTypeUser, ID: "*"}, "user:*", tuple.Object, "viewer"},
		{"injected userset", object, domain.Subject{Type: domain.SubjectTypeUser, ID: "same#member"}, "user:same#member", tuple.Object, "viewer"},
		{"unknown catalog type", domain.ResourceRef{Type: "other.instance", ID: object.ID}, sa, tuple.User, tuple.Object, "viewer"},
		{"other model type", object, sa, tuple.User, "account:inst-one", "viewer"},
		{"other object", object, sa, tuple.User, "compute_instance:inst-two", "viewer"},
		{"wildcard object", domain.ResourceRef{Type: object.Type, ID: "*"}, sa, tuple.User, "compute_instance:*", "viewer"},
		{"oversized object", domain.ResourceRef{Type: object.Type, ID: strings.Repeat("x", grantcoverage.MaxStringBytes+1)}, sa, tuple.User, tuple.Object, "viewer"},
		{"internal capability", domain.ResourceRef{Type: "iam.internal", ID: "one"}, user, "user:same", "iam_grant_role:one", "bind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := b.CompileMaterializedTuple("binding", tc.resource, tc.subject, domain.MembershipTuple{User: tc.user, Object: tc.object, Relation: tc.rel})
			require.False(t, s.Complete())
			require.NotEmpty(t, s.Obligations())
			require.Empty(t, s.Effects())
		})
	}
	require.False(t, b.CompileMaterializedTuple("", object, sa, tuple).Complete())
	require.False(t, (*Bundle)(nil).CompileMaterializedTuple("binding", object, sa, tuple).Complete())
}
