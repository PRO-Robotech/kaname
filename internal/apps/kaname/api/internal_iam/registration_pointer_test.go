// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"testing"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	"github.com/stretchr/testify/require"
)

func TestNamedPointer_ShapeDefersOnlyCatalogDecision(t *testing.T) {
	require.NoError(t, validateRegistrationShape("probemod", "probemod_box:b1", "box", "probemod_item:i1"))
	for _, tc := range []struct{ name, module, subject, relation, object string }{
		{"no-actor", "", "probemod_box:b1", "box", "probemod_item:i1"},
		{"wildcard", "probemod", "probemod_box:*", "box", "probemod_item:i1"},
		{"class", "probemod", "system_class:anonymous", "box", "probemod_item:i1"},
		{"bad-relation", "probemod", "probemod_box:b1", "b*", "probemod_item:i1"},
		{"bad-subject", "probemod", "probemod_box:b1#member", "box", "probemod_item:i1"},
		{"closed-publication", "probemod", "system_class:anonymous", "v_get", "probemod_item:i1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Error(t, validateRegistrationShape(tc.module, tc.subject, tc.relation, tc.object))
		})
	}
	for _, typ := range proxytuple.ForbiddenObjectTypes() {
		t.Run("object-"+typ, func(t *testing.T) {
			require.Error(t, validateRegistrationShape("probemod", "probemod_box:b1", "box", typ+":id"))
		})
		if typ != "project" {
			require.False(t, namedPointerSubjectType(typ), typ)
		}
	}
	require.True(t, namedPointerSubjectType("project"))
	require.True(t, namedPointerSubjectType("probemod_box"))
}

func TestNamedPointer_DoesNotExpandSharedProxyPolicy(t *testing.T) {
	require.Error(t, validateProxyTuple("probemod", "probemod_box:b1", "box", "probemod_item:i1"))
	require.False(t, proxytuple.IsProxyWritable("probemod_box:b1", "box"))
}
