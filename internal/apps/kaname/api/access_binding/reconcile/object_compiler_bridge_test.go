// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package reconcile

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
	"github.com/stretchr/testify/require"
)

func desiredObjectMembersForTest(t *testing.T, cat *catalog.Facts, bs BindingScope, object domain.MirrorObject, ancestors []domain.MirrorObject) []DesiredMember {
	t.Helper()
	desired, err := desiredMembersForObject(cat, bs, object, ancestors)
	require.NoError(t, err)
	return desired
}
func TestObjectProducerPropagatesInvalidSnapshot(t *testing.T) {
	bs := sc65Scope("user", "usr_source", nil)
	_, err := desiredMembersForObject(nil, bs, sc65BoxObject(), nil)
	require.ErrorIs(t, err, resourceeffect.ErrInvalidSnapshot)
	found, err := ProducesObjectTuple(nil, bs, sc65BoxObject(), nil, domain.MembershipTuple{})
	require.False(t, found)
	require.ErrorIs(t, err, resourceeffect.ErrInvalidSnapshot)
}
