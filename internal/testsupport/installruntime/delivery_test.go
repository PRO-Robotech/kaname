// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/stretchr/testify/require"
)

// Это проверяет будущий Given исполнения, а не успех установщика. В частности,
// неверная база не должна давать ложный успех всем отрицательным близнецам исполнения.
func TestRuntimeDeliveryInputsAreLawful(t *testing.T) {
	delivery := NewRIDDeliveryFixture()
	for _, input := range [][]byte{delivery.First, delivery.Second} {
		m, err := manifest.Load(input)
		require.NoError(t, err)
		require.Len(t, m.Seed.ServiceAccounts, 1)
		require.Len(t, m.Seed.Groups, 1)
		require.Len(t, m.Seed.AccessBindings, 1)
		require.Len(t, m.Seed.Joins, 1)
		require.Len(t, m.Seed.GrantDelegations, 1)
	}
	input, err := BoundaryDelivery(16, 16)
	require.NoError(t, err)
	m, err := manifest.Load(input)
	require.NoError(t, err)
	require.Len(t, m.Roles, 17, "the legal twin must retain the seventeenth declared role")
	require.Len(t, m.Resources, 17, "the legal twin must retain the seventeenth declared target")
	require.Len(t, m.Seed.GrantDelegations[0].SubjectTypes, 4)
}
