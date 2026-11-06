// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package clientassertion_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestRegisteredClientResolutionPreservesFailureClass(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		outcome clientassertion.Outcome
	}{
		{"unknown", domain.ErrAssertionClientUnknown, clientassertion.OutcomeClientUnknown},
		{"backend", errors.New("backend unavailable"), clientassertion.OutcomeRegistryUnavailable},
		{"cancelled", context.Canceled, clientassertion.OutcomeRegistryUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, outcome, err := clientassertion.ResolveRegisteredClient(context.Background(), stubRegistry{err: tc.err}, testClientID)
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.outcome, outcome)
		})
	}
	row := domain.AssertionClient{OwnerID: testOwnerID}
	got, outcome, err := clientassertion.ResolveRegisteredClient(context.Background(), stubRegistry{rows: map[string]domain.AssertionClient{testClientID: row}}, testClientID)
	require.NoError(t, err)
	require.Equal(t, row, got)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
}
