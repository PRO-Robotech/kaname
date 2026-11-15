// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestFullWriterContractMetadataChecksAreServiceProduced(t *testing.T) {
	for table, checks := range map[string][]string{
		"authority_producer_acl_restore_v2": {"authority_producer_acl_restore_v2_object_kind_check"},
		"authority_writer_contract":         {"authority_writer_contract_singleton_check", "authority_writer_contract_required_contract_check", "authority_writer_contract_staged_contract_check"},
	} {
		for _, check := range checks {
			require.Equal(t, checkLaneService, checkValueLaneOf(table, check), table+"."+check)
		}
	}
}
func TestPolicyScanSharedNativeExhaustionDoesNotInventPhysicalOverflow(t *testing.T) {
	for _, consumed := range []int{0, policyDiscoveryRows - 1} {
		p := scanPlan()
		p.rows = consumed
		p.nativeBudget = &relverdict.AdministrativeReadBudget{}
		require.NoError(t, p.nativeBudget.Charge(policyDiscoveryRows, 0))
		tx := &policyScanTx{remaining: 1}
		err := p.scan(context.Background(), tx, "source")
		require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
		require.False(t, errors.Is(err, errPolicyDiscoveryBudget), "native-only exhaustion is a different boundary")
		require.Equal(t, 1, tx.pages)
		require.Equal(t, 1, tx.returned)
		require.Equal(t, consumed, p.rows)
	}
}
