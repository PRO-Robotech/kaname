// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAuthorizationCeremonyOutcomeCollector_PrintsEveryDeclaredOutcome — все
// объявленные исходы на витрине, отсутствующий в снимке — нулём; величина
// идёт из переписи; источник и набор обязательны.
func TestAuthorizationCeremonyOutcomeCollector_PrintsEveryDeclaredOutcome(t *testing.T) {
	declared := []string{"authorize.issued", "exchange.code-replayed"}
	census := map[string]uint64{"exchange.code-replayed": 3}
	reg := NewRegistry()
	reg.NewAuthorizationCeremonyOutcomeCollector(declared, func() map[string]uint64 { return census })

	for _, o := range declared {
		v, present := labelledCounter(t, reg, AuthorizationCeremonyOutcomesMetric, map[string]string{"outcome": o})
		require.Truef(t, present, "исход %q объявлен и на витрину не вышел", o)
		require.Equal(t, float64(census[o]), v)
	}
	census["authorize.issued"] = 7
	v, _ := labelledCounter(t, reg, AuthorizationCeremonyOutcomesMetric, map[string]string{"outcome": "authorize.issued"})
	require.Equal(t, 7.0, v, "величина не двигается вместе с переписью")

	require.Panics(t, func() { NewRegistry().NewAuthorizationCeremonyOutcomeCollector(declared, nil) })
	require.Panics(t, func() {
		NewRegistry().NewAuthorizationCeremonyOutcomeCollector(nil, func() map[string]uint64 { return nil })
	})
}
