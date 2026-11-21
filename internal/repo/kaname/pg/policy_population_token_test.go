// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type populationTokenRow struct {
	token policyPopulationToken
	err   error
}

func (r populationTokenRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*string) = r.token.generation
	*dest[1].(*int) = r.token.count
	*dest[2].(*string) = r.token.revision
	return nil
}

type populationTokenTx struct {
	pgx.Tx
	row    populationTokenRow
	limits []int
}

func (t *populationTokenTx) QueryRow(_ context.Context, _ string, args ...any) pgx.Row {
	t.limits = append(t.limits, args[0].(int))
	return t.row
}

// Дублёр проверяет бюджет/точность Go ABI; SQL census и held SHARE проверяются PG.
func TestPolicyPopulationTokenSharesEveryScanBudgetWithoutFloat(t *testing.T) {
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(99990, 0))
	tx := &populationTokenTx{row: populationTokenRow{token: policyPopulationToken{generation: "18446744073709551615", count: 5, revision: "922337203685477580700000"}}}
	first, err := readPolicyPopulationToken(context.Background(), tx, budget)
	require.NoError(t, err)
	second, err := readPolicyPopulationToken(context.Background(), tx, budget)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, "922337203685477580700000", second.revision)
	_, err = readPolicyPopulationToken(context.Background(), tx, budget)
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Equal(t, []int{10, 5}, tx.limits, "исчерпанная попытка не начинает новый SQL")
}
func TestPolicyPopulationTokenStopsBeforeSQLOnCancelOrReadExhaustion(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		budget := &relverdict.AdministrativeReadBudget{}
		ctx, cancel := context.WithCancel(context.Background())
		want := kaname.ErrSourceReadLimit
		if cancelled {
			cancel()
			want = context.Canceled
		} else {
			require.NoError(t, budget.Charge(0, 4096))
		}
		tx := &populationTokenTx{}
		_, err := readPolicyPopulationToken(ctx, tx, budget)
		cancel()
		require.ErrorIs(t, err, want)
		require.Empty(t, tx.limits)
	}
}
func TestPolicyPopulationTokenRejectsPartialOrMalformedCensus(t *testing.T) {
	for _, bad := range []policyPopulationToken{
		{generation: "1", count: 0, revision: "0"},
		{generation: "1", count: 100001, revision: "1"},
		{generation: "0", count: 1, revision: "0"},
		{generation: "1", count: 1, revision: "-1"},
		{generation: "1", count: 1, revision: "1.1"},
		{generation: "1", count: 1, revision: "1e20"},
		{generation: "1", count: 1, revision: "01"},
	} {
		tx := &populationTokenTx{row: populationTokenRow{token: bad}}
		got, err := readPolicyPopulationToken(context.Background(), tx, &relverdict.AdministrativeReadBudget{})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.Equal(t, policyPopulationToken{}, got)
	}
}
func TestPolicyPopulationTokenPreservesBackendError(t *testing.T) {
	backend := errors.New("population snapshot unavailable")
	tx := &populationTokenTx{row: populationTokenRow{err: backend}}
	got, err := readPolicyPopulationToken(context.Background(), tx, &relverdict.AdministrativeReadBudget{})
	require.ErrorIs(t, err, backend)
	require.Equal(t, policyPopulationToken{}, got)
}
