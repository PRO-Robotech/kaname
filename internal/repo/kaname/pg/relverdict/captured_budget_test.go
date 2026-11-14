// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package relverdict

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCapturedBudgetUnboundNativeNeverResetsAllowance(t *testing.T) {
	budget := &AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(99999, 4095))
	// Необъявленный обычный тип даёт Deny после первого списания.
	// SQL невозможен (nil TX); следующий вопрос должен исчерпать тот же бюджет,
	// независимо от отсутствия scope boundary.
	in := Query{Subject: "user:actor", ObjectType: "captured_unknown_type", ObjectID: "a", Relation: "admin", DecisionAt: time.Now()}
	_, _, err := askAdministrativeBound(context.Background(), nil, in, nil, nil, budget, false)
	require.NoError(t, err)
	require.Equal(t, 100000, budget.rows)
	require.Equal(t, 4096, budget.reads)
	for _, id := range []string{"a", "b"} {
		in.ObjectID = id
		_, _, err = askAdministrativeBound(context.Background(), nil, in, nil, nil, budget, false)
		require.ErrorIs(t, err, ErrAdministrativeSourceLimit)
	}
}
func TestCapturedBudgetBindingDoesNotInventScopeBoundary(t *testing.T) {
	a := &AdministrativeAsker{}
	shared := &AdministrativeReadBudget{}
	a.BindReadBudget(shared)
	require.Same(t, shared, a.budget)
	require.True(t, a.budgetBound)
	require.False(t, a.bound)
	require.Nil(t, a.boundary)
	a.BindReadBudget(nil)
	require.True(t, a.budgetBound)
	require.Nil(t, a.budget)
}

func TestHistoricalUnboundNativeRetainsIndependentBudget(t *testing.T) {
	in := Query{Subject: "user:actor", ObjectType: "captured_unknown_type", ObjectID: "a", Relation: "admin", DecisionAt: time.Now()}
	for i := 0; i < 2; i++ {
		verdict, _, err := askAdministrativeBound(context.Background(), nil, in, nil, nil, nil, false)
		require.NoError(t, err)
		require.Equal(t, Deny, verdict)
	}
}
