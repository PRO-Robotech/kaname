// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// TestSharingCapacity_OneMemoryBudgetTwoObservers — проверяющий секрета
// клиента (LINE-A-1) делит ЁМКОСТЬ с проверяющим пароля: занятое одним место
// недоступно другому. Исходы — каждому своему приёмнику. Положительный
// контроль — после освобождения второй проверяет и сообщает своему приёмнику.
func TestSharingCapacity_OneMemoryBudgetTwoObservers(t *testing.T) {
	t.Parallel()

	humanObs, clientObs := newRecordingObserver(), newRecordingObserver()
	human := newVerifier(t, 1, humanObs)
	client, err := human.SharingCapacity(clientObs)
	require.NoError(t, err)
	_, err = human.SharingCapacity(nil)
	require.Error(t, err, "проверяющий без приёмника исходов молчит обо всех отказах разом")

	stored := verifierOf(t, bcryptValue(t, rightPassword, 10))
	held, release := make(chan struct{}), make(chan struct{})
	go human.WithCapacity(func() {
		close(held)
		<-release
	})
	<-held

	require.Equal(t, passwordverify.OutcomeCapacityExhausted, client.Verify(stored, rightPassword).Outcome,
		"место, занятое проверяющим пароля, досталось проверяющему секрета — бюджет памяти удвоен")
	close(release)
	require.Eventually(t, func() bool {
		return client.Verify(stored, rightPassword).Outcome == passwordverify.OutcomeMatched
	}, 5e9, 1e7)

	require.GreaterOrEqual(t, clientObs.count(passwordverify.OutcomeCapacityExhausted), 1)
	require.GreaterOrEqual(t, clientObs.count(passwordverify.OutcomeMatched), 1)
	require.Zero(t, humanObs.count(passwordverify.OutcomeMatched)+humanObs.count(passwordverify.OutcomeCapacityExhausted),
		"исходы секрета клиента ушли приёмнику пароля человека")
}
