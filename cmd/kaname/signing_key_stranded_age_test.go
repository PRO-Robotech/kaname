// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// signing_key_stranded_age_test.go — возраст застревания ключа согласован с
// пределами путей передачи и с интервалом прохода (#314).
//
// Сметатель выводит опубликованный ключ старше signingKeyStrandedAfter как
// застрявший. Это верно, только пока ни одна передача подписи не длится
// дольше предела ключницы, а предел не короче предела ни одного вызывающего; и
// «следующий проход доделывает прерванный» верно, только пока возраст не
// длиннее интервала прохода. Сквозь поверхность то же свойство судит
// TestSigningKeyMaintenancePass_TheNextPassRetiresAKeyStrandedBeforeItsHandOver;
// здесь — предпосылка, проверяемая и в прогоне без базы.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigningKeyStrandedAge_TheNextPassRetiresWhatAnInterruptedPassLeft(t *testing.T) {
	t.Logf("предел передачи %s · проход %s · команда %s · возраст застревания %s · интервал прохода %s",
		signingKeyHandoverLimit, signingKeyPassTimeout, signingKeyCommandTimeout,
		signingKeyStrandedAfter, signingKeySweepInterval)
	require.GreaterOrEqual(t, signingKeyHandoverLimit, signingKeyPassTimeout,
		"предел ключницы обрывал бы передачу прохода раньше предела самого прохода")
	require.GreaterOrEqual(t, signingKeyHandoverLimit, signingKeyCommandTimeout,
		"предел ключницы обрывал бы передачу команды раньше предела самой команды")
	require.Greater(t, signingKeyStrandedAfter, signingKeyHandoverLimit,
		"сметатель выводил бы ключ, чья передача ещё идёт")
	require.LessOrEqual(t, signingKeyStrandedAfter, signingKeySweepInterval,
		"ключ, оставленный прерванным проходом, не выводил бы следующий проход")
}
