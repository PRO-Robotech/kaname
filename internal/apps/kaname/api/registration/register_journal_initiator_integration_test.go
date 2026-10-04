// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration_test

// register_journal_initiator_integration_test.go — регистрация пишет
// ресурсный журнал службы доступа с инициатором полосы регистрации (NTF-3,
// Р2; сценарий NTF3-63): вызывающий не удостоверен, и изменение начинает
// компонент службы.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegisterIntegration_JournalRowsCarryTheRegistrationLaneInitiator(t *testing.T) {
	h := newHarness(t)
	email := freshEmail("journal")
	out, err := h.register(t, h.useCase(t, h.store), email)
	require.NoError(t, err)

	// Каждая строка журнала, которую записала транзакция регистрации, — о
	// человеке и его аккаунте — несёт одного инициатора.
	rows, err := h.pool.Query(h.ctx, `
		SELECT resource_kind, initiator FROM kaname.resource_journal
		 WHERE resource_id = $1
		    OR resource_id IN (SELECT id FROM kaname.accounts WHERE owner_user_id = $1)`,
		string(out.View.User.ID))
	require.NoError(t, err)
	defer rows.Close()
	n := 0
	for rows.Next() {
		var kind, initiator string
		require.NoError(t, rows.Scan(&kind, &initiator))
		require.Equal(t, "system:kaname-registration", initiator, "строка журнала вида %s", kind)
		n++
	}
	require.NoError(t, rows.Err())
	require.Positive(t, n, "фикстура: регистрация не записала журнал о человеке — судить нечего")
}
