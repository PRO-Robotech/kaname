// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp_test

// address_verification_journal_initiator_integration_test.go — полоса входа
// пишет ресурсный журнал службы доступа с инициатором, который ей положен
// (NTF-3, Р2; сценарий NTF3-63):
//
//   - регистрация — вызывающий не удостоверен, изменение начинает компонент
//     полосы регистрации (`system:kaname-registration`);
//   - подтверждение адреса — изменение начинает человек, чья сессия,
//     удостоверенная носителем, предъявила код (`user:<id>`).

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoginLaneJournalRowsCarryTheirInitiator(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-30")
	s := h.register(t, freshAddress("journal"))

	initiatorOf := func(event string) []string {
		t.Helper()
		rows, err := h.pool.Query(h.ctx, `
			SELECT initiator FROM kaname.resource_journal
			 WHERE resource_kind = 'iam_user' AND resource_id = $1 AND event_type = $2
			 ORDER BY sequence_no`, string(s.user), event)
		require.NoError(t, err)
		defer rows.Close()
		var out []string
		for rows.Next() {
			var i string
			require.NoError(t, rows.Scan(&i))
			out = append(out, i)
		}
		require.NoError(t, rows.Err())
		return out
	}
	require.Equal(t, []string{"system:kaname-registration"}, initiatorOf("CREATED"),
		"строка журнала о заведении человека регистрацией")
	updatesBefore := len(initiatorOf("UPDATED"))

	k := h.latestCode(t, "journal", s.user)
	h.clock.Advance(time.Minute)
	r := h.confirm(t, s, k)
	require.Equal(t, http.StatusOK, r.status, "подтверждение адреса: %s", r.body)
	_, marked := h.markedAt(t, s.user)
	require.True(t, marked, "фикстура: отметка подтверждения не встала — судить нечего")

	updates := initiatorOf("UPDATED")
	require.Greater(t, len(updates), updatesBefore, "подтверждение не записало журнал о человеке")
	for _, i := range updates[updatesBefore:] {
		require.Equal(t, "user:"+string(s.user), i, "строка журнала о подтверждении адреса")
	}
}
