// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_cutoff_envelope_test.go — УНИТАРНАЯ ПОЛОВИНА KN-OVL-02 (задача
// kaname#385; приёмка «вход, встретивший принудительный выход, не выдаёт
// сессии, которую отсечка уже накрыла», §4 KN-OVL-02, последнее «И»): отказ по
// отсечке уходит не раньше потолка огибающей, как всякий исход после ворот
// частоты (§0.8, Р3). Интеграционные половины сценария — в
// `internal/handler/loginlanehttp/login_overlap_integration_test.go`.
//
// Хранилище-подделка отвечает на захват строки личности отсечкой, положенной
// ЕЁ ЖЕ дверью записи отсечки (`fakeWriter.UpsertCutoff`) моментом не раньше
// m; потолок огибающей больше нуля. Положительный близнец — `TestLogin_F3_31_…`:
// там те же восемь исходов после ворот ждут того же потолка.
package humansession_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestLogin_KN_OVL_02_RefusalByTheCutoffHoldsUntilTheFloor — вход, чей момент
// не позже стоящей отсечки, отвечает тем же одним отказом, и отказ уходит не
// раньше потолка огибающей.
func TestLogin_KN_OVL_02_RefusalByTheCutoffHoldsUntilTheFloor(t *testing.T) {
	const floor = 40 * time.Millisecond
	h := newHarness(t, nil)
	h.envelope.floor = floor
	p := h.person(t, "usr-ovl-02", "ovl02@example.invalid", "correct horse battery", true)

	// Дано: отсечка P моментом m (часы полосы — `h.clock`), положенная дверью
	// записи отсечки подделки: m ≤ T, вход накрыт.
	ctx := context.Background()
	w, err := h.store.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: p.ID, RevokeBefore: h.clock, Reason: domain.RevokeReasonAdminForceLogout,
	}, ""))
	require.NoError(t, w.Commit(ctx))
	cells := h.obs.login[humansession.LoginOutcome("before-cutoff")]

	elapsed, err := timed(t, h, "ovl02@example.invalid", "correct horse battery", "203.0.113.9")

	assert.ErrorIs(t, err, humansession.ErrAuthenticationFailed,
		"вход с моментом %s при отсечке %s обязан отказать тем же одним отказом; ответ — %v",
		h.clock.Format(time.RFC3339Nano), h.clock.Format(time.RFC3339Nano), err)
	assert.GreaterOrEqual(t, elapsed, floor, "отказ по отсечке ушёл за %s — раньше потолка огибающей %s", elapsed, floor)
	assert.Equal(t, cells+1, h.obs.login[humansession.LoginOutcome("before-cutoff")], "клетка `before-cutoff` выросла на один")
}
