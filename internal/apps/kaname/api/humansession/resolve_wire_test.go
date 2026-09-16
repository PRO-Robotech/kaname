// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestResolveHandler_F3_27_FiveCausesOneWireAnswer — половина службы Ф3-27: пять
// отвергнутых носителей — выход, смена пароля, блокировка, неизвестный,
// истёкший — получают от `Resolve` ПОБАЙТОВО один ответ на проводе (`Found:
// false`, ни одного иного поля), а причина считается только клеткой счётчика
// службы; положительный контроль — живая сессия отвечает записью.
//
// Две причины Ф1-17 — принудительный выход и восстановление — служба на
// предъявлении НЕ различает by construction: их отказ производит отсечка на
// крае (Ф3-25, Ф3-26 — интеграция на моменте отсечки), и здесь они не
// притворяются пятой и шестой клеткой.
func TestResolveHandler_F3_27_FiveCausesOneWireAnswer(t *testing.T) {
	h := newHarness(t, nil)
	u := h.person(t, "usr-a", "a@example.invalid", "correct horse battery", true)
	ctx := context.Background()
	handler := humansession.NewHandler(h.resolve)

	loggedOut := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	_, err := h.logout.Execute(ctx, loggedOut.Bearer)
	require.NoError(t, err)

	changed := h.mustLogin(t, "a@example.invalid", "correct horse battery") // гаснет сменой из другой
	current := h.mustLogin(t, "a@example.invalid", "correct horse battery")
	out, err := h.change.Execute(ctx, humansession.ChangePasswordInput{Bearer: current.Bearer,
		CurrentPassword: "correct horse battery", NewPassword: "a clean passphrase"})
	require.NoError(t, err)

	// Истёкшая — посевом записи со сроком в прошлом: часы пробы стоят, и прочие
	// записи от этого не стареют.
	expiredBearer, _ := domain.NewSessionBearer()
	expiredRow := domain.HumanSession{ID: "hss-expired", UserID: u.ID, AuthenticatedAt: ucBase.Add(-2 * ucTTL),
		LastPresentedAt: ucBase.Add(-2 * ucTTL), ExpiresAt: ucBase.Add(-ucTTL), AssuranceLevel: "1", PresentedMethods: []string{"password"}}
	h.store.rows[expiredRow.ID] = &fakeRow{s: expiredRow, digest: expiredBearer.Digest()}
	live := h.mustLogin(t, "a@example.invalid", "a clean passphrase")

	answer := func(b domain.SessionBearer) []byte {
		resp, err := handler.Resolve(ctx, &iamv1.ResolveHumanSessionRequest{Bearer: b.CookieValue()})
		require.NoError(t, err)
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(resp)
		require.NoError(t, err)
		return raw
	}

	refusals := map[string][]byte{
		"logout":          answer(loggedOut.Bearer),
		"password-change": answer(changed.Bearer),
		"expired":         answer(expiredBearer),
		"unknown":         answer(domain.PresentedSessionBearer("nobody-knows-this-bearer")),
	}
	u.InviteStatus = domain.InviteStatusBlocked
	h.store.users[u.ID] = u
	refusals["blocked"] = answer(out.Bearer)
	u.InviteStatus = domain.InviteStatusActive
	h.store.users[u.ID] = u

	reference := refusals["unknown"]
	for cause, raw := range refusals {
		require.Equal(t, reference, raw, "ответ на проводе по причине %q отличим от ответа «неизвестен»", cause)
	}
	require.Equal(t, 1, h.obs.noSess[humansession.NoSessionUnknown])
	require.Equal(t, 2, h.obs.noSess[humansession.NoSessionEnded], "выход и смена пароля — обе «снята»")
	require.Equal(t, 1, h.obs.noSess[humansession.NoSessionExpired])
	require.Equal(t, 1, h.obs.noSess[humansession.NoSessionBlocked])

	// Положительный контроль: живая сессия отвечает записью, и она отличима.
	alive := answer(live.Bearer)
	require.NotEqual(t, reference, alive, "живая сессия неотличима от отказа — утверждение выше вакуумно")
	resp, err := handler.Resolve(ctx, &iamv1.ResolveHumanSessionRequest{Bearer: live.Bearer.CookieValue()})
	require.NoError(t, err)
	require.True(t, resp.GetFound())
	// Состав Р1 на проводе (Ф3-09, половина службы): личность, момент
	// аутентификации в МИКРОСЕКУНДАХ (§4.1 п.19), срок, уровень, подтверждённость
	// адреса, требование смены — каждое поле, и ни одного иного.
	sess := resp.GetSession()
	require.Equal(t, string(u.ID), sess.GetUserId())
	require.Equal(t, "a@example.invalid", sess.GetEmail())
	require.Equal(t, string(u.DisplayName), sess.GetDisplayName())
	require.True(t, sess.GetAuthenticatedAt().AsTime().Equal(live.View.Session.AuthenticatedAt), "момент аутентификации — без усечения")
	require.Equal(t, live.View.Session.AuthenticatedAt.Nanosecond()/1000, sess.GetAuthenticatedAt().AsTime().Nanosecond()/1000, "микросекунды на проводе")
	require.True(t, sess.GetExpiresAt().AsTime().Equal(live.View.Session.ExpiresAt.Truncate(time.Second)), "срок — до секунды (конвенция)")
	require.Equal(t, "1", sess.GetAssuranceLevel())
	require.True(t, sess.GetEmailVerified())
	require.False(t, sess.GetPasswordChangeRequired())
}
