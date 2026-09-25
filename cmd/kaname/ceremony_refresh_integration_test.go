// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_refresh_integration_test.go — группа G (обновляющее удостоверение
// с ротацией) и её инвариант хранилища приёмки LINE-A-1: 20, 21, 28.
//
// Мир, ступени пробы и слова исхода — `ceremony_world_integration_test.go`.
package main

import (
	"net/http"
	"net/url"
	"testing"
)

// rotate — успешная ротация: 200 и новая пара, отличная от предъявленной.
func (w *ceremonyWorld) rotate(what string, prev tokenResponse) tokenResponse {
	w.t.Helper()
	rec := w.refresh(w.ic1, prev.RefreshToken)
	if rec.Code != http.StatusOK {
		w.t.Fatalf("%s: %s: ротация ответила %d, ожидалось 200; тело %q", w.id, what, rec.Code, rec.Body.String())
	}
	requireNoStore(w.t, w.id, what, rec)
	next := decodeToken(w.t, w.id, rec)
	if next.AccessToken == "" || next.RefreshToken == "" {
		w.t.Fatalf("%s: %s: ротация не выдала новой пары: %q", w.id, what, rec.Body.String())
	}
	if next.RefreshToken == prev.RefreshToken || next.AccessToken == prev.AccessToken {
		w.t.Fatalf("%s: %s: ротация вернула прежнее удостоверение", w.id, what)
	}
	w.requireSessionFacts(what, w.bearerClaims(next.AccessToken))
	return next
}

// firstPair — обмен кода, выдавший и предъявитель, и обновляющее удостоверение.
func (w *ceremonyWorld) firstPair() tokenResponse {
	w.t.Helper()
	tr := w.redeem(w.issueCode(w.ic1, lineA1R))
	if tr.RefreshToken == "" {
		w.t.Fatalf("%s: обмен кода не выдал refresh_token (Р8: выдаётся вместе с предъявителем доступа)", w.id)
	}
	return tr
}

// TestLINEA1_20_RefreshRotatesAlongTheChain — LINE-A-1-20: rt-1 → 200 и новая
// пара (rt-2); близнец — rt-2 ротируется дальше (цепочка продолжается).
func TestLINEA1_20_RefreshRotatesAlongTheChain(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-20", "1")
	w.requireGrant(grantRefreshToken)
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	rt1 := w.firstPair()
	rt2 := w.rotate("rt-1 → rt-2", rt1)
	w.rotate("близнец: rt-2 → rt-3", rt2)
}

// TestLINEA1_21_RotatedRefreshReplayRevokesTheFamily — LINE-A-1-21: повтор уже
// ротированного rt-1 → invalid_grant, и отзывается всё семейство: rt-2 больше
// не ротируется, предъявители семейства отвергаются на предъявлении.
func TestLINEA1_21_RotatedRefreshReplayRevokesTheFamily(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-21", "1")
	w.requireGrant(grantRefreshToken)
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	rt1 := w.firstPair()
	rt2 := w.rotate("rt-1 → rt-2", rt1)
	for _, a := range []string{rt1.AccessToken, rt2.AccessToken} {
		if refused, why := w.presentation(a); refused {
			t.Fatalf("%s: предъявитель семейства отвергнут ещё до повтора: %s", w.id, why)
		}
	}

	requireInvalidGrant(t, w.id, "повтор ротированного rt-1", w.refresh(w.ic1, rt1.RefreshToken))
	requireInvalidGrant(t, w.id, "текущий rt-2 после отзыва семейства", w.refresh(w.ic1, rt2.RefreshToken))
	for name, a := range map[string]string{"предъявитель обмена кода": rt1.AccessToken, "предъявитель ротации": rt2.AccessToken} {
		if refused, _ := w.presentation(a); !refused {
			t.Errorf("%s: %s принимается на предъявлении после отзыва семейства — отзыв без читателя на пути запроса", w.id, name)
		}
	}
}

// TestLINEA1_28_ConcurrentRefreshHasOneRotationAndTheRestIsReplay —
// LINE-A-1-28: одновременные предъявления одного rt-1 → ровно одно ротирует,
// прочие классифицируются как повтор, семейство отзывается (преемник
// победителя больше не действует). Близнец — одновременные предъявления
// РАЗНЫХ актуальных удостоверений разных авторизаций проходят все.
func TestLINEA1_28_ConcurrentRefreshHasOneRotationAndTheRestIsReplay(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-28", "1")
	w.requireGrant(grantRefreshToken)
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	a, b := w.firstPair(), w.firstPair()
	distinct := []url.Values{
		{"grant_type": {grantRefreshToken}, "refresh_token": {a.RefreshToken}, "client_id": {string(w.ic1.rec.ID)}},
		{"grant_type": {grantRefreshToken}, "refresh_token": {b.RefreshToken}, "client_id": {string(w.ic1.rec.ID)}},
	}
	for i, rec := range w.raceExchange(w.ic1, distinct) {
		if rec.Code != http.StatusOK {
			t.Errorf("%s: близнец: разное актуальное удостоверение %d ответило %d; тело %q", w.id, i, rec.Code, rec.Body.String())
		}
	}

	rt1 := w.firstPair()
	same := make([]url.Values, 8)
	for i := range same {
		same[i] = url.Values{"grant_type": {grantRefreshToken}, "refresh_token": {rt1.RefreshToken}, "client_id": {string(w.ic1.rec.ID)}}
	}
	recs := w.raceExchange(w.ic1, same)
	requireExactlyOneWinner(t, w.id, "одно удостоверение", recs)
	for _, rec := range recs {
		if rec.Code != http.StatusOK {
			continue
		}
		winner := decodeToken(t, w.id, rec)
		requireInvalidGrant(t, w.id, "преемник победителя после повтора", w.refresh(w.ic1, winner.RefreshToken))
		if refused, _ := w.presentation(winner.AccessToken); !refused {
			t.Errorf("%s: предъявитель победителя принимается после отзыва семейства", w.id)
		}
	}
}
