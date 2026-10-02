// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_confirm_integration_test.go — полоса Г приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456):
// предъявление кода. Стенд — `address_verification_harness_integration_test.go`.
package loginlanehttp_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// wrongCodeLike — значение той же длины и того же алфавита, что code, но не он.
func wrongCodeLike(code string) string {
	b := []byte(strings.ReplaceAll(code, "-", ""))
	for i := range b {
		if b[i] == '7' {
			b[i] = '8'
		} else {
			b[i] = '7'
		}
	}
	return string(b[:5]) + "-" + string(b[5:])
}

const avAuthFailed = `{"code":16,"message":"authentication failed","details":[]}`

// TestEV30_TheRightCodeInTimeConfirmsTheAddress — EV-30.
func TestEV30_TheRightCodeInTimeConfirmsTheAddress(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-30")
	s := h.register(t, freshAddress("ev30"))
	k := h.latestCode(t, "EV-30", s.user)
	h.clock.Advance(time.Minute)
	presentedAt := h.clock.Now()

	r := h.confirm(t, s, k)
	require.Equal(t, http.StatusOK, r.status, "EV-30: 200: %s", r.body)
	verified, ok := sessionEmailVerified(t, r.body)
	require.True(t, ok && verified, "EV-30: session.emailVerified = true: %s", r.body)
	require.JSONEq(t, `["assuranceLevel","emailVerified","expiresAt"]`, sessionKeys(t, r.body), "EV-30: состав session")
	b2 := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, b2, "EV-30: Set-Cookie несёт новый носитель")
	require.NotEqual(t, s.bearer.Value, b2.Value, "EV-30: B2 ≠ B1")

	require.False(t, h.resolve(t, s.bearer).GetFound(), "EV-30: Resolve(B1) — found = false")
	res := h.resolve(t, b2)
	require.True(t, res.GetFound(), "EV-30: Resolve(B2) — found = true")
	require.True(t, res.GetSession().GetEmailVerified(), "EV-30: Resolve(B2) — email_verified = true")
	at, marked := h.markedAt(t, s.user)
	require.True(t, marked, "EV-30: отметка стоит")
	require.WithinDuration(t, presentedAt, at, time.Millisecond, "EV-30: отметка — момент предъявления")

	evs := h.auditEvents(t, "iam.user.email_verified", s.user)
	require.Len(t, evs, 1, "EV-30: событие iam.user.email_verified")
	require.Equal(t, string(s.user), evs[0]["user_id"])
	require.NotEmpty(t, evs[0]["session_id"])
	for k, v := range evs[0] {
		require.NotContains(t, strings.ToLower(toString(v)), strings.ToLower(s.email), "EV-30: адреса в событии нет (поле %s)", k)
	}

	after := s
	after.bearer = b2
	rp := h.post(t, after, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev30", "csrfToken": h.token(after, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusOK, rp.status, "EV-30: тем же B2 смена пароля — обычное положение без повторного входа: %s", rp.body)
}

// TestEV31_OtherSessionsOfThePersonAreEnded — EV-31.
func TestEV31_OtherSessionsOfThePersonAreEnded(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-31")
	s := h.register(t, freshAddress("ev31"))
	other := h.login(t, s)
	stranger := h.register(t, freshAddress("ev31r"))
	k := h.latestCode(t, "EV-31", s.user)

	require.Equal(t, http.StatusOK, h.confirm(t, s, k).status)
	require.False(t, h.resolve(t, other.bearer).GetFound(), "EV-31: Resolve(S′) — found = false")
	require.Equal(t, "email-verified", h.endReason(t, other.bearer), "EV-31: причина конца S′")
	require.True(t, h.resolve(t, stranger.bearer).GetFound(), "EV-31 близнец: сессия другого человека без изменений")
	require.Equal(t, "", h.endReason(t, stranger.bearer))
}

// TestEV32_AWrongCodeIsRefused — EV-32.
func TestEV32_AWrongCodeIsRefused(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-32")
	s := h.register(t, freshAddress("ev32"))
	k := h.latestCode(t, "EV-32", s.user)

	r := h.confirm(t, s, wrongCodeLike(k))
	require.Equal(t, http.StatusUnauthorized, r.status, "EV-32: 401: %s", r.body)
	require.JSONEq(t, avAuthFailed, r.body)
	require.Empty(t, r.cookies, "EV-32: без Set-Cookie")
	_, marked := h.markedAt(t, s.user)
	require.False(t, marked, "EV-32: отметки нет")
	require.True(t, h.resolve(t, s.bearer).GetFound(), "EV-32: носитель жив")
}

// TestEV33_TheCodeHasItsTerm — EV-33.
func TestEV33_TheCodeHasItsTerm(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-33")
	a := h.register(t, freshAddress("ev33a"))
	ka := h.latestCode(t, "EV-33", a.user)
	b := h.register(t, freshAddress("ev33b"))
	kb := h.latestCode(t, "EV-33", b.user)

	h.clock.Advance(avCodeTTLProfile - time.Second)
	require.Equal(t, http.StatusOK, h.confirm(t, b, kb).status, "EV-33 (б): T+30мин−1с — исход EV-30")
	h.clock.Advance(2 * time.Second)
	ra := h.confirm(t, a, ka)
	require.Equal(t, http.StatusUnauthorized, ra.status, "EV-33 (а): T+30мин+1с — отказ EV-32: %s", ra.body)
	require.JSONEq(t, avAuthFailed, ra.body)
	require.Equal(t, http.StatusUnauthorized, h.confirm(t, a, ka).status, "EV-33 (а): повтор его не оживляет")
}

// TestEV34_OnlyTheLastCodeIsAlive — EV-34.
func TestEV34_OnlyTheLastCodeIsAlive(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-34")
	s := h.register(t, freshAddress("ev34"))
	k1 := h.latestCode(t, "EV-34", s.user)
	h.clock.Advance(avIntervalProfile + time.Second)
	require.Equal(t, http.StatusOK, h.requestLetter(t, s).status)
	k2 := h.latestCode(t, "EV-34", s.user)
	require.NotEqual(t, k1, k2)

	require.Equal(t, http.StatusUnauthorized, h.confirm(t, s, k1).status, "EV-34 (а): K1 — отказ EV-32")
	require.Equal(t, http.StatusOK, h.confirm(t, s, k2).status, "EV-34 (б): K2 — исход EV-30")
}

// TestEV35_TheCodeIsSingleUse — EV-35: близнецы различаются только отметкой
// применения строки кода; адрес не меняется, других кодов нет.
func TestEV35_TheCodeIsSingleUse(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-35")
	for _, applied := range []bool{true, false} {
		s := h.register(t, freshAddress("ev35"))
		k := h.latestCode(t, "EV-35", s.user)
		if applied {
			tag, err := h.pool.Exec(h.ctx, `
				UPDATE kaname.email_verification_codes SET consumed_at = issued_at
				 WHERE user_id = $1 AND consumed_at IS NULL AND superseded_at IS NULL`, string(s.user))
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев отметки применения")
			require.EqualValues(t, 1, tag.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): живой код один")
			h.unmark(t, s.user)
		}
		r := h.confirm(t, s, k)
		if applied {
			require.Equal(t, http.StatusUnauthorized, r.status, "EV-35 (а): применённый код — отказ EV-32: %s", r.body)
			_, marked := h.markedAt(t, s.user)
			require.False(t, marked, "EV-35 (а): отметки нет")
			continue
		}
		require.Equal(t, http.StatusOK, r.status, "EV-35 (б): исход EV-30: %s", r.body)
	}
}

// TestEV36_AttemptLimitIsPerCode — EV-36.
func TestEV36_AttemptLimitIsPerCode(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-36")
	for _, wrong := range []int{avAttemptsProfile - 1, avAttemptsProfile} {
		s := h.register(t, freshAddress("ev36"))
		k := h.latestCode(t, "EV-36", s.user)
		for i := 0; i < wrong; i++ {
			require.Equal(t, http.StatusUnauthorized, h.confirm(t, s, wrongCodeLike(k)).status)
		}
		r := h.confirm(t, s, k)
		if wrong < avAttemptsProfile {
			require.Equal(t, http.StatusOK, r.status, "EV-36 (а): четыре неподошедших, затем K — 200: %s", r.body)
			continue
		}
		require.Equal(t, http.StatusUnauthorized, r.status, "EV-36 (б): шестое предъявление верным значением — отказ: %s", r.body)
		h.clock.Advance(avIntervalProfile + time.Second)
		require.Equal(t, http.StatusOK, h.requestLetter(t, s).status, "EV-36 (б): новый код")
		require.Equal(t, http.StatusOK, h.confirm(t, s, h.latestCode(t, "EV-36", s.user)).status, "EV-36 (б): новый код проходит")
	}
}

// TestEV36c_ParallelWrongPresentationsCountAtMostTheLimit — условие аудита
// поверхности: счёт попыток и сверка свёртки — один оператор. 50 параллельных
// неверных предъявлений одного кода засчитывают не больше предела, и затем
// верное значение отвергается; близнец — 4 параллельных неверных, верное
// проходит.
func TestEV36c_ParallelWrongPresentationsCountAtMostTheLimit(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-36c")
	for _, n := range []int{50, avAttemptsProfile - 1} {
		s := h.register(t, freshAddress("ev36c"))
		k := h.latestCode(t, "EV-36c", s.user)
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = h.confirm(t, s, wrongCodeLike(k))
			}()
		}
		wg.Wait()
		var attempts int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT attempts FROM kaname.email_verification_codes
			 WHERE user_id = $1 AND superseded_at IS NULL`, string(s.user)).Scan(&attempts))
		require.LessOrEqual(t, attempts, avAttemptsProfile, "EV-36c (%d параллельных): засчитано не больше предела", n)
		r := h.confirm(t, s, k)
		if n >= avAttemptsProfile {
			require.Equal(t, http.StatusUnauthorized, r.status, "EV-36c: после исчерпания верное значение отвергается")
			continue
		}
		require.Equal(t, http.StatusOK, r.status, "EV-36c близнец: верное значение проходит: %s", r.body)
	}
}

// TestEV37_AnotherPersonsCode — EV-37.
func TestEV37_AnotherPersonsCode(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-37")
	a := h.register(t, freshAddress("ev37a"))
	b := h.register(t, freshAddress("ev37b"))
	ka := h.latestCode(t, "EV-37", a.user)

	r := h.confirm(t, b, ka)
	require.Equal(t, http.StatusUnauthorized, r.status, "EV-37: код A в сессии B — отказ EV-32: %s", r.body)
	require.JSONEq(t, avAuthFailed, r.body)
	require.Equal(t, http.StatusOK, h.confirm(t, a, ka).status, "EV-37: у A код KA жив")
}

// TestEV38_TheAddressChangedAfterTheCode — EV-38.
func TestEV38_TheAddressChangedAfterTheCode(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-38")
	a := h.register(t, freshAddress("ev38a"))
	ka := h.latestCode(t, "EV-38", a.user)
	_, err := h.pool.Exec(h.ctx, `UPDATE kaname.users SET email = $2 WHERE id = $1`, string(a.user), freshAddress("ev38moved"))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев смены адреса")
	r := h.confirm(t, a, ka)
	require.Equal(t, http.StatusUnauthorized, r.status, "EV-38: код, выданный прежнему значению, — отказ: %s", r.body)
	_, marked := h.markedAt(t, a.user)
	require.False(t, marked, "EV-38: отметки нет")

	b := h.register(t, freshAddress("ev38b"))
	require.Equal(t, http.StatusOK, h.confirm(t, b, h.latestCode(t, "EV-38", b.user)).status, "EV-38 близнец: адрес не менялся")
}

// TestEV39_PresentationWithoutASession — EV-39.
func TestEV39_PresentationWithoutASession(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-39")
	s := h.register(t, freshAddress("ev39"))
	k := h.latestCode(t, "EV-39", s.user)
	noBearer := s
	noBearer.bearer = nil
	r := h.confirm(t, noBearer, k)
	require.Equal(t, http.StatusUnauthorized, r.status, "EV-39: 401: %s", r.body)
	require.JSONEq(t, avAuthFailed, r.body)
	require.Equal(t, http.StatusOK, h.confirm(t, h.login(t, s), k).status, "EV-39: код не потрачен — после входа проходит")
}

// TestEV40_PresentationByTheVerified — EV-40.
func TestEV40_PresentationByTheVerified(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-40")
	s := h.register(t, freshAddress("ev40"))
	k := h.latestCode(t, "EV-40", s.user)
	h.mark(t, s)
	at, _ := h.markedAt(t, s.user)
	h.clock.Advance(time.Minute)
	r := h.confirm(t, s, k)
	require.Equal(t, http.StatusBadRequest, r.status, "EV-40: 400: %s", r.body)
	ref := parseRefusal(t, r.body)
	require.Equal(t, 9, ref.Code)
	require.Equal(t, "EMAIL_ALREADY_VERIFIED", ref.reason())
	after, _ := h.markedAt(t, s.user)
	require.True(t, at.Equal(after), "EV-40: отметка не переписана")
}

// TestEV41_PresentationForm — EV-41.
func TestEV41_PresentationForm(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-41")
	s := h.register(t, freshAddress("ev41"))
	k := h.latestCode(t, "EV-41", s.user)

	ra := h.post(t, s, avPathConfirm, map[string]any{"code": k, "csrfToken": h.token(s, avFormRequest)})
	require.Equal(t, http.StatusForbidden, ra.status, "EV-41 (а): %s", ra.body)
	require.Equal(t, "FORM_TOKEN_REJECTED", parseRefusal(t, ra.body).reason())

	rb := h.post(t, s, avPathConfirm, map[string]any{"code": " - -  -", "csrfToken": h.token(s, avFormConfirm)})
	require.Equal(t, http.StatusBadRequest, rb.status, "EV-41 (б): %s", rb.body)
	refB := parseRefusal(t, rb.body)
	require.Equal(t, 3, refB.Code)
	require.Contains(t, refB.Message, "code: required")

	rc := h.post(t, s, avPathConfirm, map[string]any{"code": k, "email": s.email, "csrfToken": h.token(s, avFormConfirm)})
	require.Equal(t, http.StatusBadRequest, rc.status, "EV-41 (в): %s", rc.body)
	require.Contains(t, parseRefusal(t, rc.body).Message, "email: unknown field")

	var attempts int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT attempts FROM kaname.email_verification_codes
		 WHERE user_id = $1 AND superseded_at IS NULL`, string(s.user)).Scan(&attempts))
	require.Zero(t, attempts, "EV-41: ни одно не тратит попытку кода")

	lower := strings.ToLower(k[:3]) + "-" + strings.ToLower(k[3:])
	require.Equal(t, http.StatusOK, h.confirm(t, s, lower).status, "EV-41 близнец: k в нижнем регистре с дефисами проходит как K")
}

// TestEV43_ConcurrentPresentationOfOneCode — EV-43: не меньше 50 повторов,
// каждый — с новым посевом.
func TestEV43_ConcurrentPresentationOfOneCode(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-43")
	const repeats = 50
	loserOutcomes := map[string]int{}
	for i := 0; i < repeats; i++ {
		s1 := h.register(t, freshAddress("ev43"))
		s2 := h.login(t, s1)
		k := h.latestCode(t, "EV-43", s1.user)
		var (
			wg     sync.WaitGroup
			r1, r2 reply
		)
		wg.Add(2)
		go func() { defer wg.Done(); r1 = h.confirm(t, s1, k) }()
		go func() { defer wg.Done(); r2 = h.confirm(t, s2, k) }()
		wg.Wait()
		winner, loser, winnerSession, loserSession := r1, r2, s1, s2
		if r2.status == http.StatusOK {
			winner, loser, winnerSession, loserSession = r2, r1, s2, s1
		}
		require.Equal(t, http.StatusOK, winner.status, "EV-43 повтор %d: ровно один 200 (%d/%d)", i, r1.status, r2.status)
		switch {
		case loser.status == http.StatusUnauthorized:
			require.JSONEq(t, avAuthFailed, loser.body)
			loserOutcomes["401/16"]++
		case loser.status == http.StatusBadRequest && parseRefusal(t, loser.body).reason() == "EMAIL_ALREADY_VERIFIED":
			loserOutcomes["400/9 EMAIL_ALREADY_VERIFIED"]++
		default:
			t.Fatalf("EV-43 повтор %d: третий исход проигравшего: %d %s", i, loser.status, loser.body)
		}
		require.Len(t, h.auditEvents(t, "iam.user.email_verified", s1.user), 1, "EV-43: событие одно")
		live := 0
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1 AND ended_at IS NULL`,
			string(s1.user)).Scan(&live))
		require.Equal(t, 1, live, "EV-43: живая сессия человека одна")
		require.True(t, h.resolve(t, cookieNamed(winner.cookies, loginlanehttp.CookieSession)).GetFound(), "EV-43: сессия победителя с новым носителем")
		_ = winnerSession
		require.Equal(t, "email-verified", h.endReason(t, loserSession.bearer), "EV-43: сессия проигравшего снята")
		var applied int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.email_verification_codes WHERE user_id = $1 AND consumed_at IS NOT NULL`,
			string(s1.user)).Scan(&applied))
		require.Equal(t, 1, applied, "EV-43: строка K применена один раз")
	}
	t.Logf("EV-43: повторов %d; исходы проигравшего: %v", repeats, loserOutcomes)

	// Близнец — последовательное предъявление: второе детерминированно 401.
	s1 := h.register(t, freshAddress("ev43seq"))
	s2 := h.login(t, s1)
	k := h.latestCode(t, "EV-43", s1.user)
	require.Equal(t, http.StatusOK, h.confirm(t, s1, k).status)
	r := h.confirm(t, s2, k)
	require.Equal(t, http.StatusUnauthorized, r.status, "EV-43 близнец: S2 снята шагом 3 Р10: %s", r.body)
}

func sessionKeys(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Session map[string]any `json:"session"`
	}
	require.NoError(t, jsonUnmarshal(body, &out))
	keys := make([]string, 0, len(out.Session))
	for k := range out.Session {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return `["` + strings.Join(keys, `","`) + `"]`
}

// TestEV42_TheStoreDidNotAnswer — EV-42.
func TestEV42_TheStoreDidNotAnswer(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-42")
	s := h.register(t, freshAddress("ev42"))
	k := h.latestCode(t, "EV-42", s.user)
	h.failApply.Store(true)
	r := h.confirm(t, s, k)
	h.failApply.Store(false)
	require.Equal(t, http.StatusServiceUnavailable, r.status, "EV-42: 503: %s", r.body)
	require.JSONEq(t, `{"code":14,"message":"request not performed; try again later","details":[]}`, r.body)
	_, marked := h.markedAt(t, s.user)
	require.False(t, marked, "EV-42: отметки нет")
	require.Equal(t, http.StatusOK, h.confirm(t, s, k).status, "EV-42: K жив — после восстановления хранилища проходит")
}
