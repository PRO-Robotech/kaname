// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_lane_integration_test.go — полосы А, Б, В приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456): сессия и её
// положение, полоса формы в положении подтверждения, запрос письма. Стенд —
// `address_verification_harness_integration_test.go`.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run 'EV' -count=1` (Docker).
package loginlanehttp_test

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// ─── Полоса А — сессия и её положение ───────────────────────────────────────

// TestEV01_RegistrationIssuesAVerificationSessionAndQueuesTheLetter — EV-01.
func TestEV01_RegistrationIssuesAVerificationSessionAndQueuesTheLetter(t *testing.T) {
	h := newAVLane(t)
	email := freshAddress("ev01")
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "EV-01: регистрация — 200: %s", r.body)
	verified, present := sessionEmailVerified(t, r.body)
	require.True(t, present, "EV-01: тело несёт session.emailVerified: %s", r.body)
	require.False(t, verified, "EV-01: session.emailVerified = false")
	bearer := cookieNamed(r.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, bearer, "EV-01: Set-Cookie — носитель kaname_session")

	res := h.resolve(t, bearer)
	require.True(t, res.GetFound(), "EV-01: Resolve по носителю регистрации — found = true")
	require.False(t, res.GetSession().GetEmailVerified(), "EV-01: Resolve — email_verified = false")

	user := domain.UserID(res.GetSession().GetUserId())
	ls := h.letters(t, user)
	if len(ls) == 0 {
		t.Fatalf("EV-01 ЧЕСТНЫЙ-КРАСНЫЙ: строки вида %s для зарегистрированного нет", avMailKind)
	}
	require.Len(t, ls, 1, "EV-01: в очереди ровно одна строка письма подтверждения")
	require.Len(t, ls[0].code, len("XXXXX-XXXXX"), "EV-01: строка несёт живой код в форме для человека: %q", ls[0].code)
	require.Equal(t, email, ls[0].to, "EV-01: письмо адресовано зарегистрированному")

	// Близнец: регистрация отвергнута (адрес занят) — письма нет.
	tok2, ctx2 := h.lane.csrf(t, h.c, string(domain.FormRegister), nil)
	r2 := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]any{"email": email, "password": integrationPassword, "csrfToken": tok2}, fwd(), ctx2)
	require.Equal(t, http.StatusBadRequest, r2.status, "EV-01 близнец: повтор регистрации — единый отказ Ф4: %s", r2.body)
	require.Len(t, h.letters(t, user), 1, "EV-01 близнец: отвергнутая регистрация письма не ставит")
}

// TestEV02_LoginOfTheUnverifiedIssuesAVerificationSession — EV-02 (зелена и до
// кода — положительный контроль положения).
func TestEV02_LoginOfTheUnverifiedIssuesAVerificationSession(t *testing.T) {
	h := newAVLane(t)
	a := h.register(t, freshAddress("ev02a"))
	before := len(h.letters(t, a.user))

	r := h.loginReply(t, a.email, integrationPassword)
	require.Equal(t, http.StatusOK, r.status, r.body)
	v, ok := sessionEmailVerified(t, r.body)
	require.True(t, ok)
	require.False(t, v, "EV-02 (а): вход неподтверждённого — emailVerified = false")
	require.Len(t, h.letters(t, a.user), before, "EV-02 (а): вход письма не ставит")

	b := h.register(t, freshAddress("ev02b"))
	h.mark(t, b)
	rb := h.loginReply(t, b.email, integrationPassword)
	require.Equal(t, http.StatusOK, rb.status, rb.body)
	vb, ok := sessionEmailVerified(t, rb.body)
	require.True(t, ok)
	require.True(t, vb, "EV-02 (б): вход подтверждённого — emailVerified = true")
}

// TestEV03_PositionFollowsTheMarkOnEveryRequest — EV-03.
func TestEV03_PositionFollowsTheMarkOnEveryRequest(t *testing.T) {
	h := newAVLane(t)
	for _, tc := range []struct {
		name   string
		unmark bool
	}{{"а — отметка снята", true}, {"б — отметка на месте", false}} {
		t.Run(tc.name, func(t *testing.T) {
			s := h.register(t, freshAddress("ev03"))
			h.mark(t, s)
			if tc.unmark {
				h.unmark(t, s.user)
			}
			res := h.resolve(t, s.bearer)
			require.True(t, res.GetFound())
			require.Equal(t, !tc.unmark, res.GetSession().GetEmailVerified(), "EV-03: положение по текущей отметке")
			r := h.post(t, s, loginlanehttp.PathPassword, map[string]any{
				"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev03",
				"csrfToken": h.token(s, string(domain.FormPassword)),
			})
			if tc.unmark {
				require.Equal(t, http.StatusForbidden, r.status, "EV-03 (а): смена пароля — отказ Р3 на ПЕРВОМ же запросе после снятия: %s", r.body)
				require.JSONEq(t, avRefusalBody, r.body, "EV-03 (а): значение Р3")
				return
			}
			require.Equal(t, http.StatusOK, r.status, "EV-03 (б): смена пароля проходит своими правилами: %s", r.body)
		})
	}
}

// ─── Полоса Б — полоса формы в положении подтверждения ──────────────────────

// TestEV10_LogoutIsAvailableToBoth — EV-10 (зелена и до кода).
func TestEV10_LogoutIsAvailableToBoth(t *testing.T) {
	h := newAVLane(t)
	for _, verified := range []bool{false, true} {
		s := h.register(t, freshAddress("ev10"))
		if verified {
			h.mark(t, s)
		}
		r := h.post(t, s, loginlanehttp.PathLogout, map[string]any{"csrfToken": h.token(s, string(domain.FormLogout))})
		require.Equal(t, http.StatusOK, r.status, "EV-10 (подтверждён=%v): выход — 200: %s", verified, r.body)
		require.JSONEq(t, `{}`, r.body)
		gone := cookieNamed(r.cookies, loginlanehttp.CookieSession)
		require.NotNil(t, gone, "EV-10: носитель погашен")
		require.Equal(t, -1, gone.MaxAge)
		require.False(t, h.resolve(t, s.bearer).GetFound(), "EV-10: Resolve — found = false")
	}
}

// TestEV11_PasswordChangeIsRefusedInTheVerificationPosition — EV-11.
func TestEV11_PasswordChangeIsRefusedInTheVerificationPosition(t *testing.T) {
	h := newAVLane(t)
	const fresh = "a-fresh-password-for-ev11"
	a := h.register(t, freshAddress("ev11a"))
	failuresBefore := h.failuresOf(t, a.email)
	r := h.post(t, a, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": fresh, "csrfToken": h.token(a, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusForbidden, r.status, "EV-11 (а): отказ Р3 — 403: %s", r.body)
	require.JSONEq(t, avRefusalBody, r.body, "EV-11 (а): тело — дословно значение Р3")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "EV-11 (а): без Set-Cookie")
	require.Equal(t, failuresBefore, h.failuresOf(t, a.email), "EV-11 (а): попытка в счёт темпа входа не идёт")
	require.Equal(t, http.StatusOK, h.loginReply(t, a.email, integrationPassword).status, "EV-11 (а): пароль не сменён")

	b := h.register(t, freshAddress("ev11b"))
	h.mark(t, b)
	rb := h.post(t, b, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": fresh, "csrfToken": h.token(b, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusOK, rb.status, "EV-11 (б): смена пароля — 200: %s", rb.body)
	require.Equal(t, http.StatusOK, h.loginReply(t, b.email, fresh).status, "EV-11 (б): пароль сменён")
}

// TestEV12_SecondFactorAndStepUpAreRefusedOnEachOfSixPaths — EV-12.
func TestEV12_SecondFactorAndStepUpAreRefusedOnEachOfSixPaths(t *testing.T) {
	h := newAVLane(t)
	type call struct {
		method, path string
		kind         domain.FormKind
		body         map[string]any
	}
	calls := []call{
		{http.MethodGet, loginlanehttp.PathSecondFactor, "", nil},
		{http.MethodPost, loginlanehttp.PathSecondFactorEnroll, domain.FormSecondFactor, map[string]any{}},
		{http.MethodPost, loginlanehttp.PathSecondFactorConfirm, domain.FormSecondFactor, map[string]any{"code": "123456"}},
		{http.MethodPost, loginlanehttp.PathSecondFactorRemove, domain.FormSecondFactor, map[string]any{"method": "totp", "code": "123456"}},
		{http.MethodPost, loginlanehttp.PathSecondFactorBackupCodes, domain.FormSecondFactor, map[string]any{"method": "totp", "code": "123456"}},
		{http.MethodPost, loginlanehttp.PathStepUp, domain.FormStepUp, map[string]any{"method": "password", "password": integrationPassword}},
	}
	send := func(s avSession, c call) reply {
		if c.method == http.MethodGet {
			return h.lane.do(t, h.c, http.MethodGet, c.path, nil, fwd(), s.bearer, s.form)
		}
		body := map[string]any{"csrfToken": h.token(s, string(c.kind))}
		for k, v := range c.body {
			body[k] = v
		}
		return h.post(t, s, c.path, body)
	}
	a := h.register(t, freshAddress("ev12a"))
	for _, c := range calls {
		r := send(a, c)
		require.Equal(t, http.StatusForbidden, r.status, "EV-12 (а) %s: отказ Р3: %s", c.path, r.body)
		require.JSONEq(t, avRefusalBody, r.body, "EV-12 (а) %s: значение Р3", c.path)
	}
	var rows int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1 AND kind <> 'password'`,
		string(a.user)).Scan(&rows))
	require.Zero(t, rows, "EV-12 (а): состояние фактора не меняется")

	b := h.register(t, freshAddress("ev12b"))
	h.mark(t, b)
	for _, c := range calls {
		r := send(b, c)
		if r.status >= 400 {
			require.NotEqual(t, "EMAIL_NOT_VERIFIED", parseRefusal(t, r.body).reason(), "EV-12 (б) %s: своего сегодняшнего исхода", c.path)
		}
	}
	anchor := send(b, calls[0])
	require.Equal(t, http.StatusOK, anchor.status, "EV-12 (б) якорь: чтение состояния фактора — 200: %s", anchor.body)
	require.JSONEq(t, `{"totp":{"enrolled":false}}`, anchor.body)
}

// TestEV13_PositionRefusalLeavesTheSessionAlive — EV-13.
func TestEV13_PositionRefusalLeavesTheSessionAlive(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-13")
	a := h.register(t, freshAddress("ev13a"))
	b := h.register(t, freshAddress("ev13b"))
	h.clock.Advance(avIntervalProfile + time.Second)

	ra := h.post(t, a, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev13", "csrfToken": h.token(a, string(domain.FormPassword)),
	})
	require.Equal(t, http.StatusForbidden, ra.status, "EV-13 (а): Дано — отказ EV-11 (а): %s", ra.body)
	rb := h.post(t, b, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": "a-fresh-password-for-ev13", "csrfToken": "not-the-token",
	})
	require.Equal(t, http.StatusForbidden, rb.status, "EV-13 (б): Дано — отказ признака формы: %s", rb.body)
	require.Equal(t, humansession.ReasonFormTokenRejected, parseRefusal(t, rb.body).reason())

	for name, s := range map[string]avSession{"а": a, "б": b} {
		r := h.requestLetter(t, s)
		require.Equal(t, http.StatusOK, r.status, "EV-13 (%s): тем же носителем запрос письма — 200: %s", name, r.body)
		require.JSONEq(t, `{}`, r.body)
	}
}

// ─── Полоса В — запрос письма ───────────────────────────────────────────────

// TestEV20_LetterRequestUnderAVerificationSession — EV-20 (и заказ консоли:
// успех несёт Retry-After — промежуток до следующего разрешённого письма).
func TestEV20_LetterRequestUnderAVerificationSession(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-20")
	s := h.register(t, freshAddress("ev20"))
	k1 := h.latestCode(t, "EV-20", s.user)
	h.clock.Advance(avIntervalProfile + time.Second)

	r := h.requestLetter(t, s)
	require.Equal(t, http.StatusOK, r.status, "EV-20: 200: %s", r.body)
	require.JSONEq(t, `{}`, r.body, "EV-20: тело {}")
	require.Empty(t, r.cookies, "EV-20: без Set-Cookie")
	require.Equal(t, strconv.Itoa(int(avIntervalProfile/time.Second)), r.header.Get("Retry-After"),
		"EV-20: успех называет промежуток до следующего разрешённого письма")
	ls := h.letters(t, s.user)
	require.Len(t, ls, 2, "EV-20: в очереди одна НОВАЯ строка")
	k2 := ls[1].code
	require.NotEqual(t, k1, k2)
	// K1 вытеснен (EV-34): не подходит, K2 — подходит.
	require.Equal(t, http.StatusUnauthorized, h.confirm(t, s, k1).status, "EV-20: K1 вытеснен")
	require.Equal(t, http.StatusOK, h.confirm(t, s, k2).status, "EV-20: K2 жив")
}

// TestEV21_LetterRequestWithoutASession — EV-21.
func TestEV21_LetterRequestWithoutASession(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-21")
	s := h.register(t, freshAddress("ev21"))
	h.clock.Advance(avIntervalProfile + time.Second)
	before := len(h.letters(t, s.user))

	noBearer := s
	noBearer.bearer = nil
	ra := h.requestLetter(t, noBearer)
	require.Equal(t, http.StatusUnauthorized, ra.status, "EV-21 (а): носителя нет — 401: %s", ra.body)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, ra.body)

	lo := h.post(t, s, loginlanehttp.PathLogout, map[string]any{"csrfToken": h.token(s, string(domain.FormLogout))})
	require.Equal(t, http.StatusOK, lo.status)
	rb := h.requestLetter(t, s)
	require.Equal(t, http.StatusUnauthorized, rb.status, "EV-21 (б): носитель снятой сессии — 401: %s", rb.body)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, rb.body)
	require.Len(t, h.letters(t, s.user), before, "EV-21: строки в очереди нет")
}

// TestEV22_LetterRequestByTheVerified — EV-22.
func TestEV22_LetterRequestByTheVerified(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-22")
	s := h.register(t, freshAddress("ev22"))
	h.mark(t, s)
	at, _ := h.markedAt(t, s.user)
	h.clock.Advance(avIntervalProfile + time.Second)
	before := len(h.letters(t, s.user))

	r := h.requestLetter(t, s)
	require.Equal(t, http.StatusBadRequest, r.status, "EV-22: 400: %s", r.body)
	ref := parseRefusal(t, r.body)
	require.Equal(t, 9, ref.Code)
	require.Equal(t, "email address is already verified", ref.Message)
	require.Equal(t, "EMAIL_ALREADY_VERIFIED", ref.reason())
	require.Len(t, h.letters(t, s.user), before, "EV-22: строки нет")
	after, _ := h.markedAt(t, s.user)
	require.True(t, at.Equal(after), "EV-22: отметка не тронута")
}

// TestEV23_IntervalBetweenLetters — EV-23.
func TestEV23_IntervalBetweenLetters(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-23")
	s := h.register(t, freshAddress("ev23")) // письмо регистрации — момент T
	h.clock.Advance(avIntervalProfile - time.Second)
	ra := h.requestLetter(t, s)
	require.Equal(t, http.StatusTooManyRequests, ra.status, "EV-23 (а): T+59с — 429: %s", ra.body)
	ref := parseRefusal(t, ra.body)
	require.Equal(t, 8, ref.Code)
	require.Equal(t, humansession.ReasonTooManyAttempts, ref.reason())
	require.Equal(t, "1", ra.header.Get("Retry-After"), "EV-23 (а): Retry-After: 1")
	require.Len(t, h.letters(t, s.user), 1, "EV-23 (а): строки нет")

	h.clock.Advance(time.Second)
	rb := h.requestLetter(t, s)
	require.Equal(t, http.StatusOK, rb.status, "EV-23 (б): T+60с — 200: %s", rb.body)
	require.Len(t, h.letters(t, s.user), 2, "EV-23 (б): строка есть")
}

// TestEV24_DailyLimitCountsTheRegistrationLetter — EV-24.
func TestEV24_DailyLimitCountsTheRegistrationLetter(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-24")
	s := h.register(t, freshAddress("ev24")) // письмо 1 — момент T
	start := h.clock.Now()
	for i := 2; i <= avLimitProfile; i++ {
		h.clock.Advance(avIntervalProfile)
		r := h.requestLetter(t, s)
		require.Equal(t, http.StatusOK, r.status, "EV-24: Дано — письмо %d: %s", i, r.body)
	}
	h.clock.Advance(avIntervalProfile)
	ra := h.requestLetter(t, s)
	require.Equal(t, http.StatusTooManyRequests, ra.status, "EV-24 (а): шестой запрос в тех же сутках — 429: %s", ra.body)
	wantRetry := start.Add(avWindowProfile).Sub(h.clock.Now())
	gotRetry, err := strconv.Atoi(ra.header.Get("Retry-After"))
	require.NoError(t, err, "EV-24 (а): Retry-After — целое число секунд")
	require.InDelta(t, wantRetry.Seconds(), float64(gotRetry), 1, "EV-24 (а): Retry-After — до выхода письма 1 из окна")
	require.Len(t, h.letters(t, s.user), avLimitProfile, "EV-24 (а): строки нет")

	h.clock.Advance(wantRetry)
	rb := h.requestLetter(t, s)
	require.Equal(t, http.StatusOK, rb.status, "EV-24 (б): письмо 1 вышло из окна — 200: %s", rb.body)
	require.Len(t, h.letters(t, s.user), avLimitProfile+1)
}

// TestEV25_LetterRequestForm — EV-25.
func TestEV25_LetterRequestForm(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-25")
	s := h.register(t, freshAddress("ev25"))
	h.clock.Advance(avIntervalProfile + time.Second)

	ra := h.post(t, s, avPathRequest, map[string]any{"email": "x@y.invalid", "csrfToken": h.token(s, avFormRequest)})
	require.Equal(t, http.StatusBadRequest, ra.status, "EV-25 (а): %s", ra.body)
	refA := parseRefusal(t, ra.body)
	require.Equal(t, 3, refA.Code)
	require.Contains(t, refA.Message, "email: unknown field", "EV-25 (а)")

	rb := h.post(t, s, avPathRequest, map[string]any{})
	require.Equal(t, http.StatusBadRequest, rb.status, "EV-25 (б): %s", rb.body)
	refB := parseRefusal(t, rb.body)
	require.Equal(t, 3, refB.Code)
	require.Contains(t, refB.Message, "csrfToken", "EV-25 (б): поле названо")

	rc := h.post(t, s, avPathRequest, map[string]any{"csrfToken": h.token(s, avFormConfirm)})
	require.Equal(t, http.StatusForbidden, rc.status, "EV-25 (в): %s", rc.body)
	refC := parseRefusal(t, rc.body)
	require.Equal(t, 7, refC.Code)
	require.Equal(t, humansession.ReasonFormTokenRejected, refC.reason())
	require.Len(t, h.letters(t, s.user), 1, "EV-25: строки нет ни в одном")

	require.Equal(t, http.StatusOK, h.requestLetter(t, s).status, "EV-25 близнец: годная форма — 200")
}

// failuresOf — следов неверных предъявлений по адресу.
func (h *avLane) failuresOf(t *testing.T, email string) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.login_failures WHERE scope = 'address' AND key = lower($1)`,
		email).Scan(&n))
	return n
}
