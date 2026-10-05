// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_enroll_integration_test.go — первый пароль заводится из живой
// сессии (задача PRO-Robotech/kaname#213; приёмка
// `docs/engineering/acceptance/first-password-from-a-live-session.md`,
// отпечаток 72825c63…, запись
// `docs/specs/reviews/first-password-from-a-live-session/72825c63….yaml`,
// APPROVED): сценарии уровня I FP-01…FP-08, FP-11 на слушателе полосы над
// настоящим хранилищем (харнесс `avLane`, часы `avClock` — только вперёд).
//
// «Дано I» (§4.0): личность без строки способа «пароль» с подтверждённым
// адресом и сессией, выданной операцией выдачи с предъявлением ключа
// (`KeyAssertion(true, false)` — так такая личность входит, Ф13-19). Здесь
// личность заводится регистрацией, а строка «пароль» снимается записью: итог —
// то же состояние, что вставка строк личности пробой (§4.0), и единственный
// шаг мимо продукта по-прежнему один.
//
// Путь и вид признака — литералами: проба обязана компилироваться на ревизии
// без глагола (иначе «не выполнилось», а не красный); на ней путь отвечает 404.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

const (
	fpPath = "/iam/v1/auth/password/enroll"
	fpKind = "password-enroll"
)

// fpGiven — «Дано I»: личность без пароля, адрес подтверждён, сессия ключа `S`
// в t₀ = avClock.Now(); контекст формы — тот, что выдала регистрация.
func fpGiven(t *testing.T, h *avLane, tag string, verified bool) avSession {
	t.Helper()
	s := h.register(t, freshAddress(tag))
	tag2, err := h.pool.Exec(h.ctx, `DELETE FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(s.user))
	require.NoError(t, err)
	require.EqualValues(t, 1, tag2.RowsAffected(), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка «пароль» снята записью")
	if verified {
		h.mark(t, s)
	}
	s.bearer = fpKeySession(t, h, s)
	return s
}

// fpKeySession — ещё одна сессия той же личности, выданная операцией выдачи с
// предъявлением ключа в момент avClock.Now().
func fpKeySession(t *testing.T, h *avLane, s avSession) *http.Cookie {
	t.Helper()
	var user domain.User
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT id, account_id, email, invite_status FROM kaname.users WHERE id = $1`,
		string(s.user)).Scan(&user.ID, &user.AccountID, &user.Email, &user.InviteStatus))
	w, err := h.sessions.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	_, bearer, err := humansession.IssueSession(h.ctx, w, humansession.IssueInput{
		User: user, Presented: []assurance.Presentation{assurance.KeyAssertion(true, false)},
		At: h.clock.Now(), TTL: laneSessionTTL,
	})
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача сессии ключа")
	require.NoError(t, w.Commit(h.ctx))
	return &http.Cookie{Name: loginlanehttp.CookieSession, Value: bearer.CookieValue()}
}

func fpEnroll(t *testing.T, h *avLane, s avSession, password string) reply {
	t.Helper()
	return h.post(t, s, fpPath, map[string]any{"newPassword": password, "csrfToken": h.token(s, fpKind)})
}

func fpPasswordRows(t *testing.T, h *avLane, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`, string(user)).Scan(&n))
	return n
}

func fpEvents(t *testing.T, h *avLane, user domain.UserID) []map[string]any {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `SELECT event_payload::text FROM kaname.audit_outbox
		 WHERE event_type = 'iam.user.password_enrolled' AND event_payload->>'user_id' = $1`, string(user))
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var p string
		require.NoError(t, rows.Scan(&p))
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(p), &m))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestFP01_PasswordlessPersonEnrollsAPasswordAndSignsInWithIt — FP-01.
func TestFP01_PasswordlessPersonEnrollsAPasswordAndSignsInWithIt(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp01", true)
	s2 := fpKeySession(t, h, s)
	h.clock.Advance(time.Minute)

	r := fpEnroll(t, h, s, "first-password-of-fp01")
	require.Equalf(t, http.StatusOK, r.status, "FP-01: заведение из свежей сессии — 200: %s", r.body)
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "FP-01: Set-Cookie носителя нет")
	var out struct {
		Session map[string]any `json:"session"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.Equal(t, "3", out.Session["assuranceLevel"], "FP-01: тело — форма Ф3-01, уровень сессии прежний")

	require.Equal(t, http.StatusOK, h.loginReply(t, s.email, "first-password-of-fp01").status, "FP-01: вход новым паролем")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, s.email, "some-other-password-fp01").status)
	require.True(t, h.resolve(t, s.bearer).GetFound(), "FP-01: S жива")
	require.True(t, h.resolve(t, s2).GetFound(), "FP-01: S2 жива")
	require.Equal(t, "3", h.resolve(t, s.bearer).GetSession().GetAssuranceLevel(), "уровень S прежний")

	ev := fpEvents(t, h, s.user)
	require.Len(t, ev, 1, "FP-01: ровно одно событие")
	require.Equal(t, []any{"webauthn"}, ev[0]["methods"], "methods — предъявленное S")
	require.NotEmpty(t, ev[0]["session_id"])
	for k := range ev[0] {
		require.Contains(t, []string{"user_id", "session_id", "methods"}, k, "FP-01: без материала пароля")
	}
}

// TestFP02_EnrollmentIsRefusedWhenAPasswordRowExists — FP-02.
func TestFP02_EnrollmentIsRefusedWhenAPasswordRowExists(t *testing.T) {
	h := newAVLane(t)
	s := h.register(t, freshAddress("fp02"))
	h.mark(t, s)
	r := fpEnroll(t, h, s, "another-password-fp02")
	require.Equalf(t, http.StatusConflict, r.status, "FP-02: 409: %s", r.body)
	require.Contains(t, r.body, `"code":6`)
	require.Contains(t, r.body, "password is already set; change it with the current password")
	require.Contains(t, r.body, "PASSWORD_ALREADY_SET")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession))
	require.Equal(t, http.StatusOK, h.loginReply(t, s.email, integrationPassword).status, "вход прежним паролем")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, s.email, "another-password-fp02").status)
	require.Empty(t, fpEvents(t, h, s.user), "события нет")
}

// TestFP03_StaleSessionIsRefusedAndTheWindowBoundaryIsIncluded — FP-03.
func TestFP03_StaleSessionIsRefusedAndTheWindowBoundaryIsIncluded(t *testing.T) {
	t.Run("(а) окно + 1 с", func(t *testing.T) {
		h := newAVLane(t)
		s := fpGiven(t, h, "fp03a", true)
		h.clock.Advance(laneFreshness + time.Second)
		r := fpEnroll(t, h, s, "first-password-fp03a")
		require.Equalf(t, http.StatusForbidden, r.status, "FP-03 (а): %s", r.body)
		require.Contains(t, r.body, "re-authentication required: present a credential again")
		require.Contains(t, r.body, "SESSION_NOT_FRESH")
		require.Zero(t, fpPasswordRows(t, h, s.user))
		require.True(t, h.resolve(t, s.bearer).GetFound(), "S жива")
	})
	t.Run("(б) ровно окно", func(t *testing.T) {
		h := newAVLane(t)
		s := fpGiven(t, h, "fp03b", true)
		h.clock.Advance(laneFreshness)
		r := fpEnroll(t, h, s, "first-password-fp03b")
		require.Equalf(t, http.StatusOK, r.status, "FP-03 (б): граница включена: %s", r.body)
		require.Equal(t, 1, fpPasswordRows(t, h, s.user))
	})
}

// TestFP04_VerificationPositionRefusesEnrollment — FP-04.
func TestFP04_VerificationPositionRefusesEnrollment(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp04", false)
	r := fpEnroll(t, h, s, "first-password-fp04")
	require.Equalf(t, http.StatusForbidden, r.status, "FP-04: %s", r.body)
	require.Contains(t, r.body, "EMAIL_NOT_VERIFIED")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession))
	require.Zero(t, fpPasswordRows(t, h, s.user))
	require.True(t, h.resolve(t, s.bearer).GetFound(), "S жива")
}

// TestFP05_NoSessionIsTheUnifiedRefusal — FP-05.
func TestFP05_NoSessionIsTheUnifiedRefusal(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp05", true)
	anon := s
	anon.bearer = nil
	r := fpEnroll(t, h, anon, "first-password-fp05")
	require.Equalf(t, http.StatusUnauthorized, r.status, "FP-05 (а): %s", r.body)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)

	out := h.post(t, s, loginlanehttp.PathLogout, map[string]any{"csrfToken": h.token(s, string(domain.FormLogout))})
	require.Equal(t, http.StatusOK, out.status, "Дано: выход")
	r = fpEnroll(t, h, s, "first-password-fp05")
	require.Equalf(t, http.StatusUnauthorized, r.status, "FP-05 (б): %s", r.body)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
	require.Zero(t, fpPasswordRows(t, h, s.user))
}

// TestFP06_FormFieldsAreNamedAndAForeignKindIsRejected — FP-06.
func TestFP06_FormFieldsAreNamedAndAForeignKindIsRejected(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp06", true)
	r := h.post(t, s, fpPath, map[string]any{"newPassword": "first-password-fp06"})
	require.Equalf(t, http.StatusBadRequest, r.status, "FP-06 (а): %s", r.body)
	require.Contains(t, r.body, "Illegal argument csrfToken: required")
	r = h.post(t, s, fpPath, map[string]any{"newPassword": "first-password-fp06", "csrfToken": h.token(s, string(domain.FormPassword))})
	require.Equalf(t, http.StatusForbidden, r.status, "FP-06 (б): %s", r.body)
	require.Contains(t, r.body, "form token rejected")
	require.Contains(t, r.body, "FORM_TOKEN_REJECTED")
	r = h.post(t, s, fpPath, map[string]any{"newPassword": "first-password-fp06", "currentPassword": "x", "csrfToken": h.token(s, fpKind)})
	require.Equalf(t, http.StatusBadRequest, r.status, "FP-06 (в): %s", r.body)
	require.Contains(t, r.body, "Illegal argument currentPassword: unknown field")
	r = h.post(t, s, fpPath, map[string]any{"csrfToken": h.token(s, fpKind)})
	require.Equalf(t, http.StatusBadRequest, r.status, "FP-06 (г): %s", r.body)
	require.Contains(t, r.body, "Illegal argument newPassword: required")
	require.Zero(t, fpPasswordRows(t, h, s.user), "ни в одном случае строки нет")
}

// TestFP07_NewPasswordIsJudgedByTheOneRule — FP-07 (а, б).
func TestFP07_NewPasswordIsJudgedByTheOneRule(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp07", true)
	r := fpEnroll(t, h, s, "short-fp07a")
	require.Equalf(t, http.StatusBadRequest, r.status, "FP-07 (а): %s", r.body)
	require.Contains(t, r.body, "Illegal argument newPassword:")
	local := s.email[:strings.Index(s.email, "@")]
	r = fpEnroll(t, h, s, local+"-fp07b")
	require.Equalf(t, http.StatusBadRequest, r.status, "FP-07 (б): %s", r.body)
	require.Contains(t, r.body, "Illegal argument newPassword:")
	require.Zero(t, fpPasswordRows(t, h, s.user))
}

// TestFP08_TwoEnrollmentsRaceAndOneRowRemains — FP-08.
func TestFP08_TwoEnrollmentsRaceAndOneRowRemains(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp08", true)
	s2 := s
	s2.bearer = fpKeySession(t, h, s)
	pw := map[int]string{0: "pw-alpha-fp08", 1: "pw-bravo-fp08"}
	sessions := []avSession{s, s2}
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		st = map[int]int{}
	)
	for i := range sessions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := postStatusAV(h, sessions[i], fpPath, map[string]any{"newPassword": pw[i], "csrfToken": h.token(sessions[i], fpKind)})
			mu.Lock()
			st[i] = code
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	winner := -1
	for i, c := range st {
		if c == http.StatusOK {
			require.Equal(t, -1, winner, "FP-08: проходит одно")
			winner = i
		} else {
			require.Equal(t, http.StatusConflict, c, "FP-08: проигравший — отказ FP-02")
		}
	}
	require.NotEqual(t, -1, winner)
	require.Equal(t, 1, fpPasswordRows(t, h, s.user), "строка одна")
	require.Len(t, fpEvents(t, h, s.user), 1, "событие одно")
	require.Equal(t, http.StatusOK, h.loginReply(t, s.email, pw[winner]).status, "вход паролем победителя")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, s.email, pw[1-winner]).status, "проигравшего — 401")
}

// postStatusAV — POST под сессией без require: безопасен из горутины.
func postStatusAV(h *avLane, s avSession, path string, body map[string]any) int {
	cookies := []*http.Cookie{}
	if s.bearer != nil {
		cookies = append(cookies, s.bearer)
	}
	if s.form != nil {
		cookies = append(cookies, s.form)
	}
	return postStatusVia(h.lane, h.c, path, body, cookies...)
}

// TestFP11_EnrollmentLeavesTheFailureCountUntouched — FP-11.
func TestFP11_EnrollmentLeavesTheFailureCountUntouched(t *testing.T) {
	h := newAVLane(t)
	s := fpGiven(t, h, "fp11", true)
	s0 := s
	h.clock.Advance(laneFreshness + time.Second)
	s1 := s
	s1.bearer = fpKeySession(t, h, s)
	s2 := s
	s2.bearer = fpKeySession(t, h, s)
	sourceCount := func() int {
		var n int
		require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM kaname.login_failures WHERE scope = 'source' AND key = $1`,
			fwd()[loginlanehttp.HeaderForwardedFor]).Scan(&n))
		return n
	}
	a0, src0 := h.failuresOf(t, s.email), sourceCount()

	require.Equal(t, http.StatusForbidden, fpEnroll(t, h, s0, "first-password-fp11").status, "шаг 1 — SESSION_NOT_FRESH")
	require.Equal(t, http.StatusBadRequest, h.post(t, s1, fpPath, map[string]any{"csrfToken": h.token(s1, fpKind)}).status, "шаг 2")
	require.Equal(t, http.StatusBadRequest, fpEnroll(t, h, s1, "short-fp11").status, "шаг 3")
	require.Equal(t, http.StatusOK, fpEnroll(t, h, s1, "first-password-fp11").status, "шаг 4")
	require.Equal(t, http.StatusConflict, fpEnroll(t, h, s2, "second-password-fp11").status, "шаг 5")

	require.Equal(t, a0, h.failuresOf(t, s.email), "FP-11: счёт по адресу не тронут")
	require.Equal(t, src0, sourceCount(), "FP-11: счёт по источнику не тронут")
	require.Equal(t, http.StatusUnauthorized, h.loginReply(t, s.email, "wrong-password-fp11").status)
	require.Equal(t, a0+1, h.failuresOf(t, s.email), "контроль чувствительности: неверный вход считается")
	require.Equal(t, src0+1, sourceCount())
}
