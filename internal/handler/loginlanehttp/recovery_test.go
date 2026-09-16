// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_test.go — HTTP-контракт двух глаголов восстановления доступа на
// полосе формы (фаза Ф5, `kacho#1271`): запрос кода и его предъявление вместе с
// новым паролем. Формы запросов закрыты, ответ на запрос кода побайтово один
// при любом исходе (Ф5-01/02, Ф1-25/26), предъявление отвечает как вход:
// печенья Р3 и тело Ф3-01. Варианты использования подставлены дублёрами:
// предмет проб — транспорт.
package loginlanehttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// Глаголы восстановления дублёра полосы (поля — в handler_test.go).
func (s *stubLane) RequestRecovery(_ context.Context, in humansession.RequestRecoveryInput) error {
	s.requestIn = append(s.requestIn, in)
	return s.requestErr
}

func (s *stubLane) CompleteRecovery(_ context.Context, in humansession.CompleteRecoveryInput) (humansession.CompleteRecoveryOutput, error) {
	s.completeIn = append(s.completeIn, in)
	return s.completeOut, s.completeErr
}

func TestLane_F5_Paths_AreSixAndDeclaredOnce(t *testing.T) {
	require.Equal(t, []string{
		loginlanehttp.PathLogin, loginlanehttp.PathLogout, loginlanehttp.PathPassword, loginlanehttp.PathCSRF,
		loginlanehttp.PathRecovery, loginlanehttp.PathRecoveryComplete,
	}, loginlanehttp.Paths(), "край читает тот же перечень для ретрансляции")
	require.Equal(t, "/iam/v1/auth/recovery", loginlanehttp.PathRecovery)
	require.Equal(t, "/iam/v1/auth/recovery/complete", loginlanehttp.PathRecoveryComplete)
}

// TestLane_F5_01_02_RequestAnswersTheSameBodyWhateverTheOutcome — ответ на
// запрос кода один: 200 с пустым объектом, без Set-Cookie, — и для адреса,
// который есть, и для адреса, которого нет: исход глагол не сообщает вовсе.
func TestLane_F5_01_02_RequestAnswersTheSameBodyWhateverTheOutcome(t *testing.T) {
	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "recovery", nil)

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery",
		map[string]string{"email": "a@example.invalid", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.JSONEq(t, `{}`, r.body)
	require.Empty(t, r.cookies, "запрос кода печений не пишет: сессии нет, контекст формы прежний")
	require.Len(t, stub.requestIn, 1)
	require.Equal(t, "a@example.invalid", stub.requestIn[0].Email)
	require.Equal(t, "203.0.113.7", stub.requestIn[0].Source)

	again := l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery",
		map[string]string{"email": "nobody@example.invalid", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk)
	require.Equal(t, r.status, again.status)
	require.Equal(t, r.body, again.body, "Ф5-02: побайтово тот же ответ")

	// Форма: поле, лишнее поле, признак — как у входа.
	hits := len(stub.requestIn)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery", map[string]string{"csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument email: required"`)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery", map[string]string{"email": "a@example.invalid", "csrfToken": tok, "code": "x"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `code`, "лишнее поле называется")
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery", map[string]string{"email": "a@example.invalid"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument csrfToken: required"`)
	// Признак ДРУГОГО вида — чужой: признак входа форме восстановления не годится (Ф1 Р6).
	loginTok, _ := l.csrf(t, c, "login", ctxCk)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery", map[string]string{"email": "a@example.invalid", "csrfToken": loginTok}, nil, ctxCk)
	require.Equal(t, http.StatusForbidden, r.status)
	require.Contains(t, r.body, `"reason":"FORM_TOKEN_REJECTED"`)
	require.Equal(t, hits, len(stub.requestIn), "отказы формы глагол не исполняют")

	// Хранилище не ответило — 503 своим текстом; тело не раскрывает адреса.
	stub.requestErr = humansession.ErrStoreUnavailable
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery", map[string]string{"email": "a@example.invalid", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.JSONEq(t, `{"code":14,"message":"request not performed; try again later","details":[]}`, r.body)
}

// TestLane_F5_03_CompleteIssuesTheSessionCookieLikeALogin — предъявление кода с
// новым паролем: тело как у входа (Ф3-01), `kaname_session`, новый контекст
// формы; в глагол уходят адрес, код, пароль и источник.
func TestLane_F5_03_CompleteIssuesTheSessionCookieLikeALogin(t *testing.T) {
	bearer, _ := domain.NewSessionBearer()
	view := sessionView()
	view.Session.PresentedMethods = []string{"recovery_code"}
	stub := &stubLane{completeOut: humansession.CompleteRecoveryOutput{View: view, Bearer: bearer}}
	l := newLane(t, stub, "console.example.invalid")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "recovery-complete", nil)

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete",
		map[string]string{"email": "a@example.invalid", "code": "ABCDE-FGHJK", "newPassword": "brand-new-password", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.Equal(t, "usr-a", body["user"].(map[string]any)["id"])
	sess := body["session"].(map[string]any)
	require.Equal(t, "1", sess["assuranceLevel"])
	require.Equal(t, false, sess["passwordChangeRequired"])
	require.Equal(t, base.Add(24*time.Hour).Format(time.RFC3339), sess["expiresAt"])
	require.NotContains(t, r.body, bearer.CookieValue(), "носитель не в теле")
	require.NotContains(t, r.body, "ABCDE-FGHJK", "код в ответе не повторяется")

	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc)
	require.Equal(t, bearer.CookieValue(), sc.Value)
	require.Equal(t, 86400, sc.MaxAge)
	require.True(t, sc.HttpOnly)
	require.True(t, sc.Secure)
	require.Equal(t, "console.example.invalid", sc.Domain)
	fc := cookieNamed(r.cookies, "kaname_form")
	require.NotNil(t, fc, "контекст формы сменён выдачей сессии (Р12)")
	require.NotEqual(t, ctxCk.Value, fc.Value)

	require.Len(t, stub.completeIn, 1)
	in := stub.completeIn[0]
	require.Equal(t, "a@example.invalid", in.Email)
	require.Equal(t, "ABCDE-FGHJK", in.Code)
	require.Equal(t, "brand-new-password", in.NewPassword)
	require.Equal(t, "203.0.113.7", in.Source)
}

// TestLane_F5_04_08_CompleteRefusalsAreFixedTextsWithoutSetCookie — отказы
// предъявления: один текст на код после срока, повторный, чужой и
// заблокированную личность (401, как у входа); по частоте — 429 с Retry-After;
// негодный пароль — 400 с полем; форма — до глагола.
func TestLane_F5_04_08_CompleteRefusalsAreFixedTextsWithoutSetCookie(t *testing.T) {
	stub := &stubLane{completeErr: humansession.ErrAuthenticationFailed}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "recovery-complete", nil)
	form := map[string]string{"email": "a@example.invalid", "code": "ABCDE-FGHJK", "newPassword": "brand-new-password", "csrfToken": tok}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", form, nil, ctxCk)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
	require.Empty(t, r.cookies)
	first := r.body
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", form, nil, ctxCk)
	require.Equal(t, first, r.body, "отказ один: второй раз тело побайтово то же")

	stub.completeErr = &humansession.TooManyAttemptsError{Scope: humansession.FailureByAddress, RetryAfter: 90 * time.Second}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", form, nil, ctxCk)
	require.Equal(t, http.StatusTooManyRequests, r.status)
	require.Equal(t, "90", r.header.Get("Retry-After"))
	require.Contains(t, r.body, `"reason":"TOO_MANY_ATTEMPTS"`)

	stub.completeErr = &humansession.FieldError{Field: "newPassword", Rule: "shorter than 8"}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", form, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument newPassword: shorter than 8"`)

	stub.completeErr = humansession.ErrStoreUnavailable
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", form, nil, ctxCk)
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.Empty(t, r.cookies)

	hits := len(stub.completeIn)
	for _, missing := range []string{"email", "code", "newPassword"} {
		partial := map[string]string{}
		for k, v := range form {
			if k != missing {
				partial[k] = v
			}
		}
		r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete", partial, nil, ctxCk)
		require.Equal(t, http.StatusBadRequest, r.status)
		require.Contains(t, r.body, `"Illegal argument `+missing+`: required"`)
	}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete",
		map[string]string{"email": "a@example.invalid", "code": "x", "newPassword": "brand-new-password", "csrfToken": tok, "currentPassword": "old"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `currentPassword`, "лишнее поле называется: восстановление текущего пароля не спрашивает")
	requestTok, _ := l.csrf(t, c, "recovery", ctxCk)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/recovery/complete",
		map[string]string{"email": "a@example.invalid", "code": "x", "newPassword": "brand-new-password", "csrfToken": requestTok}, nil, ctxCk)
	require.Equal(t, http.StatusForbidden, r.status, "признак запроса кода форме предъявления не годится")
	require.Equal(t, hits, len(stub.completeIn), "отказы формы глагол не исполняют")

	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/recovery/complete", nil, nil)
	require.Equal(t, http.StatusMethodNotAllowed, r.status)
	r = l.do(t, l.client(t, vpcSAN), http.MethodPost, "/iam/v1/auth/recovery", form, nil, ctxCk)
	require.Equal(t, http.StatusForbidden, r.status, "не край — не допущен, как на всякий глагол полосы")
}
