// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_test.go — HTTP-контракт глагола регистрации (фаза Ф4, `kacho#1270`;
// Ф4-01 наблюдение снаружи, Ф4-11/12 побайтовое равенство отказа, Р3).
// Вариант использования подставлен дублёром: предмет проб — транспорт.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// TestLane_F4_01_RegisterIssuesTheSessionCookieAndANewFormContext — успех
// регистрации: 200, состав ответа как у входа, печенье сессии, контекст формы
// сменён; адрес и пароль уходят глаголу как есть, источник — один адрес.
func TestLane_F4_01_RegisterIssuesTheSessionCookieAndANewFormContext(t *testing.T) {
	bearer, _ := domain.NewSessionBearer()
	view := sessionView()
	view.EmailVerified = false
	stub := &stubLane{registerOut: registration.Output{View: view, Bearer: bearer}}
	l := newLane(t, stub, "console.example.invalid")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "register", nil)

	r := l.do(t, c, http.MethodPost, loginlanehttp.PathRegister,
		map[string]string{"email": "a@example.invalid", "password": "correct-horse-battery-staple-9", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	user := body["user"].(map[string]any)
	require.Equal(t, "usr-a", user["id"])
	sess := body["session"].(map[string]any)
	require.Equal(t, false, sess["emailVerified"], "адрес только что заведён — не подтверждён (Ф1-20)")
	require.Equal(t, base.Add(24*time.Hour).Format(time.RFC3339), sess["expiresAt"])
	require.NotContains(t, r.body, bearer.CookieValue(), "носитель не в теле")

	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc, "сессия выдана регистрацией (третье следствие)")
	require.Equal(t, bearer.CookieValue(), sc.Value)
	require.Equal(t, 86400, sc.MaxAge)
	require.True(t, sc.HttpOnly)
	require.True(t, sc.Secure)
	fc := cookieNamed(r.cookies, "kaname_form")
	require.NotNil(t, fc, "контекст формы сменён выдачей сессии (Р12)")
	require.NotEqual(t, ctxCk.Value, fc.Value)

	require.Len(t, stub.registerIn, 1)
	require.Equal(t, "a@example.invalid", stub.registerIn[0].Email)
	require.Equal(t, "correct-horse-battery-staple-9", stub.registerIn[0].Password)
	require.Equal(t, "203.0.113.7", stub.registerIn[0].Source)
	require.Contains(t, loginlanehttp.Paths(), loginlanehttp.PathRegister, "край читает тот же перечень")
}

// TestLane_F4_11_12_RefusalIsOneFixedBodyWithoutACause — единый отказ
// регистрации: 400 FAILED_PRECONDITION фиксированным текстом и признаком, без
// Set-Cookie, без Retry-After; тело побайтово одно на любую причину (Р3).
// Отказ формы (правило пароля) — осознанное исключение: называет поле.
func TestLane_F4_11_12_RefusalIsOneFixedBodyWithoutACause(t *testing.T) {
	stub := &stubLane{registerErr: registration.ErrRefused}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "register", nil)
	form := map[string]string{"email": "a@example.invalid", "password": "correct-horse-battery-staple-9", "csrfToken": tok}

	r := l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, form, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.JSONEq(t, `{"code":9,"message":"registration refused","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"REGISTRATION_REFUSED","domain":"iam.kaname.cloud"}]}`, r.body)
	require.Empty(t, r.cookies, "без Set-Cookie")
	require.Empty(t, r.header.Get("Retry-After"), "потолок темпа не выдаётся заголовком")
	first := r.body
	// Второй раз — тот же сентинел (у глагола причин две, у транспорта — одна):
	// тело побайтово равно.
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, form, nil, ctxCk)
	require.Equal(t, first, r.body)

	stub.registerErr = &humansession.FieldError{Field: "password", Rule: humansession.RuleTooShort}
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, form, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument password: `)
	require.Empty(t, r.cookies)

	stub.registerErr = humansession.ErrStoreUnavailable
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, form, nil, ctxCk)
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.JSONEq(t, `{"code":14,"message":"request not performed; try again later","details":[]}`, r.body)

	// Форма: отсутствующее поле называется ДО глагола; лишнее отвергается;
	// признак формы — свой вид (`register`), чужой вид не подходит.
	hits := len(stub.registerIn)
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, map[string]string{"email": "a@example.invalid", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument password: required"`)
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, map[string]string{"email": "a@example.invalid", "password": "x", "csrfToken": tok, "displayName": "Ann"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `displayName`, "лишнее поле называется")
	loginTok, _ := l.csrf(t, c, "login", ctxCk)
	r = l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, map[string]string{"email": "a@example.invalid", "password": "x", "csrfToken": loginTok}, nil, ctxCk)
	require.Equal(t, http.StatusForbidden, r.status, "признак чужого вида формы не подходит")
	require.Contains(t, r.body, `"reason":"FORM_TOKEN_REJECTED"`)
	require.Equal(t, hits, len(stub.registerIn), "отказы формы глагол не исполняют")
}
