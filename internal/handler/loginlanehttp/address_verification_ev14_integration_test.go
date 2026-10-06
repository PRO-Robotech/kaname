// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_verification_ev14_integration_test.go — EV-14: текст отказа положения
// называет шаг, и названный шаг снимает отказ (приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// редакция 5 и далее, Р3; задача PRO-Robotech/kaname#526).
//
// Значение отказа читается у ОДНОГО помощника стенда (`avRefusalBody`), которым
// утверждают Р3 и прочие пробы полосы формы, — не третьим литералом.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// TestEV14_RefusalNamesTheStepAndTheStepLiftsIt — EV-14 (а), (б), (в).
func TestEV14_RefusalNamesTheStepAndTheStepLiftsIt(t *testing.T) {
	h := newAVLane(t)
	h.requireVerbs(t, "EV-14")
	const fresh = "a-fresh-password-for-ev14"
	s := h.register(t, freshAddress("ev14"))
	k := h.latestCode(t, "EV-14", s.user)
	change := func(sess avSession) reply {
		return h.post(t, sess, loginlanehttp.PathPassword, map[string]any{
			"currentPassword": integrationPassword, "newPassword": fresh, "csrfToken": h.token(sess, string(domain.FormPassword)),
		})
	}

	// (а) — отказ положения, тело дословно значение Р3.
	r := change(s)
	require.Equal(t, http.StatusForbidden, r.status, "EV-14 (а): отказ Р3 — 403: %s", r.body)
	require.JSONEq(t, avRefusalBody, r.body, "EV-14 (а): тело — дословно значение Р3")
	require.Nil(t, cookieNamed(r.cookies, loginlanehttp.CookieSession), "EV-14 (а): без Set-Cookie")

	// (в) — путь, который называет текст, есть путь полосы, доступный в
	// положении подтверждения. Пустой вырез — отказ пробы.
	var refusal struct {
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &refusal))
	path := ev14StepPath(refusal.Message)
	t.Logf("EV-14 (в): вырезанный путь шага — %q", path)
	require.NotEmpty(t, path, "EV-14 (в): текст отказа %q не называет шага (выреза после \"POST \" до \")\" нет)", refusal.Message)
	require.True(t, slices.Contains(loginlanehttp.Paths(), path), "EV-14 (в): %q — не путь полосы формы", path)
	require.Equal(t, loginlanehttp.PathAvailableInVerification, loginlanehttp.PathPositions()[path],
		"EV-14 (в): Р2 обязана объявлять %q доступным в положении подтверждения", path)

	// Шаг, названный текстом: предъявить код из письма.
	rc := h.post(t, s, path, map[string]any{"code": k, "csrfToken": h.token(s, avFormConfirm)})
	require.Equal(t, http.StatusOK, rc.status, "EV-14: шаг, названный отказом, — 200: %s", rc.body)
	verified, ok := sessionEmailVerified(t, rc.body)
	require.True(t, ok && verified, "EV-14: session.emailVerified = true: %s", rc.body)
	b2 := cookieNamed(rc.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, b2, "EV-14: шаг выдал новый носитель")

	// (б) — близнец: то же обращение после шага проходит.
	after := s
	after.bearer = b2
	rb := change(after)
	require.Equal(t, http.StatusOK, rb.status, "EV-14 (б): после шага смена пароля — 200: %s", rb.body)
	require.NotContains(t, rb.body, "EMAIL_NOT_VERIFIED", "EV-14 (б): отказа положения нет")
	require.Equal(t, http.StatusOK, h.loginReply(t, s.email, fresh).status, "EV-14 (б): пароль сменён")
}

// ev14StepPath — путь между `POST ` и `)` текста отказа; пусто, если выреза нет.
func ev14StepPath(text string) string {
	_, after, ok := strings.Cut(text, "POST ")
	if !ok {
		return ""
	}
	path, _, ok := strings.Cut(after, ")")
	if !ok {
		return ""
	}
	return path
}
