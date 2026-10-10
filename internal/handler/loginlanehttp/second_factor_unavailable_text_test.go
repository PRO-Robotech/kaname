// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_unavailable_text_test.go — недоступность материала второго
// фактора называет шаг человека, а не «позже» (PRO-Robotech/kaname#258 п. 2;
// Ф12 Р2, редакции 16–17). Текст — литералом из приёмки.
package loginlanehttp_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// stepSecondFactorUnavailable — Ф12 Р2: материал не открывается; дословно.
const stepSecondFactorUnavailable = "second factor cannot be verified; ask the administrator of this installation"

// TestLane_F12_35_UnavailableNamesTheOperatorStep — Ф12-35 (в), (г) на
// транспорте: `503` / `14` текстом Р2, без `Retry-After`; ни «позже», ни класса
// причины. Текст один на все глаголы сверки кода — вход, step-up, подтверждение.
func TestLane_F12_35_UnavailableNamesTheOperatorStep(t *testing.T) {
	stub := &stubLane{
		loginErr:   humansession.ErrSecondFactorUnavailable,
		stepUpErr:  humansession.ErrSecondFactorUnavailable,
		confirmErr: humansession.ErrSecondFactorUnavailable,
	}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	loginTok, loginCk := l.csrf(t, c, "login", nil)
	login := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, map[string]any{
		"email": "a@example.invalid", "password": "pw", "csrfToken": loginTok,
		"secondFactor": map[string]string{"method": "totp", "code": "123456"},
	}, fwd(), loginCk)
	require.Equal(t, http.StatusServiceUnavailable, login.status, login.body)
	require.Equal(t, refusalWire(14, stepSecondFactorUnavailable), login.body, "Ф12-35: текст Р2 дословно")
	require.Empty(t, login.header.Get("Retry-After"), "повтор ничего не восстановит — срока нет")

	suTok, suCk := l.csrf(t, c, "step-up", loginCk)
	stepUp := l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": suTok}, fwd(), suCk, sess)
	require.Equal(t, http.StatusServiceUnavailable, stepUp.status)
	require.Equal(t, login.body, stepUp.body, "текст один на глаголы и способы")
	require.Empty(t, stepUp.header.Get("Retry-After"))

	requireNamesNoCause(t, stepSecondFactorUnavailable,
		"temporarily", "try again", "later", "key", "wrap", "secret", "material", "decrypt", "encrypt")
}
