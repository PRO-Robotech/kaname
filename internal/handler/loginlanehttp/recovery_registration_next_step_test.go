// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_registration_next_step_test.go — отказы регистрации и
// восстановления называют следующий шаг, не называя причины
// (PRO-Robotech/kaname#211; Ф4 редакция 8, Ф5 редакции 10–11). Тексты —
// литералами из приёмок (почему — next_step_refusals_test.go).
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

const (
	// Ф5 Р10 п. 1: ответ запроса кода — один на все исходы.
	stepRecoveryRequest = "a letter with a recovery code is sent if this address can recover access; if no letter arrives, request again later, sign in and confirm the address, or ask an administrator to reset your sign-in methods"
	// Ф5 Р10 п. 2: отказ завершения — один на все причины глагола.
	stepRecoveryRefused = "access not restored; request a new recovery code, and if a new code does not restore access, ask an administrator"
	// Ф4 Р3, редакция 8: единый отказ регистрации.
	stepRegistrationRefused = "registration refused; if this address is already yours, sign in or recover access; if you were invited, ask an account administrator to invite again; otherwise try again later"
)

// TestLane_F5_01_02_RequestNamesTheNextStepWhateverTheOutcome — Ф5-01/02
// (редакция 10): ответ запроса кода — `200`, без печений, тело ровно
// `{"nextStep": <текст Р10 п. 1>}` — одно на любой исход; других полей нет.
func TestLane_F5_01_02_RequestNamesTheNextStepWhateverTheOutcome(t *testing.T) {
	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "recovery", nil)

	want, err := json.Marshal(map[string]string{"nextStep": stepRecoveryRequest})
	require.NoError(t, err)

	first := l.do(t, c, http.MethodPost, loginlanehttp.PathRecovery,
		map[string]string{"email": "a@example.invalid", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusOK, first.status, first.body)
	require.Equal(t, string(want), first.body, "Ф5-01: тело ровно {nextStep} с текстом Р10 п. 1")
	require.Empty(t, first.cookies)

	other := l.do(t, c, http.MethodPost, loginlanehttp.PathRecovery,
		map[string]string{"email": "nobody@example.invalid", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, first.status, other.status)
	require.Equal(t, first.body, other.body, "Ф5-02: побайтово тот же ответ")

	// Текст не утверждает, что письмо ОТПРАВЛЕНО: на половине исходов это была бы ложь.
	require.NotContains(t, strings.ToLower(stepRecoveryRequest), "was sent")
}

// TestLane_F5_04_CompletionRefusalNamesTheStepAndNoCause — Ф5-04/05/07/17
// (редакции 10–11): отказ завершения — `401` / `16`, `details` пусты, без
// `Set-Cookie`, текст Р10 п. 2 дословно; это НЕ текст отказа входа.
func TestLane_F5_04_CompletionRefusalNamesTheStepAndNoCause(t *testing.T) {
	stub := &stubLane{completeErr: humansession.ErrAccessNotRestored}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "recovery-complete", nil)
	form := map[string]string{"email": "a@example.invalid", "code": "ABCDE-FGHJK", "newPassword": "brand-new-password", "csrfToken": tok}

	r := l.do(t, c, http.MethodPost, loginlanehttp.PathRecoveryComplete, form, nil, ctxCk)
	require.Equal(t, http.StatusUnauthorized, r.status, r.body)
	require.Equal(t, refusalWire(16, stepRecoveryRefused), r.body, "Ф5-04: текст Р10 п. 2 дословно")
	require.Empty(t, r.cookies, "без Set-Cookie")
	require.NotEqual(t, refusalWire(16, "authentication failed"), r.body, "текст свой у глагола, а не отказа входа (Д22)")
	requireNamesNoCause(t, stepRecoveryRefused, "expired", "used", "invalid", "blocked", "wrong", "not found")

	again := l.do(t, c, http.MethodPost, loginlanehttp.PathRecoveryComplete, form, nil, ctxCk)
	require.Equal(t, r.body, again.body, "Ф5-05: тело и код побайтово равны")
}

// TestLane_F4_11_RegistrationRefusalNamesTheStepAndNoCause — Ф4-11 (редакция 8):
// `400`, `code` `9`, `reason = REGISTRATION_REFUSED`, текст Р3 дословно, без
// `Retry-After`; ни одной цифры и ни одного слова причины либо величины.
func TestLane_F4_11_RegistrationRefusalNamesTheStepAndNoCause(t *testing.T) {
	stub := &stubLane{registerErr: registration.ErrRefused}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "register", nil)
	form := map[string]string{"email": "a@example.invalid", "password": "correct-horse-battery-staple-9", "csrfToken": tok}

	r := l.do(t, c, http.MethodPost, loginlanehttp.PathRegister, form, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	var body struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Reason string `json:"reason"`
		} `json:"details"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.Equal(t, 9, body.Code)
	require.Equal(t, stepRegistrationRefused, body.Message, "Ф4-11: текст Р3 дословно")
	require.Len(t, body.Details, 1)
	require.Equal(t, "REGISTRATION_REFUSED", body.Details[0].Reason)
	require.Empty(t, r.header.Get("Retry-After"))
	require.False(t, regexp.MustCompile(`[0-9]`).MatchString(stepRegistrationRefused), "в тексте нет ни одной цифры")
	requireNamesNoCause(t, stepRegistrationRefused, "in use", "taken", "exists", "registered", "limit", "rate", "quota", "seconds")
}
