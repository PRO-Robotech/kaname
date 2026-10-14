// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_next_step_integration_test.go — DoD Ф5 редакции 10, пп. 1–2
// (PRO-Robotech/kaname#211): на слушателе над НАСТОЯЩИМИ глаголами и базой
// ответ запроса кода на трёх исходах — подтверждённый адрес, адреса нет,
// неподтверждённый адрес личности с паролем — побайтово один и несёт
// `nextStep` с текстом Р10 п. 1 дословно; отказ завершения — текст Р10 п. 2 на
// любой причине, побайтово один.
//
// Транспортная проба с дублёром (recovery_registration_next_step_test.go)
// зеленела бы при любом исходе глагола; здесь исходы рождает вариант
// использования, и равенство тел сказано о настоящих ветвях.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run Integration -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

func TestLaneIntegration_F5_01_02_RequestNamesTheStepOnEveryOutcome(t *testing.T) {
	h := newAVLane(t)
	verified := h.register(t, freshAddress("ns-verified"))
	h.mark(t, verified)
	unverified := h.register(t, freshAddress("ns-unverified")) // пароль есть, адрес не подтверждён
	nobody := freshAddress("ns-nobody")

	request := func(email string) (reply, *http.Cookie) {
		tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery,
			map[string]any{"email": email, "csrfToken": tok}, fwd(), ctxCk), ctxCk
	}
	want, err := json.Marshal(map[string]string{"nextStep": stepRecoveryRequest})
	require.NoError(t, err)

	rv, ctxV := request(verified.email)
	require.Equal(t, http.StatusOK, rv.status, rv.body)
	require.Equal(t, string(want), rv.body, "подтверждённый адрес: тело ровно {nextStep}")
	require.Empty(t, rv.cookies)
	for name, email := range map[string]string{"адреса нет": nobody, "адрес не подтверждён у личности с паролем": unverified.email} {
		r, _ := request(email)
		require.Equal(t, rv.status, r.status, name)
		require.Equal(t, rv.body, r.body, "%s: побайтово тот же ответ (Р2)", name)
		require.Empty(t, r.cookies, name)
	}

	// Отказ завершения: неверный код у существующего адреса и любой код у
	// адреса, которого нет, — один текст Р10 п. 2, побайтово.
	complete := func(email string, ctxCk *http.Cookie) reply {
		ctok, ctx2 := h.lane.csrf(t, h.c, string(domain.FormRecoveryComplete), ctxCk)
		return h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
			"email": email, "code": "AAAAA-AAAAA", "newPassword": "brand-new-password-ns", "csrfToken": ctok,
		}, fwd(), ctx2)
	}
	wrong := complete(verified.email, ctxV)
	require.Equal(t, http.StatusUnauthorized, wrong.status, wrong.body)
	require.Equal(t, refusalWire(16, stepRecoveryRefused), wrong.body, "Ф5-04: текст Р10 п. 2 дословно")
	require.Empty(t, wrong.cookies, "без Set-Cookie")
	_, ctxN := request(nobody)
	none := complete(nobody, ctxN)
	require.Equal(t, wrong.status, none.status)
	require.Equal(t, wrong.body, none.body, "адреса нет — тот же отказ, побайтово")
}
