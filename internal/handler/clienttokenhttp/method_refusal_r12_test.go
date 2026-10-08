// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clienttokenhttp_test

// method_refusal_r12_test.go — KN-PACE-46 (а), KN-PACE-10 (а) приёмки темпа
// церемонии, редакция 6, решение Р12 (PRO-Robotech/kaname#524): неверный метод
// на токен-эндпоинте отвечает ФОРМОЙ решения R36 п. 3 — той же, что у полосы
// входа и REST-фронта службы: `405`, `Content-Type: application/json`, тело
// побайтово `{"code":12,"message":"method not allowed","details":[]}`,
// `Allow: POST`.
//
// Тело — литерал из приёмки, а не константа производителя: утверждение «равно
// константе» зеленело бы при любом её значении, в том числе при прежнем
// `{"error":"invalid_request"}`.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

const r12WrongMethodBody = `{"code":12,"message":"method not allowed","details":[]}`

func TestKNPACE46a_TokenEndpointWrongMethodIsTheOneForm(t *testing.T) {
	s := newStand(t)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		s.h.ServeHTTP(rec, httptest.NewRequest(m, clienttokenhttp.TokenPath, nil))
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, "метод %s", m)
		require.Equal(t, "application/json", rec.Header().Get("Content-Type"), "метод %s", m)
		require.Equal(t, http.MethodPost, rec.Header().Get("Allow"), "метод %s", m)
		require.Equal(t, r12WrongMethodBody, rec.Body.String(), "метод %s: тело формы Р12 побайтово", m)
	}
	// Близнец: допустимый метод с годной формой — не 405 (KN-PACE-02 форма).
	require.NotEqual(t, http.StatusMethodNotAllowed, s.post(t, goodForm()).Code)
}

// requireMethodRefusal — форма Р12 на токен-эндпоинте: держатель строк а
// KN-PACE-10 и KN-PACE-25 (прежде — `{"error":"invalid_request"}`).
func requireMethodRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code, "тело %q", rec.Body.String())
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
	require.Equal(t, r12WrongMethodBody, rec.Body.String(), "форма Р12 побайтово")
}
