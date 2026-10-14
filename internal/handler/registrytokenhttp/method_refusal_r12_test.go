// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenhttp

// method_refusal_r12_test.go — KN-PACE-46 (г) приёмки темпа церемонии,
// редакция 6, решение Р12 (PRO-Robotech/kaname#524): полоса реестра образов
// отвечает на неверный метод формой решения R36 п. 3 — `405`,
// `Content-Type: application/json`, тело побайтово
// `{"code":12,"message":"method not allowed","details":[]}`, `Allow: GET, POST`.
// Прежде — `text/plain` с телом `{"error":"method_not_allowed"}`.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const r12WrongMethodBody = `{"code":12,"message":"method not allowed","details":[]}`

func TestKNPACE46d_RegistryTokenWrongMethodIsTheOneForm(t *testing.T) {
	for _, m := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		rec := httptest.NewRecorder()
		newTokenHandler(&fakeIssuer{}).ServeHTTP(rec, httptest.NewRequest(m, "/iam/token", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: статус %d, ожидался 405", m, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("%s: Content-Type %q", m, got)
		}
		if got := rec.Header().Get("Allow"); got != "GET, POST" {
			t.Errorf("%s: Allow %q", m, got)
		}
		if got := rec.Body.String(); got != r12WrongMethodBody {
			t.Errorf("%s: тело %q, ожидалось побайтово %q (Р12)", m, got, r12WrongMethodBody)
		}
	}
	// Близнец: GET без удостоверения — не 405, а отказ полосы реестра (401).
	rec := httptest.NewRecorder()
	newTokenHandler(&fakeIssuer{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil))
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("близнец GET получил 405")
	}
}
