// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

// method_refusal_r12_test.go — KN-PACE-46 (б), (в), KN-PACE-28 (b) приёмки темпа
// церемонии, редакция 6, решение Р12 (PRO-Robotech/kaname#524): точка
// авторизации и метаданные отвечают на неверный метод формой решения R36 п. 3 —
// `405`, `Content-Type: application/json`, тело побайтово
// `{"code":12,"message":"method not allowed","details":[]}`, `Allow: GET`.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const r12WrongMethodBody = `{"code":12,"message":"method not allowed","details":[]}`

func requireR12(t *testing.T, rec *httptest.ResponseRecorder, allow, what string) {
	t.Helper()
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("%s: статус %d, ожидался 405", what, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("%s: Content-Type %q", what, got)
	}
	if got := rec.Header().Get("Allow"); got != allow {
		t.Errorf("%s: Allow %q, ожидался %q", what, got, allow)
	}
	if got := rec.Body.String(); got != r12WrongMethodBody {
		t.Errorf("%s: тело %q, ожидалось побайтово %q (Р12)", what, got, r12WrongMethodBody)
	}
}

func TestKNPACE46b_AuthorizeWrongMethodIsTheOneForm(t *testing.T) {
	a, _, _, _ := newTestAuthorize(t, directory{})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest(m, AuthorizePath, nil))
		requireR12(t, rec, http.MethodGet, m+" "+AuthorizePath)
	}
}

func TestKNPACE46c_DiscoveryWrongMethodIsTheOneForm(t *testing.T) {
	d, err := NewDiscovery(DiscoveryConfig{
		Issuer: "https://iam.example.test", AuthorizationEndpoint: "https://iam.example.test" + AuthorizePath,
		TokenEndpoint: "https://iam.example.test/iam/v1/token", GrantTypes: []string{"authorization_code"},
		Scopes: domain.CeremonyScopes(),
	})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, DiscoveryPath, nil))
	requireR12(t, rec, http.MethodGet, "POST "+DiscoveryPath)

	// Близнец: GET — 200, метаданные (LINE-A-1-22).
	get := httptest.NewRecorder()
	d.ServeHTTP(get, httptest.NewRequest(http.MethodGet, DiscoveryPath, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("близнец GET: %d", get.Code)
	}
}
