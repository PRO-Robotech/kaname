// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package methodrefusal_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/methodrefusal"
)

// TestWriteIsTheOneForm — форма R36 п. 3 / Р12: статус, тип, Allow и тело
// побайтово. Тело — литерал решения, а не константа пакета: утверждение «равно
// константе» зеленело бы при любом её значении.
func TestWriteIsTheOneForm(t *testing.T) {
	rec := httptest.NewRecorder()
	methodrefusal.Write(rec, http.MethodGet, http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("статус %d, ожидался 405", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q", got)
	}
	if got := rec.Header().Get("Allow"); got != "GET, POST" {
		t.Errorf("Allow %q", got)
	}
	if got, want := rec.Body.String(), `{"code":12,"message":"method not allowed","details":[]}`; got != want {
		t.Errorf("тело %q, ожидалось побайтово %q", got, want)
	}
}
