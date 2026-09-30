// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package jwksproxyhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
)

// ownKeySetPath — путь нашей записи по умолчанию (`authn.token-signing.key-set-path`).
const ownKeySetPath = "/.well-known/kaname/jwks.json"

// RJU-06 — internal-only lock: the key-set route is served ONLY by the publisher
// mux (mounted on the cluster-INTERNAL :9097 listener), and is NOT reachable on
// the EXTERNAL registry-token mux (:9096). Publishing the key set on an
// external-reachable surface would regress ban #6.
func TestJWKSProxy_RJU06_NotOnExternalRegistryTokenMux(t *testing.T) {
	// External registry-token mux (docker clients hit /iam/token through the edge).
	externalMux := registrytokenhttp.NewMux(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, ownKeySetPath, nil)
	externalMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("external registry-token mux served %s → %d; want 404 (route must be internal-only, ban #6)",
			ownKeySetPath, rec.Code)
	}

	// The dedicated publisher mux DOES route the key-set path to its handler.
	//
	// Маршрут монтируется ОБЪЯВЛЕННОЙ привязкой «издатель → путь»: путь
	// выводится из привязки, а не выписывается по месту.
	binding, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{{
		Issuer:  "https://kaname.kacho.local",
		Path:    ownKeySetPath,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }),
	}})
	if err != nil {
		t.Fatalf("законная привязка обязана строиться: %v", err)
	}
	jwksMux, err := jwksproxyhttp.NewMux(binding)
	if err != nil {
		t.Fatalf("mux по законной привязке обязан строиться: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, ownKeySetPath, nil)
	jwksMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("publisher mux did not route %s to its handler (got %d)", ownKeySetPath, rec.Code)
	}
}
