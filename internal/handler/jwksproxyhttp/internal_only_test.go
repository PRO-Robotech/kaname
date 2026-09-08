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

// RJU-06 — internal-only lock: the /.well-known/jwks.json route is served ONLY by
// the jwks-proxy mux (mounted on the cluster-INTERNAL :9097 listener), and is NOT
// reachable on the EXTERNAL registry-token mux (:9096). Publishing JWKS on an
// external-reachable surface would regress ban #6.
func TestJWKSProxy_RJU06_NotOnExternalRegistryTokenMux(t *testing.T) {
	// External registry-token mux (docker clients hit /iam/token through the edge).
	externalMux := registrytokenhttp.NewMux(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, jwksproxyhttp.WellKnownJWKSPath, nil)
	externalMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("external registry-token mux served %s → %d; want 404 (route must be internal-only, ban #6)",
			jwksproxyhttp.WellKnownJWKSPath, rec.Code)
	}

	// The dedicated jwks-proxy mux DOES route the well-known path to the handler.
	//
	// Маршрут монтируется теперь ОБЪЯВЛЕННОЙ привязкой «издатель → путь»
	// (записей больше одной, см. binding.go). Утверждение то же самое; изменился
	// способ, каким путь попадает в mux, и это ровно то, что требовалось: перечень
	// путей выводится из привязки, а не выписывается по месту.
	binding, err := jwksproxyhttp.NewBinding([]jwksproxyhttp.Record{{
		Issuer:  "https://provider.kacho.local",
		Path:    jwksproxyhttp.WellKnownJWKSPath,
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
	req = httptest.NewRequest(http.MethodGet, jwksproxyhttp.WellKnownJWKSPath, nil)
	jwksMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Fatalf("jwks-proxy mux did not route %s to its handler (got %d)",
			jwksproxyhttp.WellKnownJWKSPath, rec.Code)
	}
}
