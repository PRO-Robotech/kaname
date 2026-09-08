// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
)

// TestRegistryTokenListener_ConfiguredSeparatePort — the composition root must
// expose the Docker Registry v2 `/iam/token` auth-server on its OWN
// external-reachable port (default :9096), never sharing the public/internal
// gRPC surfaces or the cluster-internal hooks (:9092) / metrics (:9095)
// listeners. Behavioural check against the loaded config.
func TestRegistryTokenListener_ConfiguredSeparatePort(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	tok := cfg.APIServer.RegistryToken
	addr := tok.ListenAddress()
	if addr == "" {
		t.Fatal("registry token listener disabled by default — docker login has no token endpoint")
	}
	for name, other := range map[string]string{
		"public gRPC":   cfg.APIServer.ListenAddress(),
		"internal gRPC": cfg.APIServer.InternalListenAddress(),
		"hooks HTTP":    cfg.AuthN.HooksHTTPListenAddress(),
		"metrics HTTP":  cfg.APIServer.MetricsListenAddress(),
	} {
		if addr == other {
			t.Errorf("registry token addr %q == %s addr — must be a separate port", addr, name)
		}
	}
	if got := tok.TokenIssuer(); got != "https://api.kacho.local/iam/token" {
		t.Errorf("TokenIssuer() = %q, want https://api.kacho.local/iam/token", got)
	}
	// АДРЕСАТ УМОЛЧАНИЯ НЕ ИМЕЕТ (задача #1184): имя службы реестра объявляет
	// посадка ОДИН раз на обе стороны полосы (`global.kacho.registry.serviceAud`),
	// и здесь оно не задано. Прежде проба закрепляла встроенное умолчание — то
	// самое второе объявление предмета, которое молча расходилось с именем,
	// объявленным реестром.
	if got := tok.TokenService(); got != "" {
		t.Errorf("TokenService() = %q, want empty (адресат объявляет посадка, а не код)", got)
	}
	if got := tok.TokenTTL(); got != 5*time.Minute {
		t.Errorf("TokenTTL() = %s, want 5m", got)
	}
}

// TestServeWiresRegistryTokenListener — composition-root guard. serve.go must
// (1) build the token mux via registrytokenwire.Build from the config policy,
// (2) stand up the token HTTP listener, and (3) drain it in the shared shutdown
// chain.
//
// RED-demonstration: drop the registrytokenwire.Build / token listener from
// serve.go → this test fails before merge.
func TestServeWiresRegistryTokenListener(t *testing.T) {
	src := readFileT(t, "serve.go")
	for _, want := range []string{
		"registrytokenwire.Build(",
		"cfg.APIServer.RegistryToken.ListenAddress()",
		"cfg.APIServer.RegistryToken.TokenIssuer()",
		"cfg.APIServer.RegistryToken.TokenService()",
		"cfg.AuthN.ResolveHydraTokenURL()",
		// The anchor of the hop travels with its address: a root that passes one
		// without the other is how https ends up verified against the system roots.
		"cfg.AuthN.ResolveHydraTokenCAFile()",
		"cfg.AuthN.ResolveHydraTokenEndpoint()",
		// Подъём, гашение и строка самоотчёта переехали в профиль не-gRPC
		// поверхности: докладывает о себе она сама, и доклад несёт то, чего прежняя
		// строка не несла никогда, — досягаемость и решение об аутентификации.
		// Свойство утверждает `TestIAMSurfacesServeAndReleaseTheirPorts`.
		"servicehost.ServeSurface(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: missing registry token wiring %q", want)
		}
	}
}

// TestRegistryTokenMux_ChallengesAnonymousWithConfiguredRealm — end-to-end proof
// that the config policy flows into the minted challenge: the mux serve.go builds
// answers an anonymous /iam/token with 401 + a WWW-Authenticate carrying the
// CONFIGURED issuer-realm and the DECLARED lane addressee (умолчания у него нет). No DB is required — the challenge
// precedes any DB-backed validator/signer call, so a nil pool is safe here.
func TestRegistryTokenMux_ChallengesAnonymousWithConfiguredRealm(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	tok := cfg.APIServer.RegistryToken

	// Адресат ОБЪЯВЛЯЕТСЯ здесь, а не берётся из умолчания: умолчания у него нет,
	// и сборка полосы на пустом отказывает (это её собственный страж). Значение
	// произвольно — проба утверждает про вызов на аутентификацию, а не про имя.
	const laneService = "registry.probe.local"

	mux, err := registrytokenwire.Build(nil, registrytokenwire.BuildConfig{
		Realm:             tok.TokenIssuer(),
		Service:           laneService,
		HydraTokenURL:     cfg.AuthN.ResolveHydraTokenURL(),
		AssertionAudience: cfg.AuthN.ResolveHydraTokenEndpoint(),
	})
	if err != nil {
		t.Fatalf("registrytokenwire.Build: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/token", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /iam/token (no Basic) status = %d, want 401", rec.Code)
	}
	ch := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(ch, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", ch)
	}
	if !strings.Contains(ch, `realm="https://api.kacho.local/iam/token"`) {
		t.Errorf("WWW-Authenticate = %q, want realm from the configured issuer", ch)
	}
	if !strings.Contains(ch, `service="`+laneService+`"`) {
		t.Errorf("WWW-Authenticate = %q, want service from the declared lane addressee %q", ch, laneService)
	}
}
