// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestResolveHydraJWKSURL_Precedence — the internal JWKS-proxy upstream mirrors the
// KACHO_IAM_HYDRA_TOKEN_URL precedence (authn.go): explicit field → env
// KACHO_IAM_HYDRA_JWKS_URL (cluster-internal hydra-public) → derived
// ResolveHydraIssuer()+"/.well-known/jwks.json" (back-compat).
func TestResolveHydraJWKSURL_Precedence(t *testing.T) {
	// Default: derived from the Hydra issuer's well-known path.
	c := config.AuthNConfig{}
	if got := c.ResolveHydraJWKSURL(); got != "https://hydra.api.kacho.cloud/.well-known/jwks.json" {
		t.Fatalf("default ResolveHydraJWKSURL() = %q; want derived issuer well-known", got)
	}

	// Env override: the cluster-internal hydra-public Service (mirror of the token URL).
	t.Setenv("KACHO_IAM_HYDRA_JWKS_URL", "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json")
	if got := c.ResolveHydraJWKSURL(); got != "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json" {
		t.Fatalf("env-override ResolveHydraJWKSURL() = %q; want the cluster-internal URL", got)
	}

	// Explicit field wins over env.
	c2 := config.AuthNConfig{HydraJWKSURL: "http://explicit:4444/.well-known/jwks.json"}
	if got := c2.ResolveHydraJWKSURL(); got != "http://explicit:4444/.well-known/jwks.json" {
		t.Fatalf("field-override ResolveHydraJWKSURL() = %q; want the explicit field", got)
	}
}

// TestJWKSProxyListenAddress — the api-server.jwks-proxy.endpoint normalises like
// the other listeners; empty disables it.
func TestJWKSProxyListenAddress(t *testing.T) {
	c := config.APIServerConfig{JWKSProxy: config.JWKSProxyConfig{Endpoint: "tcp://0.0.0.0:9097"}}
	if got := c.JWKSProxy.ListenAddress(); got != "0.0.0.0:9097" {
		t.Fatalf("JWKSProxy.ListenAddress() = %q; want 0.0.0.0:9097", got)
	}
	if got := (config.JWKSProxyConfig{}).ListenAddress(); got != "" {
		t.Fatalf("empty endpoint ListenAddress() = %q; want empty (disabled)", got)
	}
}

// TestJWKSProxyServerTLSConfig_DefaultOffPlaintext — the jwks-proxy HTTP TLS edge is
// per-edge opt-in: default-off (Enable=false) → (nil, nil), listener stays plaintext
// (dev byte-identical), mirroring the hooks/metrics HTTP edges.
func TestJWKSProxyServerTLSConfig_DefaultOffPlaintext(t *testing.T) {
	m := config.MTLSConfig{}
	cfg, err := m.JWKSProxyServerTLSConfig()
	if err != nil {
		t.Fatalf("default-off JWKSProxyServerTLSConfig() err = %v; want nil", err)
	}
	if cfg != nil {
		t.Fatalf("default-off JWKSProxyServerTLSConfig() = %v; want nil (plaintext)", cfg)
	}
}
