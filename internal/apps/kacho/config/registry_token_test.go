// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestRegistryTokenListenAddress_Default — the Docker Registry v2 `/iam/token`
// auth-server listens on a SEPARATE external-reachable port (default :9096),
// distinct from the public/internal gRPC surfaces and the metrics listener.
func TestRegistryTokenListenAddress_Default(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tok := cfg.APIServer.RegistryToken
	if got := tok.ListenAddress(); got != "0.0.0.0:9096" {
		t.Fatalf("ListenAddress() = %q, want 0.0.0.0:9096", got)
	}
	if tok.ListenAddress() == cfg.APIServer.ListenAddress() {
		t.Error("registry token listener must not share the public gRPC port")
	}
	if tok.ListenAddress() == cfg.APIServer.InternalListenAddress() {
		t.Error("registry token listener must not share the internal gRPC port")
	}
	if tok.ListenAddress() == cfg.APIServer.MetricsListenAddress() {
		t.Error("registry token listener must not share the metrics port")
	}
}

// TestRegistryTokenPolicy_Defaults — the minted identity-JWT policy defaults
// (issuer + audience/service + TTL) match the data-plane's advertised realm.
func TestRegistryTokenPolicy_Defaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tok := cfg.APIServer.RegistryToken
	if got := tok.TokenIssuer(); got != "https://api.kacho.local/iam/token" {
		t.Errorf("TokenIssuer() = %q, want https://api.kacho.local/iam/token", got)
	}
	if got := tok.TokenService(); got != "registry.kacho.local" {
		t.Errorf("TokenService() = %q, want registry.kacho.local", got)
	}
	if got := tok.TokenTTL(); got != 5*time.Minute {
		t.Errorf("TokenTTL() = %s, want 5m", got)
	}
}

// TestRegistryTokenConfig_AccessorFallbacks — the accessors fall back to the
// built-in policy defaults on an unset struct (independent of viper), and
// normalise the endpoint like every other listener.
func TestRegistryTokenConfig_AccessorFallbacks(t *testing.T) {
	t.Parallel()
	var empty config.RegistryTokenConfig
	if got := empty.TokenIssuer(); got != "https://api.kacho.local/iam/token" {
		t.Errorf("empty TokenIssuer() = %q, want default issuer", got)
	}
	if got := empty.TokenService(); got != "registry.kacho.local" {
		t.Errorf("empty TokenService() = %q, want default service", got)
	}
	if got := empty.TokenTTL(); got != 5*time.Minute {
		t.Errorf("empty TokenTTL() = %s, want 5m", got)
	}
	if got := empty.ListenAddress(); got != "" {
		t.Errorf("empty ListenAddress() = %q, want empty (disabled)", got)
	}

	c := config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:7100"}
	if got := c.ListenAddress(); got != "0.0.0.0:7100" {
		t.Errorf("ListenAddress() = %q, want 0.0.0.0:7100", got)
	}
	c2 := config.RegistryTokenConfig{Endpoint: "7200"}
	if got := c2.ListenAddress(); got != ":7200" {
		t.Errorf("ListenAddress() = %q, want :7200", got)
	}
}
