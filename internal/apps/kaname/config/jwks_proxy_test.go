// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

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
