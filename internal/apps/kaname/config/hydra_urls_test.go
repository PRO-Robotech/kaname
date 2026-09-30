// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Пробы резолва АДМИНИСТРАТИВНОГО адреса поставщика здесь больше нет: дорога
// снята вместе с посадкой поставщика (kaname#363), и резолвера у неё нет.

// TestResolveHydraTokenURL_DefaultAndOverride — the shim's POST target defaults to
// the external issuer's token endpoint, and honors KANAME_HYDRA_TOKEN_URL for
// the cluster-internal Hydra public Service.
func TestResolveHydraTokenURL_DefaultAndOverride(t *testing.T) {
	c := config.AuthNConfig{Domain: "access.example.invalid"}
	if got := c.ResolveHydraTokenURL(); got != "https://hydra.access.example.invalid/oauth2/token" {
		t.Fatalf("default ResolveHydraTokenURL() = %q", got)
	}
	t.Setenv("KANAME_HYDRA_TOKEN_URL", "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token")
	if got := c.ResolveHydraTokenURL(); got != "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token" {
		t.Fatalf("override ResolveHydraTokenURL() = %q", got)
	}
}

// TestResolveHydraTokenEndpoint_ExternalIssuerTokenEndpoint — the client_assertion
// audience stays the EXTERNAL issuer's token endpoint (what Hydra recognises),
// regardless of the cluster-internal POST target.
func TestResolveHydraTokenEndpoint_ExternalIssuerTokenEndpoint(t *testing.T) {
	c := config.AuthNConfig{Domain: "access.example.invalid"}
	if got := c.ResolveHydraTokenEndpoint(); got != "https://hydra.access.example.invalid/oauth2/token" {
		t.Fatalf("ResolveHydraTokenEndpoint() = %q; want external issuer token endpoint", got)
	}
}

// TestResolveHydraIssuer_EnvOverride — ProviderIssuerEnv (`KANAME_HYDRA_ISSUER`)
// points iam at the ACTUAL Hydra issuer when it differs from the derived
// hydra.<domain>. The shim's
// client_assertion audience (ResolveHydraTokenEndpoint) is derived from the issuer,
// and Hydra rejects the exchange invalid_client if it doesn't match Hydra's real
// issuer — so the env override must reach both resolvers.
func TestResolveHydraIssuer_EnvOverride(t *testing.T) {
	t.Setenv(config.ProviderIssuerEnv, "http://localhost:28080/.ory/hydra/public/")
	c := config.AuthNConfig{}
	if got := c.ResolveHydraIssuer(); got != "http://localhost:28080/.ory/hydra/public/" {
		t.Fatalf("ResolveHydraIssuer() = %q; want env override", got)
	}
	if got := c.ResolveHydraTokenEndpoint(); got != "http://localhost:28080/.ory/hydra/public/oauth2/token" {
		t.Fatalf("ResolveHydraTokenEndpoint() = %q; want issuer-derived endpoint", got)
	}
}

// TestResolveHydraIssuer_FieldWinsOverEnv — an explicit config field takes
// precedence over the env (field → env → derived).
func TestResolveHydraIssuer_FieldWinsOverEnv(t *testing.T) {
	t.Setenv(config.ProviderIssuerEnv, "http://env.example/")
	c := config.AuthNConfig{HydraIssuer: "https://field.example/"}
	if got := c.ResolveHydraIssuer(); got != "https://field.example/" {
		t.Fatalf("ResolveHydraIssuer() = %q; want field override", got)
	}
}
