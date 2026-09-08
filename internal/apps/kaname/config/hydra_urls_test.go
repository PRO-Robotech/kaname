// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// TestResolveHydraAdminURL_DerivesByDefault — with no override, the admin URL is
// derived from the issuer (hydra.X → hydra-admin.X), preserving back-compat.
func TestResolveHydraAdminURL_DerivesByDefault(t *testing.T) {
	// Домен объявлен ЯВНО: умолчания у него нет (задача #2127), и предмет этой
	// пробы — ДЕРИВАЦИЯ, а не умолчание. Прежде фикстура была нулевой и молча
	// опиралась на подставленное построением имя чужого продукта.
	c := config.AuthNConfig{Domain: "access.example.invalid"} // issuer https://hydra.<domain>
	if got := c.ResolveHydraAdminURL(); got != "https://hydra-admin.access.example.invalid" {
		t.Fatalf("ResolveHydraAdminURL() = %q; want derived hydra-admin.<domain>", got)
	}
}

// TestResolveHydraAdminURL_EnvOverride — KANAME_HYDRA_ADMIN_URL points iam at
// the cluster-internal admin Service when the external issuer would not resolve
// in-cluster (fix for the "hydra publish failed" wiring gap).
func TestResolveHydraAdminURL_EnvOverride(t *testing.T) {
	t.Setenv("KANAME_HYDRA_ADMIN_URL", "http://kacho-umbrella-hydra-admin.kacho.svc:4445")
	c := config.AuthNConfig{}
	if got := c.ResolveHydraAdminURL(); got != "http://kacho-umbrella-hydra-admin.kacho.svc:4445" {
		t.Fatalf("ResolveHydraAdminURL() = %q; want the env override", got)
	}
}

// TestResolveHydraAdminURL_FieldOverride — an explicit config field wins over the
// derivation (and over the env, which is unset here).
func TestResolveHydraAdminURL_FieldOverride(t *testing.T) {
	c := config.AuthNConfig{HydraAdminURL: "http://admin.internal:4445"}
	if got := c.ResolveHydraAdminURL(); got != "http://admin.internal:4445" {
		t.Fatalf("ResolveHydraAdminURL() = %q; want field override", got)
	}
}

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

// TestResolveHydraIssuer_EnvOverride — KANAME_HYDRA_ISSUER points iam at the
// ACTUAL Hydra issuer when it differs from the derived hydra.<domain>. The shim's
// client_assertion audience (ResolveHydraTokenEndpoint) is derived from the issuer,
// and Hydra rejects the exchange invalid_client if it doesn't match Hydra's real
// issuer — so the env override must reach both resolvers.
func TestResolveHydraIssuer_EnvOverride(t *testing.T) {
	t.Setenv("KANAME_HYDRA_ISSUER", "http://localhost:28080/.ory/hydra/public/")
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
	t.Setenv("KANAME_HYDRA_ISSUER", "http://env.example/")
	c := config.AuthNConfig{HydraIssuer: "https://field.example/"}
	if got := c.ResolveHydraIssuer(); got != "https://field.example/" {
		t.Fatalf("ResolveHydraIssuer() = %q; want field override", got)
	}
}
