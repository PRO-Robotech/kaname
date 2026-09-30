// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Пробы резолва АДМИНИСТРАТИВНОГО адреса поставщика здесь больше нет: дорога
// снята вместе с посадкой поставщика (kaname#363), и резолвера у неё нет.

// derivedTokenEndpoint — адрес обмена, который продукт ВЫВОДИТ из домена, когда
// ни поле, ни переменная издателя не заданы (`ResolveProviderIssuer`, authn.go).
// Это значение печатает продукт, и проба называет его литералом, а не собирает
// из того же построения: собранное, оно зеленело бы при любом умолчании.
const derivedTokenEndpoint = "https://hydra.access.example.invalid/oauth2/token"

// TestResolveProviderTokenURL_DefaultAndOverride — the shim's POST target
// defaults to the external issuer's token endpoint, and honors
// ProviderExchangeURLEnv for the provider's cluster-internal public Service.
func TestResolveProviderTokenURL_DefaultAndOverride(t *testing.T) {
	c := config.AuthNConfig{Domain: "access.example.invalid"}
	if got := c.ResolveProviderTokenURL(); got != derivedTokenEndpoint {
		t.Fatalf("default ResolveProviderTokenURL() = %q", got)
	}
	t.Setenv(config.ProviderExchangeURLEnv, "http://kacho-umbrella-provider-public.kacho.svc:4444/oauth2/token")
	if got := c.ResolveProviderTokenURL(); got != "http://kacho-umbrella-provider-public.kacho.svc:4444/oauth2/token" {
		t.Fatalf("override ResolveProviderTokenURL() = %q", got)
	}
}

// TestResolveProviderTokenEndpoint_ExternalIssuerTokenEndpoint — the
// client_assertion audience stays the EXTERNAL issuer's token endpoint (what the
// provider recognises), regardless of the cluster-internal POST target.
func TestResolveProviderTokenEndpoint_ExternalIssuerTokenEndpoint(t *testing.T) {
	c := config.AuthNConfig{Domain: "access.example.invalid"}
	if got := c.ResolveProviderTokenEndpoint(); got != derivedTokenEndpoint {
		t.Fatalf("ResolveProviderTokenEndpoint() = %q; want external issuer token endpoint", got)
	}
}

// TestResolveProviderIssuer_EnvOverride — ProviderIssuerEnv points iam at the
// ACTUAL provider issuer when it differs from the one derived from the domain.
// The shim's client_assertion audience (ResolveProviderTokenEndpoint) is derived
// from the issuer, and the provider rejects the exchange invalid_client if it
// doesn't match its real issuer — so the env override must reach both resolvers.
func TestResolveProviderIssuer_EnvOverride(t *testing.T) {
	t.Setenv(config.ProviderIssuerEnv, "http://localhost:28080/provider/public/")
	c := config.AuthNConfig{}
	if got := c.ResolveProviderIssuer(); got != "http://localhost:28080/provider/public/" {
		t.Fatalf("ResolveProviderIssuer() = %q; want env override", got)
	}
	if got := c.ResolveProviderTokenEndpoint(); got != "http://localhost:28080/provider/public/oauth2/token" {
		t.Fatalf("ResolveProviderTokenEndpoint() = %q; want issuer-derived endpoint", got)
	}
}

// TestResolveProviderIssuer_FieldWinsOverEnv — an explicit config field takes
// precedence over the env (field → env → derived).
func TestResolveProviderIssuer_FieldWinsOverEnv(t *testing.T) {
	t.Setenv(config.ProviderIssuerEnv, "http://env.example/")
	c := config.AuthNConfig{ProviderIssuer: "https://field.example/"}
	if got := c.ResolveProviderIssuer(); got != "https://field.example/" {
		t.Fatalf("ResolveProviderIssuer() = %q; want field override", got)
	}
}
