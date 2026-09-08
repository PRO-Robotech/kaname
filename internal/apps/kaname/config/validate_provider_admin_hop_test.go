// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// validate_provider_admin_hop_test.go — a production iam must not reach the
// identity provider's ADMIN API at a GUESSED address, nor in the clear.
//
// What rides this hop: iam is the platform's sole facade to the provider, so
// every OAuth2 client it registers for a personal token or a service-account key,
// every trust grant and every session teardown goes over it, carrying the
// administrative bearer. The provider's admin API authenticates nobody — reaching
// it IS the authorization — so both properties matter and for different reasons.
//
// The address was DERIVED from the issuer when unset ("hydra.X" → "hydra-admin.X",
// else "https://hydra-admin.<domain>"). A derived address is never empty, so the
// facade looked configured on every profile, including the ones that never
// declared it — the exact shape the platform rule about not deriving a
// security-relevant dependency address was written for.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// adminHopCfg — goodEndpoints plus the secrets production demands, so the
// provider-admin hop is the only variable left.
func adminHopCfg(mode config.Mode, adminURL string) config.Config {
	cfg := goodEndpoints(mode, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.HydraAdminURL = adminURL
	return cfg
}

// TLS with nothing to verify against is refused too — the provider's in-cluster
// certificate is internal-CA issued and this process trusts the system roots, so
// the hop would fail on an unknown authority while the address reads as hardened.
func TestValidate_Production_RefusesTLSProviderAdminURLWithoutAnchor(t *testing.T) {
	cfg := adminHopCfg(config.ModeProduction, "https://kacho-umbrella-hydra-admin.kacho.svc:4445")
	cfg.AuthN.HydraAdminCAFile = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal for an https hop with no pinned anchor")
	}
	if !strings.Contains(err.Error(), "hydra-admin-ca-file") {
		t.Fatalf("the refusal must name the anchor setting, got: %q", err.Error())
	}
}

// Production with the address left to derivation MUST be refused. Nothing else
// catches this: the derivation always yields a non-empty string, so the facade
// reports itself configured while addressing a host nobody chose.
func TestValidate_Production_RefusesDerivedProviderAdminURL(t *testing.T) {
	cfg := adminHopCfg(config.ModeProduction, "")
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal when the provider-admin address is derived")
	}
	if !strings.Contains(err.Error(), "hydra-admin-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// Production with a plaintext address MUST be refused: the administrative bearer
// is readable by anything on the path, and the admin API it opens authenticates
// nobody.
func TestValidate_Production_RefusesPlaintextProviderAdminURL(t *testing.T) {
	cfg := adminHopCfg(config.ModeProduction, "http://kacho-umbrella-hydra-admin.kacho.svc:4445")
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal for a plaintext provider-admin hop")
	}
	if !strings.Contains(err.Error(), "hydra-admin-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// The sanctioned shape — declared, over TLS — boots. The guard must stay silent
// on a correct configuration, or the first false refusal gets it deleted.
func TestValidate_Production_AcceptsDeclaredTLSProviderAdminURL(t *testing.T) {
	cfg := adminHopCfg(config.ModeProduction, "https://kacho-umbrella-hydra-admin.kacho.svc:4445")
	cfg.AuthN.HydraAdminCAFile = "/etc/kaname/tls/server/ca.crt"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a declared https provider-admin hop", err)
	}
}

// dev keeps the derivation and tolerates plaintext: an in-process fixture has no
// provider at all, and a developer stand may run one without a certificate. The
// exemption is stated as its own case so it is a decision on record.
func TestValidate_Dev_ToleratesDerivedAndPlaintextProviderAdminURL(t *testing.T) {
	if err := adminHopCfg(config.ModeDev, "").Validate(); err != nil {
		t.Fatalf("dev with a derived address: %v", err)
	}
	if err := adminHopCfg(config.ModeDev, "http://hydra-admin:4445").Validate(); err != nil {
		t.Fatalf("dev with a plaintext address: %v", err)
	}
}
