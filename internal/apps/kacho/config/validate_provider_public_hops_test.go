// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// validate_provider_public_hops_test.go — the two hops iam makes to the identity
// provider's PUBLIC listener must be named by an operator, and when they are
// addressed over TLS they must carry something to verify the peer against.
//
// WHY THESE TWO, AND WHY THEY ARE NOT THE ADMIN HOP. iam is the platform's only
// facade to the provider, and three separate addresses ride that facade. The
// administrative one already refuses to start unless it is declared and
// encrypted. These two were left behind:
//
//   - the JWKS upstream: the keyset iam mirrors on its cluster-internal listener
//     IS the data-plane's only anchor for deciding whether a token was signed by
//     the provider. Whatever answers that address decides which signatures the
//     platform accepts.
//   - the token endpoint: the exchange posts a signed client assertion and reads
//     the minted bearer back out of the response body.
//
// Both fell back to a DERIVATION from the issuer when a profile named neither.
// A derivation is never empty, so the facade read as configured while addressing
// the public ingress hostname — which does not resolve inside the cluster, and if
// it ever does, it is not the process the operator meant. Requiring the
// declaration is the platform rule that a security-relevant dependency address is
// never worked out from a neighbour's.
//
// Transport is a SEPARATE question and deliberately not asserted here: the
// provider serves its public listener in plain http on every profile, and moving
// it is a change with its own acceptance (see the note in
// deploy/helm/umbrella/templates/hydra-admin-certificate.yaml). What IS asserted
// is that the moment a profile says https, the anchor must be pinned with it —
// otherwise the address reads as hardened while the process verifies against the
// system roots, which an internal-CA certificate never chains to.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// publicHopCfg — a production config that satisfies every other production
// requirement, so the hop under test is the only variable left.
func publicHopCfg(mode config.Mode) config.Config {
	cfg := goodEndpoints(mode, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	return cfg
}

// The JWKS upstream left to derivation must be refused. Nothing else catches it:
// ResolveHydraJWKSURL always returns a non-empty string.
func TestValidate_Production_RefusesDerivedProviderJWKSURL(t *testing.T) {
	t.Setenv("KACHO_IAM_HYDRA_JWKS_URL", "")
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraJWKSURL = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal when the JWKS upstream address is derived")
	}
	if !strings.Contains(err.Error(), "hydra-jwks-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// The token endpoint left to derivation must be refused, for the same reason.
func TestValidate_Production_RefusesDerivedProviderTokenURL(t *testing.T) {
	t.Setenv("KACHO_IAM_HYDRA_TOKEN_URL", "")
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraJWKSURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"
	cfg.AuthN.HydraTokenURL = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal when the token endpoint address is derived")
	}
	if !strings.Contains(err.Error(), "hydra-token-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// https with nothing to verify against is refused on BOTH hops: the provider's
// in-cluster certificate is internal-CA issued and this process trusts the system
// roots, so every fetch would fail on an unknown authority after the address
// already reads as hardened.
func TestValidate_Production_RefusesTLSPublicHopWithoutAnchor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		set     func(*config.Config)
		wantHas string
	}{
		{
			name: "jwks",
			set: func(c *config.Config) {
				c.AuthN.HydraJWKSURL = "https://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"
				c.AuthN.HydraJWKSCAFile = ""
			},
			wantHas: "hydra-jwks-ca-file",
		},
		{
			name: "token",
			set: func(c *config.Config) {
				c.AuthN.HydraTokenURL = "https://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
				c.AuthN.HydraTokenCAFile = ""
			},
			wantHas: "hydra-token-ca-file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := publicHopCfg(config.ModeProduction)
			cfg.AuthN.HydraJWKSURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"
			cfg.AuthN.HydraTokenURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
			tc.set(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want refusal for an https hop with no pinned anchor")
			}
			if !strings.Contains(err.Error(), tc.wantHas) {
				t.Fatalf("the refusal must name the anchor setting, got: %q", err.Error())
			}
		})
	}
}

// A garbage address is refused too — a non-absolute string would otherwise reach
// the http client and fail at the first fetch, long after boot.
func TestValidate_Production_RefusesNonAbsolutePublicHop(t *testing.T) {
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraJWKSURL = "kacho-umbrella-hydra-public:4444/.well-known/jwks.json"
	cfg.AuthN.HydraTokenURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refusal for an address that is not an absolute http(s) URL")
	}
	if !strings.Contains(err.Error(), "hydra-jwks-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// The shape the deployed profiles actually carry — both hops declared, in plain
// http, no anchor — must still boot. The transport of the provider's public
// listener is a separate change; this guard is about the address being named and
// about TLS never being claimed without an anchor.
func TestValidate_Production_AcceptsDeclaredPlaintextPublicHops(t *testing.T) {
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraJWKSURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"
	cfg.AuthN.HydraTokenURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for declared plaintext public hops", err)
	}
}

// https WITH an anchor on both hops must boot — this is the shape a stand takes
// once the provider's public listener is served over TLS.
func TestValidate_Production_AcceptsTLSPublicHopsWithAnchor(t *testing.T) {
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraJWKSURL = "https://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json"
	cfg.AuthN.HydraJWKSCAFile = "/etc/kacho-iam/tls/server/ca.crt"
	cfg.AuthN.HydraTokenURL = "https://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
	cfg.AuthN.HydraTokenCAFile = "/etc/kacho-iam/tls/server/ca.crt"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for https public hops with pinned anchors", err)
	}
}

// The ENV override counts as declared — it is one of the two sources an operator
// actually writes, and the chart ships the address that way.
func TestValidate_Production_AcceptsEnvDeclaredPublicHops(t *testing.T) {
	t.Setenv("KACHO_IAM_HYDRA_JWKS_URL", "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json")
	t.Setenv("KACHO_IAM_HYDRA_TOKEN_URL", "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token")
	cfg := publicHopCfg(config.ModeProduction)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when the addresses come from the ENV override", err)
	}
}

// dev keeps the derivation: an in-process fixture has no provider at all, and a
// developer stand may run one without a certificate.
func TestValidate_Dev_LeavesPublicHopsAlone(t *testing.T) {
	t.Setenv("KACHO_IAM_HYDRA_JWKS_URL", "")
	t.Setenv("KACHO_IAM_HYDRA_TOKEN_URL", "")
	cfg := publicHopCfg(config.ModeDev)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil in dev with both public hops derived", err)
	}
}
