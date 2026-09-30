// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// validate_provider_public_hops_test.go — the hop iam makes to the identity
// provider's PUBLIC listener must be named by an operator, and when it is
// addressed over TLS it must carry something to verify the peer against.
//
// WHY THIS ONE, AND WHY IT IS NOT THE ADMIN HOP. The administrative address
// already refuses to start unless it is declared and encrypted. The token
// endpoint was left behind: the exchange posts a signed client assertion and
// reads the minted bearer back out of the response body. The second public hop —
// the upstream of the key-set mirror — left together with the mirror
// (kaname#361), and nothing here names it any more.
//
// It fell back to a DERIVATION from the issuer when a profile named nothing.
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
//
// СТРОКИ ПОЛОСЫ СНЯТОЙ ПОСАДКИ СУДЯТСЯ НАПРЯМУЮ (задача #424). Посадка
// `external` снята фундаментом (PRO-Robotech/corelib#30), и проверка старта
// отвергает её раньше требований её полосы (Provider.Validate): через
// Config.Validate эти стражи больше не достижимы. Строки таблицы, которые их
// зовут, живут до снятия полосы целиком (#363), и пробы их содержимого ходят
// в строки напрямую (externalLaneRefusal), а не через проверку старта —
// иначе положительные случаи зеленели бы на полосе `own`, где эти стражи не
// предъявляются вовсе.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// publicHopCfg — a production config that satisfies every other production
// requirement, so the hop under test is the only variable left.
func publicHopCfg(mode config.Mode) config.Config {
	cfg := goodEndpoints(mode, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	return cfg
}

// The token endpoint left to derivation must be refused. Nothing else catches it:
// ResolveHydraTokenURL always returns a non-empty string.
func TestValidate_Production_RefusesDerivedProviderTokenURL(t *testing.T) {
	t.Setenv("KANAME_HYDRA_TOKEN_URL", "")
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraTokenURL = ""
	err := externalLaneRefusal(cfg)
	if err == nil {
		t.Fatal("external-lane rows = nil, want refusal when the token endpoint address is derived")
	}
	if !strings.Contains(err.Error(), "hydra-token-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// https with nothing to verify against is refused: the provider's in-cluster
// certificate is internal-CA issued and this process trusts the system roots, so
// every call would fail on an unknown authority after the address already reads
// as hardened.
func TestValidate_Production_RefusesTLSPublicHopWithoutAnchor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		set     func(*config.Config)
		wantHas string
	}{
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
			cfg.AuthN.HydraTokenURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
			tc.set(&cfg)
			err := externalLaneRefusal(cfg)
			if err == nil {
				t.Fatal("external-lane rows = nil, want refusal for an https hop with no pinned anchor")
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
	cfg.AuthN.HydraTokenURL = "kacho-umbrella-hydra-public:4444/oauth2/token"
	err := externalLaneRefusal(cfg)
	if err == nil {
		t.Fatal("external-lane rows = nil, want refusal for an address that is not an absolute http(s) URL")
	}
	if !strings.Contains(err.Error(), "hydra-token-url") {
		t.Fatalf("the refusal must name the setting, got: %q", err.Error())
	}
}

// The shape the deployed profiles actually carry — the hop declared, in plain
// http, no anchor — must still boot. The transport of the provider's public
// listener is a separate change; this guard is about the address being named and
// about TLS never being claimed without an anchor.
func TestValidate_Production_AcceptsDeclaredPlaintextPublicHops(t *testing.T) {
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraTokenURL = "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
	if err := externalLaneRefusal(cfg); err != nil {
		t.Fatalf("external-lane rows = %v, want nil for a declared plaintext public hop", err)
	}
}

// https WITH an anchor must boot — this is the shape a stand takes once the
// provider's public listener is served over TLS.
func TestValidate_Production_AcceptsTLSPublicHopsWithAnchor(t *testing.T) {
	cfg := publicHopCfg(config.ModeProduction)
	cfg.AuthN.HydraTokenURL = "https://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token"
	cfg.AuthN.HydraTokenCAFile = "/etc/kaname/tls/server/ca.crt"
	if err := externalLaneRefusal(cfg); err != nil {
		t.Fatalf("external-lane rows = %v, want nil for an https public hop with a pinned anchor", err)
	}
}

// The ENV override counts as declared — it is one of the two sources an operator
// actually writes, and the chart ships the address that way.
func TestValidate_Production_AcceptsEnvDeclaredPublicHops(t *testing.T) {
	t.Setenv("KANAME_HYDRA_TOKEN_URL", "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token")
	cfg := publicHopCfg(config.ModeProduction)
	if err := externalLaneRefusal(cfg); err != nil {
		t.Fatalf("external-lane rows = %v, want nil when the address comes from the ENV override", err)
	}
}

// dev keeps the derivation: an in-process fixture has no provider at all, and a
// developer stand may run one without a certificate.
func TestValidate_Dev_LeavesPublicHopsAlone(t *testing.T) {
	t.Setenv("KANAME_HYDRA_TOKEN_URL", "")
	cfg := publicHopCfg(config.ModeDev)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil in dev with the public hop derived", err)
	}
}
