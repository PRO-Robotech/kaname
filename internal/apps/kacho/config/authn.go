// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authn_phase2.go — helpers for the AuthN core config fields.
//
// Reading order:
//
//  1. value from YAML/ENV directly (e.g. authn.hook-shared-secret),
//  2. ENV variable referenced by authn.hook-shared-secret-env (default
//     KACHO_IAM_HOOK_TOKEN). Required because secrets are never written to
//     YAML (workspace policy — secretKeyRef-only).
//
// ResolveHydraIssuer() / ResolveAudience() — derived from Domain. Default
// `api.kacho.cloud` is configurable, avoiding hard-code.
//
// All methods are pure (no side-effects; only os.Getenv reads).
package config

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// ResolveHookSharedSecret returns the current shared-secret for Hydra hooks.
// If authn.hook-shared-secret is set directly (dev) we use it; otherwise we
// read the ENV variable named by authn.hook-shared-secret-env. An empty
// return is allowed in dev mode (the handler accepts calls without Bearer).
func (c AuthNConfig) ResolveHookSharedSecret() string {
	if c.HookSharedSecret != "" {
		return c.HookSharedSecret
	}
	envName := c.HookSharedSecretEnv
	if envName == "" {
		envName = "KACHO_IAM_HOOK_TOKEN"
	}
	return os.Getenv(envName)
}

// ResolveJWKSEncryptionKey returns the 32-byte AES-GCM key decoded from hex.
// Source: authn.jwks-encryption-key-hex directly, or the ENV variable named
// by authn.jwks-encryption-key-hex-env (default KACHO_IAM_JWKS_ENC_KEY).
// The key must be exactly 32 bytes (256 bit); otherwise error.
func (c AuthNConfig) ResolveJWKSEncryptionKey() ([]byte, error) {
	raw := c.JWKSEncryptionKeyHex
	if raw == "" {
		envName := c.JWKSEncryptionKeyHexEnv
		if envName == "" {
			envName = "KACHO_IAM_JWKS_ENC_KEY"
		}
		raw = os.Getenv(envName)
	}
	if raw == "" {
		return nil, fmt.Errorf("authn.jwks-encryption-key-hex is empty (set ENV KACHO_IAM_JWKS_ENC_KEY)")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("authn.jwks-encryption-key-hex: invalid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("authn.jwks-encryption-key-hex: must decode to 32 bytes (got %d)", len(key))
	}
	return key, nil
}

// ResolveDomain returns the public Kachō domain. Default `api.kacho.cloud`.
func (c AuthNConfig) ResolveDomain() string {
	d := strings.TrimSpace(c.Domain)
	if d == "" {
		return "api.kacho.cloud"
	}
	return d
}

// ResolveHydraIssuer returns the Hydra issuer. Precedence: explicit HydraIssuer
// field → KACHO_IAM_HYDRA_ISSUER env → derived `https://hydra.<Domain>`. The env
// fallback lets a deployment whose Hydra advertises a non-derivable issuer (e.g. a
// dev-stand behind a path-prefixed public URL) align the shim's client_assertion
// audience with Hydra's real issuer — otherwise the exchange fails invalid_client.
func (c AuthNConfig) ResolveHydraIssuer() string {
	if iss := strings.TrimSpace(c.HydraIssuer); iss != "" {
		return iss
	}
	if v := strings.TrimSpace(os.Getenv("KACHO_IAM_HYDRA_ISSUER")); v != "" {
		return v
	}
	return "https://hydra." + c.ResolveDomain()
}

// ResolveAudience returns the caller-aud for tokens (`<domain>` without
// scheme). Used by token_hook to embed the audience claim.
func (c AuthNConfig) ResolveAudience() string {
	return c.ResolveDomain()
}

// ResolveHydraAdminURL — URL of the Hydra admin API (client-registration +
// jwt-bearer trust-grants). Precedence: the explicit `authn.hydra-admin-url` /
// ENV KACHO_IAM_HYDRA_ADMIN_URL override, then the derivation from the issuer
// (hydra.X → hydra-admin.X). The override lets in-cluster iam reach the
// cluster-internal admin Service (http://kacho-umbrella-hydra-admin.<ns>.svc:4445)
// even when the external issuer host does not resolve in-cluster.
func (c AuthNConfig) ResolveHydraAdminURL() string {
	if v := strings.TrimSpace(c.HydraAdminURL); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("KACHO_IAM_HYDRA_ADMIN_URL")); v != "" {
		return v
	}
	if iss := c.ResolveHydraIssuer(); iss != "" {
		u, err := url.Parse(iss)
		if err == nil {
			// hydra.X.Y → hydra-admin.X.Y (Hydra split public/admin convention).
			if h := u.Hostname(); strings.HasPrefix(h, "hydra.") {
				u.Host = "hydra-admin." + strings.TrimPrefix(h, "hydra.")
				if p := u.Port(); p != "" {
					u.Host += ":" + p
				}
				return u.String()
			}
		}
	}
	return "https://hydra-admin." + c.ResolveDomain()
}

// ResolveHydraTokenEndpoint — the EXTERNAL issuer's token endpoint
// (`<issuer>/oauth2/token`). This is the value Hydra recognises as the audience
// of a client_assertion, and stays external regardless of the cluster-internal
// POST target.
func (c AuthNConfig) ResolveHydraTokenEndpoint() string {
	return strings.TrimRight(c.ResolveHydraIssuer(), "/") + "/oauth2/token"
}

// ResolveHydraTokenURL — the Hydra public token endpoint the `/iam/token` shim
// POSTs the exchange to. Precedence: the explicit `authn.hydra-token-url` / ENV
// KACHO_IAM_HYDRA_TOKEN_URL override (a cluster-internal Service, e.g.
// http://kacho-umbrella-hydra-public.<ns>.svc:4444/oauth2/token), then the
// external token endpoint (back-compat). The `iss` of the resulting token remains
// the external Hydra issuer; only the network target differs.
func (c AuthNConfig) ResolveHydraTokenURL() string {
	if v := strings.TrimSpace(c.HydraTokenURL); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("KACHO_IAM_HYDRA_TOKEN_URL")); v != "" {
		return v
	}
	return c.ResolveHydraTokenEndpoint()
}

// ResolveHydraJWKSURL — the upstream Hydra PUBLIC JWKS URL the cluster-internal
// jwks-proxy listener mirrors (`GET /.well-known/jwks.json`). Precedence mirrors
// ResolveHydraTokenURL: the explicit `authn.hydra-jwks-url` / ENV
// KACHO_IAM_HYDRA_JWKS_URL override (a cluster-internal Service, e.g.
// http://kacho-umbrella-hydra-public.<ns>.svc:4444/.well-known/jwks.json), then the
// derived `<issuer>/.well-known/jwks.json` (back-compat). Hydra remains the signer;
// iam serves a byte-identical mirror so the served kids are Hydra's real signing
// kids (never iam's own kacho-* oidc_jwks_keys kids). Only the network target
// differs — the `iss` of a verified token stays the external Hydra issuer.
func (c AuthNConfig) ResolveHydraJWKSURL() string {
	if v := strings.TrimSpace(c.HydraJWKSURL); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("KACHO_IAM_HYDRA_JWKS_URL")); v != "" {
		return v
	}
	return strings.TrimRight(c.ResolveHydraIssuer(), "/") + "/.well-known/jwks.json"
}

// SessionRevocationsCacheTTL returns the TTL for the memo-cache over
// session_revocations. Default 5 seconds (SLA — ≤1s after force-logout;
// cache TTL must be shorter).
func (c AuthNConfig) SessionRevocationsCacheTTL() time.Duration {
	s := c.SessionRevocationsTTLSec
	if s <= 0 {
		s = 5
	}
	return time.Duration(s) * time.Second
}

// JWKSRotationDuration — JWKS key TTL (default 90 days).
func (c AuthNConfig) JWKSRotationDuration() time.Duration {
	d := c.JWKSRotationDays
	if d <= 0 {
		d = 90
	}
	return time.Duration(d) * 24 * time.Hour
}

// HooksHTTPListenAddress — normalised listen-addr for the webhook HTTP
// server. Default `tcp://0.0.0.0:9092` (separate port from gRPC
// public/internal).
func (c AuthNConfig) HooksHTTPListenAddress() string {
	return listenAddress(c.HooksHTTPEndpoint)
}
