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

// ResolveHydraIssuer returns the Hydra issuer. Default `https://hydra.<Domain>`.
// If HydraIssuer is set explicitly we use it (supports custom deployments).
func (c AuthNConfig) ResolveHydraIssuer() string {
	if iss := strings.TrimSpace(c.HydraIssuer); iss != "" {
		return iss
	}
	return "https://hydra." + c.ResolveDomain()
}

// ResolveAudience returns the caller-aud for tokens (`<domain>` without
// scheme). Used by token_hook to embed the audience claim.
func (c AuthNConfig) ResolveAudience() string {
	return c.ResolveDomain()
}

// ResolveHydraAdminURL — URL of the Hydra admin API (for publishing JWKS).
// Default https://hydra-admin.<Domain>; can be customised via env if needed.
func (c AuthNConfig) ResolveHydraAdminURL() string {
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
