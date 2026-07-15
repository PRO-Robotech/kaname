// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// registry_token.go — config for the Docker Registry v2 `/iam/token`
// auth-server HTTP listener (the `/iam/token` endpoint only). There is NO JWKS
// endpoint on this listener: the data-plane's Hydra-JWKS verification keys are
// served separately by the cluster-INTERNAL jwks-proxy listener (a caching mirror
// of Hydra's public JWKS — see jwks_proxy.go / internal/handler/jwksproxyhttp).
// Hydra stays the issuer/signer; iam mints nothing here.
//
// The listener is EXTERNAL-reachable (docker clients hit `/iam/token` through
// the edge); TLS is terminated at the ingress, so the process binds plaintext —
// same posture as the hooks / metrics listeners. Policy fields (issuer, service,
// TTL) shape the minted identity-JWT and must match the data-plane's advertised
// Bearer realm.
package config

import (
	"strings"
	"time"
)

// Built-in policy defaults. viper also registers them (defaults.go); the
// accessors carry the same fallbacks so an unset struct (tests / partial config)
// still resolves to a valid policy.
const (
	defaultRegistryTokenIssuer  = "https://api.kacho.local/iam/token" // #nosec G101 -- OIDC issuer URL default (iss claim), not a credential
	defaultRegistryTokenService = "registry.kacho.local"              // #nosec G101 -- registry service-name default (aud claim), not a credential
	defaultRegistryTokenTTL     = 5 * time.Minute
)

// RegistryTokenConfig — api-server.registry-token section.
//
//	Endpoint — HTTP listen address (`tcp://0.0.0.0:9096` or bare `9096`).
//	           Empty disables the listener.
//	Issuer   — the `iss` claim + the WWW-Authenticate realm URL.
//	Service  — the default registry service name (→ `aud` + challenge service).
//	TTL      — minted-token lifetime (clamped to registry_token.MaxTTL downstream).
type RegistryTokenConfig struct {
	Endpoint string        `mapstructure:"endpoint"`
	Issuer   string        `mapstructure:"issuer"`
	Service  string        `mapstructure:"service"`
	TTL      time.Duration `mapstructure:"ttl"`
}

// ListenAddress — normalised listen-addr for the token HTTP server (empty
// endpoint → empty, i.e. the listener is disabled). Separate external port from
// the gRPC / hooks / metrics listeners.
func (c RegistryTokenConfig) ListenAddress() string { return listenAddress(c.Endpoint) }

// TokenIssuer — the `iss` claim + WWW-Authenticate realm. Falls back to the
// built-in default when unset.
func (c RegistryTokenConfig) TokenIssuer() string {
	if s := strings.TrimSpace(c.Issuer); s != "" {
		return s
	}
	return defaultRegistryTokenIssuer
}

// TokenService — the default registry service name (`aud`). Falls back to the
// built-in default when unset.
func (c RegistryTokenConfig) TokenService() string {
	if s := strings.TrimSpace(c.Service); s != "" {
		return s
	}
	return defaultRegistryTokenService
}

// TokenTTL — the minted-token lifetime. Non-positive values fall back to the
// built-in default (the use-case additionally clamps to registry_token.MaxTTL).
func (c RegistryTokenConfig) TokenTTL() time.Duration {
	if c.TTL <= 0 {
		return defaultRegistryTokenTTL
	}
	return c.TTL
}
