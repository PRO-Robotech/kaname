// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenwire

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/registrytokenhttp"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// BuildConfig — the composition inputs for the registry `/token` surface.
type BuildConfig struct {
	// Issuer — the `iss` claim + the WWW-Authenticate realm URL
	// (e.g. https://api.kacho.local/iam/token). Must match the data-plane's
	// advertised Bearer realm.
	Issuer string
	// Service — the default registry service name (→ aud + WWW-Authenticate
	// service, e.g. registry.kacho.local).
	Service string
	// TTL is applied to minted tokens (clamped to registry_token.MaxTTL).
	TTL registrytokenuc.Config
	// JWKSEncryptionKey — the AES-256-GCM key protecting the oidc_jwks private
	// keys at rest (cfg.AuthN.ResolveJWKSEncryptionKey()).
	JWKSEncryptionKey []byte
}

// Build assembles the registry token endpoints from a pgx pool: the SA-key
// validator, the RS256 signer (current oidc_jwks key), and the JWKS provider,
// wired into the token + JWKS HTTP handlers. The caller mounts the returned mux
// on an EXTERNAL-reachable HTTP listener.
//
// Composition root only — this is the single wire-up call for serve.go.
func Build(pool *pgxpool.Pool, cfg BuildConfig) http.Handler {
	jwksRepo := kachopg.NewOIDCJwksKeyRepo(pool)
	saRepo := kachopg.NewSAOAuthClientRepo(pool)

	validator := registrytokenuc.NewSAKeyValidator(NewSAKeyLookup(saRepo))
	signer := registrytokenuc.NewRS256Signer(NewRSAKeyProvider(jwksRepo, cfg.JWKSEncryptionKey))

	ucCfg := cfg.TTL
	ucCfg.Issuer = cfg.Issuer
	ucCfg.DefaultService = cfg.Service
	useCase := registrytokenuc.NewIssueRegistryTokenUseCase(ucCfg, validator, signer)

	tokenHandler := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          cfg.Issuer,
		DefaultService: cfg.Service,
	}, useCase)
	jwksHandler := registrytokenhttp.NewJWKSHandler(NewJWKSProvider(jwksRepo))

	return registrytokenhttp.NewMux(tokenHandler, jwksHandler)
}
