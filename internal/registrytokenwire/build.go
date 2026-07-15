// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenwire

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/registrytokenhttp"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// BuildConfig — the composition inputs for the registry `/iam/token` shim.
type BuildConfig struct {
	// Realm — the WWW-Authenticate realm URL advertised to docker clients
	// (e.g. https://api.kacho.local/iam/token). Must match the data-plane's
	// advertised Bearer realm.
	Realm string
	// Service — the default registry service name (→ requested token audience +
	// WWW-Authenticate service, e.g. registry.kacho.local).
	Service string
	// HydraTokenURL — the Hydra public token endpoint the shim POSTs the exchange
	// to (cluster-internal in production, e.g.
	// http://kacho-umbrella-hydra-public.<ns>.svc:4444/oauth2/token).
	HydraTokenURL string
	// AssertionAudience — the `aud` of the client_assertion: the Hydra token
	// endpoint URL Hydra recognises (its external issuer's token endpoint).
	AssertionAudience string
	// Scope — optional scope requested from Hydra.
	Scope string
	// AnonymousClientID / AnonymousKeyID / AnonymousPrivateKeyPEM — the configured
	// public-principal identity the shim authenticates as for anonymous pull (RG-1
	// D-7). The data-plane resolves this client_id's token to the FGA wildcard
	// `user:*`. Empty (the default) leaves anonymous pull DISABLED — no-Basic-creds
	// then fails closed to a 401 challenge (secure-by-default; anon is opt-in).
	AnonymousClientID      string
	AnonymousKeyID         string
	AnonymousPrivateKeyPEM string
}

// Build assembles the registry `/iam/token` shim from a pgx pool: the SA-key
// credential validator (reverse lookup by client_id), the ES256 client_assertion
// signer, and the Hydra token exchanger, wired into the token HTTP handler. The
// caller mounts the returned mux on an EXTERNAL-reachable HTTP listener.
//
// Composition root only — this is the single wire-up call for serve.go. Unlike
// the deprecated RS256 signer, the shim needs NO JWKS encryption key: it does not
// mint tokens (Hydra does) and does not decrypt any at-rest signing key. The
// data-plane's verification keys are Hydra's, served via the separate
// cluster-internal jwks-proxy mirror (internal/handler/jwksproxyhttp) — not by this
// `/iam/token` shim.
func Build(pool *pgxpool.Pool, cfg BuildConfig) http.Handler {
	saRepo := kachopg.NewSAOAuthClientRepo(pool)

	validator := registrytokenuc.NewSAKeyValidator(NewSAClientLookup(saRepo))
	signer := registrytokenuc.ES256AssertionSigner{}
	exchanger := NewHydraExchange(clients.NewHydraTokenClient(cfg.HydraTokenURL))

	useCase := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		AssertionAudience: cfg.AssertionAudience,
		DefaultService:    cfg.Service,
		Scope:             cfg.Scope,
		// Anonymous-pull identity (RG-1 D-7). Empty → anonymous pull disabled; the
		// shim then serves the SA-key path only (no-Basic-creds → 401 challenge).
		Anonymous: registrytokenuc.AnonymousIdentity{
			ClientID:      cfg.AnonymousClientID,
			KeyID:         cfg.AnonymousKeyID,
			PrivateKeyPEM: cfg.AnonymousPrivateKeyPEM,
		},
	}, validator, signer, exchanger)

	tokenHandler := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          cfg.Realm,
		DefaultService: cfg.Service,
	}, useCase)

	return registrytokenhttp.NewMux(tokenHandler)
}
