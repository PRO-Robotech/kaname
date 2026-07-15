// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytokenhttp — thin HTTP transport for the IAM Docker Registry v2
// auth-server: the `/iam/token` endpoint (Basic-auth → Hydra-brokered token).
//
// Transport only: parse the Docker token-auth request, delegate to the
// registry_token use-case (which verifies the SA-key and brokers a token from
// Ory Hydra), format the Docker-compatible JSON. No business logic.
//
// Hydra remains the token issuer/signer; kacho-iam mints NOTHING. The data-plane
// verifies the returned token against HYDRA's JWKS — which it now fetches from a
// cluster-INTERNAL Hydra-JWKS mirror served by kacho-iam (a short-TTL caching
// reverse-proxy of Hydra's public JWKS at GET /.well-known/jwks.json on the :9097
// jwks-proxy listener, package internal/handler/jwksproxyhttp), NOT from this
// external `/iam/token` listener. The mirror keeps the served kids equal to Hydra's
// real signing kids; iam never serves its own oidc_jwks_keys kacho-* kids. This
// `/iam/token` mux therefore carries no JWKS endpoint of its own.
//
// Endpoint:
//
//	GET|POST /iam/token — Docker Registry v2 token endpoint (Basic → Hydra token).
package registrytokenhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
)

// TokenPath — the token endpoint path. MUST equal the data-plane's Bearer realm
// path (the WWW-Authenticate realm), so verifiers and docker clients resolve the
// same URL.
const TokenPath = "/iam/token"

// NewMux mounts the token handler on its canonical path. The caller exposes the
// returned mux on an EXTERNAL-reachable HTTP listener (docker clients hit
// /iam/token through the edge) — unlike the cluster-internal hooks mux.
func NewMux(token http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if token != nil {
		mux.Handle(TokenPath, token)
	}
	return mux
}

// TokenIssuer — the registry_token use-case port the handler delegates to.
// Execute brokers the SA-key (Basic-creds) path; ExecuteAnonymous brokers the
// public `user:*` anonymous-pull path (no Basic creds); AnonymousEnabled reports
// whether that path is configured (else the handler fails closed to a challenge).
type TokenIssuer interface {
	Execute(ctx context.Context, in registrytokenuc.IssueInput) (registrytokenuc.IssueOutput, error)
	ExecuteAnonymous(ctx context.Context, service string) (registrytokenuc.IssueOutput, error)
	AnonymousEnabled() bool
}

// Config — handler config (the WWW-Authenticate realm + default service name).
type Config struct {
	// Realm — the token-endpoint URL advertised in WWW-Authenticate (must match
	// the data-plane's Bearer realm, e.g. https://api.kacho.local/iam/token).
	Realm string
	// DefaultService — the service name used in WWW-Authenticate when the request
	// omits ?service= (e.g. registry.kacho.local).
	DefaultService string
}

// TokenHandler — the `/iam/token` endpoint.
type TokenHandler struct {
	cfg    Config
	issuer TokenIssuer
}

// NewTokenHandler — builder.
func NewTokenHandler(cfg Config, issuer TokenIssuer) *TokenHandler {
	return &TokenHandler{cfg: cfg, issuer: issuer}
}

// tokenResponse — the Docker Registry v2 token-endpoint body. `access_token`
// mirrors `token` for OAuth2-flow client compatibility. `issued_at` is an RFC3339
// UTC *string* per the Docker Registry v2 token spec: the docker client parses it
// via `time.Time.UnmarshalJSON`, which accepts ONLY a JSON string — serializing it
// as a bare Unix-epoch number breaks `docker login` with «Time.UnmarshalJSON:
// input is not a JSON string», so no bearer is minted and all pull/push 401.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at,omitempty"`
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	service := r.URL.Query().Get("service")
	if service == "" {
		service = h.cfg.DefaultService
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		// No Basic creds → the docker anonymous-pull flow. When anonymous pull is
		// enabled, issue the read-only public `user:*` bearer; otherwise fail
		// closed to the 401 Bearer challenge (secure-by-default, anon is opt-in).
		if !h.issuer.AnonymousEnabled() {
			h.challenge(w, service)
			return
		}
		out, err := h.issuer.ExecuteAnonymous(r.Context(), service)
		if err != nil {
			h.writeError(w, service, err)
			return
		}
		h.writeToken(w, out)
		return
	}

	out, err := h.issuer.Execute(r.Context(), registrytokenuc.IssueInput{
		Username: user,
		Password: pass,
		Service:  service,
	})
	if err != nil {
		h.writeError(w, service, err)
		return
	}
	h.writeToken(w, out)
}

// writeError maps a use-case failure to the fail-closed HTTP response: an
// unreachable issuer (Hydra) → 503 (no token); any auth failure → 401 challenge;
// anything else → 500. No raw Hydra/network error ever leaks (fixed text).
func (h *TokenHandler) writeError(w http.ResponseWriter, service string, err error) {
	switch {
	case errors.Is(err, registrytokenuc.ErrIssuerUnavailable):
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
	case errors.Is(err, registrytokenuc.ErrUnauthenticated):
		h.challenge(w, service)
	default:
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}
}

// writeToken writes the 200 Docker Registry v2 token body.
func (h *TokenHandler) writeToken(w http.ResponseWriter, out registrytokenuc.IssueOutput) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	issuedAt := ""
	if out.IssuedAt > 0 {
		issuedAt = time.Unix(out.IssuedAt, 0).UTC().Format(time.RFC3339)
	}
	// #nosec G117 -- registry token endpoint intentionally returns the minted bearer token to the client (Docker registry v2 auth flow); serializing it is the contract, not a leak
	_ = json.NewEncoder(w).Encode(tokenResponse{
		Token:       out.Token,
		AccessToken: out.Token,
		ExpiresIn:   out.ExpiresIn,
		IssuedAt:    issuedAt,
	})
}

// challenge writes the 401 Bearer WWW-Authenticate challenge (realm + service).
func (h *TokenHandler) challenge(w http.ResponseWriter, service string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm=%q,service=%q`, h.cfg.Realm, service))
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}
