// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytokenhttp — thin HTTP transport for the IAM Docker Registry v2
// auth-server: the `/token` endpoint (Basic-auth → identity-JWT) and its JWKS.
//
// Transport only: parse the Docker token-auth request, delegate to the
// registry_token use-case, format the Docker-compatible JSON. No business logic.
//
// Endpoints:
//
//	GET|POST /iam/token       — Docker Registry v2 token endpoint (Basic → JWT).
//	GET      /iam/token/jwks  — JWK Set for verifying minted identity-JWTs.
package registrytokenhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// Route paths for the registry token endpoints. TokenPath MUST equal the
// data-plane's Bearer realm path (the WWW-Authenticate realm), so verifiers and
// docker clients resolve the same URL.
const (
	TokenPath = "/iam/token"
	JWKSPath  = "/iam/token/jwks"
)

// NewMux mounts the token + JWKS handlers on their canonical paths. The caller
// exposes the returned mux on an EXTERNAL-reachable HTTP listener (docker clients
// hit /iam/token through the edge) — unlike the cluster-internal hooks mux.
func NewMux(token, jwks http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if token != nil {
		mux.Handle(TokenPath, token)
	}
	if jwks != nil {
		mux.Handle(JWKSPath, jwks)
	}
	return mux
}

// TokenIssuer — the registry_token use-case port the handler delegates to.
type TokenIssuer interface {
	Execute(ctx context.Context, in registrytokenuc.IssueInput) (registrytokenuc.IssueOutput, error)
}

// JWKSProvider — supplies the public JWK Set for verifying minted tokens.
type JWKSProvider interface {
	PublicJWKS(ctx context.Context) (registrytoken.JWKS, error)
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

// TokenHandler — the `/token` endpoint.
type TokenHandler struct {
	cfg    Config
	issuer TokenIssuer
}

// NewTokenHandler — builder.
func NewTokenHandler(cfg Config, issuer TokenIssuer) *TokenHandler {
	return &TokenHandler{cfg: cfg, issuer: issuer}
}

// tokenResponse — the Docker Registry v2 token-endpoint body. `access_token`
// mirrors `token` for OAuth2-flow client compatibility.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    int64  `json:"issued_at,omitempty"`
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
		// Anonymous / non-Basic → 401 challenge (secure-by-default, no anon pull).
		h.challenge(w, service)
		return
	}

	out, err := h.issuer.Execute(r.Context(), registrytokenuc.IssueInput{
		Username: user,
		Password: pass,
		Service:  service,
	})
	if err != nil {
		if errors.Is(err, registrytokenuc.ErrUnauthenticated) {
			h.challenge(w, service)
			return
		}
		// Signing / infra failure — fixed text, no internal detail leaked.
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tokenResponse{
		Token:       out.Token,
		AccessToken: out.Token,
		ExpiresIn:   out.ExpiresIn,
		IssuedAt:    out.IssuedAt,
	})
}

// challenge writes the 401 Bearer WWW-Authenticate challenge (realm + service).
func (h *TokenHandler) challenge(w http.ResponseWriter, service string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm=%q,service=%q`, h.cfg.Realm, service))
	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}

// JWKSHandler — the `/token/jwks` endpoint.
type JWKSHandler struct {
	provider JWKSProvider
}

// NewJWKSHandler — builder.
func NewJWKSHandler(p JWKSProvider) *JWKSHandler { return &JWKSHandler{provider: p} }

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	set, err := h.provider.PublicJWKS(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Public verification keys rotate slowly; allow brief caching by verifiers.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(set)
}
