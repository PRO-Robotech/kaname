// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package jwksproxyhttp — the cluster-INTERNAL Hydra-JWKS proxy: a thin, short-TTL
// CACHING reverse-proxy of Ory Hydra's PUBLIC JWKS (`GET /.well-known/jwks.json`).
//
// Purpose. The data-plane (kacho-registry) verifies docker-Bearer signatures with
// verification keys fetched from iam instead of dialing Hydra directly. Hydra stays
// the token issuer/signer (iam mints NOTHING) — so iam serves a BYTE-IDENTICAL
// mirror of Hydra's JWKS: the served `kid`/`alg` are Hydra's ACTUAL signing kids.
// It never serves iam's own `oidc_jwks_keys` `kacho-*` kids (that store + the
// jwks-rotator + HydraPublisher are vestigial and OUT of the verify path); a
// `kacho-*` kid would be a guaranteed kid-miss → fail-closed reject of every pull.
//
// Fail-closed. A cold cache + an unavailable Hydra (network error / non-200 / empty
// keyset / timeout) yields 502 — never an empty 200, never a substitute keyset. A
// warm cache within TTL survives a brief Hydra blip (bounded-stale); once the TTL
// elapses with Hydra still down the endpoint degrades to fail-closed, never
// indefinitely-stale.
//
// Per-call timeout. The upstream fetch uses a dedicated http.Client WITH a Timeout
// plus a per-request context deadline — never http.DefaultClient (architecture.md:
// DefaultClient has no Timeout, so a hung/half-open Hydra would wedge the goroutine
// forever).
//
// AuthN exception (security.md, RJU-07). This route is UNAUTHENTICATED-BY-DESIGN: it
// serves only PUBLIC verification keys (standard OIDC well-known), on a cluster-
// INTERNAL listener (:9097, never external — ban #6) protected by one-way
// server-TLS (internal-CA leaf; NOT mutual — mTLS-gating would break the registry
// verifier's "untouched" property). This is a CONSCIOUS, documented exception to the
// "authN on every listener" invariant, justified by: internal-only surface +
// server-TLS + only-public-material is served. Do NOT add an authN gate here without
// revisiting that decision (and the registry verifier's TLS client).
package jwksproxyhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WellKnownJWKSPath — the standard OIDC JWKS well-known path this proxy serves.
const WellKnownJWKSPath = "/.well-known/jwks.json"

const (
	defaultTTL       = 5 * time.Minute
	defaultTimeout   = 5 * time.Second
	maxJWKSBytes     = 1 << 20 // 1 MiB upstream-body cap (defensive)
	failClosedStatus = http.StatusBadGateway
)

// Config — inputs for the JWKS-proxy handler.
type Config struct {
	// UpstreamURL — the Hydra PUBLIC JWKS URL to mirror (config.ResolveHydraJWKSURL).
	UpstreamURL string
	// Client — optional injectable http.Client. nil → an internal client WITH a
	// per-call Timeout (never http.DefaultClient).
	Client *http.Client
	// TTL — cache lifetime when the upstream advertises no Cache-Control max-age.
	// <=0 → defaultTTL (5m).
	TTL time.Duration
	// Timeout — per-call upstream-fetch timeout. <=0 → defaultTimeout (5s).
	Timeout time.Duration
	// Clock — injectable time source (tests). nil → time.Now.
	Clock func() time.Time
	// Logger — nil → slog.Default().
	Logger *slog.Logger
}

// cachedDoc — a verbatim upstream JWKS document + its serving metadata.
type cachedDoc struct {
	body         []byte
	contentType  string
	cacheControl string
	expiresAt    time.Time
}

// Handler — the caching reverse-proxy handler.
type Handler struct {
	upstreamURL string
	client      *http.Client
	ttl         time.Duration
	timeout     time.Duration
	clock       func() time.Time
	logger      *slog.Logger

	mu     sync.Mutex
	cached *cachedDoc
}

// NewHandler builds the JWKS-proxy handler. The default http.Client carries a
// per-call Timeout (never http.DefaultClient).
func NewHandler(cfg Config) *Handler {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		// Dedicated client with a Timeout — NEVER http.DefaultClient (which has
		// no Timeout and would wedge on a hung Hydra).
		client = &http.Client{Timeout: timeout}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		upstreamURL: cfg.UpstreamURL,
		client:      client,
		ttl:         ttl,
		timeout:     timeout,
		clock:       clock,
		logger:      logger,
	}
}

// NewMux mounts the handler on the canonical well-known path. The caller exposes
// the returned mux on the cluster-INTERNAL jwks-proxy listener (never external).
func NewMux(h http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if h != nil {
		mux.Handle(WellKnownJWKSPath, h)
	}
	return mux
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read-only well-known endpoint.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeFailClosed(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	now := h.clock()

	// Fresh cache → serve verbatim without hitting the upstream (this is also what
	// makes a within-TTL Hydra blip a no-op: we do not even try the upstream).
	h.mu.Lock()
	c := h.cached
	h.mu.Unlock()
	if c != nil && now.Before(c.expiresAt) {
		h.serve(w, c)
		return
	}

	// Cold OR expired → refetch. Success caches + serves; failure is fail-closed
	// (never empty-200, never a substitute keyset).
	doc, err := h.fetch(r.Context())
	if err != nil {
		h.logger.Error("jwks-proxy: upstream Hydra JWKS fetch failed (fail-closed)",
			slog.String("upstream", h.upstreamURL),
			slog.String("err", err.Error()))
		writeFailClosed(w, failClosedStatus, "jwks_upstream_unavailable")
		return
	}

	h.mu.Lock()
	h.cached = doc
	h.mu.Unlock()
	h.serve(w, doc)
}

// serve writes a cached document verbatim with its Content-Type + Cache-Control.
func (h *Handler) serve(w http.ResponseWriter, c *cachedDoc) {
	w.Header().Set("Content-Type", c.contentType)
	w.Header().Set("Cache-Control", c.cacheControl)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.body)
}

// fetch GETs the upstream Hydra JWKS under a per-call deadline, validates it is a
// non-empty keyset, and returns a verbatim cached document. Any transport error,
// non-200 status, oversized/unparseable body, or empty keyset → error (fail-closed).
func (h *Handler) fetch(parent context.Context) (*cachedDoc, error) {
	ctx, cancel := context.WithTimeout(parent, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.upstreamURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build upstream request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read upstream body: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("upstream body exceeds %d bytes", maxJWKSBytes)
	}
	if err := validateNonEmptyKeyset(body); err != nil {
		return nil, err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}

	cacheControl := strings.TrimSpace(resp.Header.Get("Cache-Control"))
	ttl := h.ttl
	if maxAge, ok := parseMaxAge(cacheControl); ok && maxAge > 0 && maxAge < ttl {
		// Honor the upstream's freshness signal ONLY when it SHORTENS our TTL.
		// h.ttl is a HARD CEILING: a large upstream max-age (e.g. a CDN/Ory
		// advertising 24h) must never let iam serve a rotated/revoked keyset past
		// the short bounded-stale window — the data-plane trusts these kids as its
		// token-verification anchor, so freshness cannot be delegated to an
		// unvalidated upstream header (security freshness invariant).
		ttl = maxAge
	}
	if cacheControl == "" {
		cacheControl = "public, max-age=" + strconv.Itoa(int(ttl.Seconds()))
	}

	return &cachedDoc{
		body:         body,
		contentType:  contentType,
		cacheControl: cacheControl,
		expiresAt:    h.clock().Add(ttl),
	}, nil
}

// validateNonEmptyKeyset ensures the upstream document is a JWKS with >=1 key.
// An empty keyset is treated as unavailable (fail-closed) — never served as a
// success (a keyless JWKS verifies nothing).
func validateNonEmptyKeyset(body []byte) error {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("upstream body is not a JWKS document: %w", err)
	}
	if len(doc.Keys) == 0 {
		return fmt.Errorf("upstream JWKS has no keys")
	}
	return nil
}

// parseMaxAge extracts the `max-age=<seconds>` directive from a Cache-Control
// header. Returns (0, false) when absent/unparseable.
func parseMaxAge(cc string) (time.Duration, bool) {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			secs, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || secs < 0 {
				return 0, false
			}
			return time.Duration(secs) * time.Second, true
		}
	}
	return 0, false
}

// writeFailClosed emits a fixed opaque JSON error (no upstream/pgx text leak, no
// keys, never a kacho-* kid).
func writeFailClosed(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, reason)
}
