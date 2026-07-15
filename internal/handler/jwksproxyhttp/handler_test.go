// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package jwksproxyhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Hydra-mirrored JWKS fixtures. The whole point of the proxy is that the served
// kids are Hydra's ACTUAL signing kids — never iam's own `kacho-*` oidc_jwks_keys
// kids (which would be a guaranteed kid-miss / fail-closed reject of every pull).
const (
	hydraJWKS1 = `{"keys":[{"kty":"RSA","use":"sig","kid":"hydra-kid-1","alg":"RS256","n":"sbjXaaaa","e":"AQAB"}]}`
	hydraJWKS2 = `{"keys":[{"kty":"RSA","use":"sig","kid":"hydra-kid-1","alg":"RS256","n":"sbjXaaaa","e":"AQAB"},{"kty":"RSA","use":"sig","kid":"hydra-kid-2","alg":"RS256","n":"ZZZdefff","e":"AQAB"}]}`
	emptyJWKS  = `{"keys":[]}`
)

// fakeClock is an injectable, advanceable clock so cache-TTL / rotation tests are
// deterministic (never time.Sleep — testing.md).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// upstream is a scripted fake Hydra JWKS server with a hit counter and a togglable
// body / status so a test can simulate rotation, a brief blip, or a hard outage.
type upstream struct {
	mu      sync.Mutex
	body    string
	status  int
	cc      string // Cache-Control the fake upstream advertises (may be empty)
	hits    int
	blockCh chan struct{} // when non-nil, the handler blocks on it before responding
}

func (u *upstream) setBody(b string) { u.mu.Lock(); defer u.mu.Unlock(); u.body = b }
func (u *upstream) setStatus(s int)  { u.mu.Lock(); defer u.mu.Unlock(); u.status = s }
func (u *upstream) hitCount() int    { u.mu.Lock(); defer u.mu.Unlock(); return u.hits }

func (u *upstream) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	u.mu.Lock()
	u.hits++
	block := u.blockCh
	body, status, cc := u.body, u.status, u.cc
	u.mu.Unlock()

	if block != nil {
		<-block // simulate a hung / half-open upstream
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func newUpstream(body string) *upstream {
	return &upstream{body: body, status: http.StatusOK, cc: "public, max-age=300"}
}

// kidsOf extracts the kid values from a JWKS document body.
func kidsOf(t *testing.T, body []byte) []string {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	kids := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func doGet(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, WellKnownJWKSPath, nil)
	h.ServeHTTP(rec, req)
	return rec
}

// RJU-01 — happy: iam serves a BYTE-IDENTICAL mirror of Hydra's JWKS with
// Cache-Control, and the served kids are Hydra's kids (not any kacho-* kid).
func TestJWKSProxy_RJU01_ByteIdenticalMirror(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	srv := httptest.NewServer(up)
	defer srv.Close()

	h := NewHandler(Config{UpstreamURL: srv.URL})
	rec := doGet(t, h)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	if got := rec.Body.String(); got != hydraJWKS1 {
		t.Fatalf("body not byte-identical to upstream JWKS.\n got=%q\nwant=%q", got, hydraJWKS1)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Fatalf("Cache-Control header not set")
	}
	kids := kidsOf(t, rec.Body.Bytes())
	if len(kids) != 1 || kids[0] != "hydra-kid-1" {
		t.Fatalf("served kids = %v; want [hydra-kid-1]", kids)
	}
	for _, k := range kids {
		if strings.HasPrefix(k, "kacho-") {
			t.Fatalf("served an iam kacho-* kid %q — proxy must mirror Hydra kids only", k)
		}
	}
}

// RJU-02 — the upstream fetch uses a per-call-timeout http.Client, never
// http.DefaultClient (architecture.md: DefaultClient has no Timeout → a hung peer
// wedges the goroutine forever). Two arms: (a) the constructed client is not the
// shared DefaultClient and carries a timeout; (b) a hung upstream returns
// fail-closed within a bounded time instead of hanging.
func TestJWKSProxy_RJU02_PerCallTimeoutNotDefaultClient(t *testing.T) {
	h := NewHandler(Config{UpstreamURL: "http://127.0.0.1:1/.well-known/jwks.json"})
	if h.client == http.DefaultClient {
		t.Fatalf("handler uses http.DefaultClient (no Timeout) on the upstream hot-path")
	}
	if h.client.Timeout <= 0 {
		t.Fatalf("handler http.Client has no per-call Timeout (got %v)", h.client.Timeout)
	}

	// (b) behavioural: a hung upstream must not wedge the request.
	up := newUpstream(hydraJWKS1)
	up.blockCh = make(chan struct{})
	srv := httptest.NewServer(up)
	defer srv.Close()
	defer close(up.blockCh) // unblock the server goroutine BEFORE srv.Close()

	h2 := NewHandler(Config{UpstreamURL: srv.URL, Timeout: 100 * time.Millisecond})
	start := time.Now()
	rec := doGet(t, h2)
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("request did not honor per-call timeout (elapsed %v)", elapsed)
	}
	if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("hung upstream: status = %d; want 502/503 (fail-closed)", rec.Code)
	}
}

// RJU-03 — fail-closed: a COLD cache + an unavailable Hydra (5xx / unreachable /
// empty keyset) must yield 502/503 — never an empty 200, never iam's own kacho-*
// kids as a substitute.
func TestJWKSProxy_RJU03_FailClosedColdUpstreamDown(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T) *Handler
	}{
		{
			name: "upstream 5xx",
			build: func(t *testing.T) *Handler {
				up := newUpstream(hydraJWKS1)
				up.setStatus(http.StatusInternalServerError)
				srv := httptest.NewServer(up)
				t.Cleanup(srv.Close)
				return NewHandler(Config{UpstreamURL: srv.URL})
			},
		},
		{
			name: "upstream empty keyset",
			build: func(t *testing.T) *Handler {
				up := newUpstream(emptyJWKS)
				srv := httptest.NewServer(up)
				t.Cleanup(srv.Close)
				return NewHandler(Config{UpstreamURL: srv.URL})
			},
		},
		{
			name: "upstream unreachable",
			build: func(t *testing.T) *Handler {
				srv := httptest.NewServer(newUpstream(hydraJWKS1))
				url := srv.URL
				srv.Close() // now unreachable
				return NewHandler(Config{UpstreamURL: url, Timeout: 200 * time.Millisecond})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.build(t)
			rec := doGet(t, h)

			if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d; want 502/503 (fail-closed)", rec.Code)
			}
			// Never an empty-200 masquerading as success.
			if rec.Code == http.StatusOK {
				t.Fatalf("served 200 on a cold cache + down upstream (fail-open)")
			}
			// Never a non-empty Hydra-shaped keyset, and never a kacho-* kid.
			if kids := kidsOf(t, rec.Body.Bytes()); len(kids) > 0 {
				t.Fatalf("fail-closed body carried keys %v; must serve no keys", kids)
			}
			if strings.Contains(rec.Body.String(), "kacho-") {
				t.Fatalf("fail-closed body leaked an iam kacho-* kid: %q", rec.Body.String())
			}
		})
	}
}

// RJU-04 — bounded-stale: a warm cache within TTL survives a brief Hydra blip
// (served from cache, upstream not re-hit); once TTL elapses and Hydra is still
// down the endpoint degrades to fail-closed (never indefinitely-stale).
func TestJWKSProxy_RJU04_BoundedStaleWarmBlip(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	up.cc = "" // force the default TTL path (no upstream Cache-Control)
	srv := httptest.NewServer(up)
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := NewHandler(Config{UpstreamURL: srv.URL, TTL: 5 * time.Minute, Clock: clk.Now})

	// Warm the cache.
	if rec := doGet(t, h); rec.Code != http.StatusOK {
		t.Fatalf("warm-up status = %d; want 200", rec.Code)
	}
	if up.hitCount() != 1 {
		t.Fatalf("warm-up upstream hits = %d; want 1", up.hitCount())
	}

	// Hydra blips down, but we're within TTL → served from cache, no re-fetch.
	up.setStatus(http.StatusInternalServerError)
	rec := doGet(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("within-TTL blip status = %d; want 200 (bounded-stale from cache)", rec.Code)
	}
	if up.hitCount() != 1 {
		t.Fatalf("within-TTL blip re-hit upstream (hits=%d); must serve from cache", up.hitCount())
	}
	if got := rec.Body.String(); got != hydraJWKS1 {
		t.Fatalf("within-TTL blip body = %q; want cached %q", got, hydraJWKS1)
	}

	// TTL elapses, Hydra still down → fail-closed (never indefinitely-stale).
	clk.Advance(6 * time.Minute)
	rec = doGet(t, h)
	if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-TTL + down status = %d; want 502/503 (never indefinitely-stale)", rec.Code)
	}
}

// MaxAgeCeiling — a LARGE upstream Cache-Control max-age must NOT extend our cache
// past the configured TTL ceiling. h.ttl is a hard freshness bound: iam is the
// data-plane's token-verification anchor, so a CDN/Ory advertising max-age=24h must
// never make iam serve a rotated/revoked keyset past the short window. Regression
// for the go-style review finding (max-age honored with no ceiling).
func TestJWKSProxy_MaxAgeCeiling(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	up.cc = "public, max-age=86400" // 24h — far larger than the 5m TTL ceiling
	srv := httptest.NewServer(up)
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := NewHandler(Config{UpstreamURL: srv.URL, TTL: 5 * time.Minute, Clock: clk.Now})

	// Warm the cache (upstream advertises 24h freshness).
	if rec := doGet(t, h); rec.Code != http.StatusOK {
		t.Fatalf("warm-up status = %d; want 200", rec.Code)
	}

	// Advance PAST the 5m ceiling but far WITHIN the upstream's 24h max-age, then take
	// Hydra down. If the ceiling holds, the cache is expired at 6m → refetch → down →
	// fail-closed. If max-age were honored uncapped, it would still serve stale at 6m.
	clk.Advance(6 * time.Minute)
	up.setStatus(http.StatusInternalServerError)
	rec := doGet(t, h)
	if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-ceiling + down status = %d; want 502/503 (h.ttl caps upstream max-age)", rec.Code)
	}
}

// Cache: a second call within TTL does NOT re-hit upstream; after TTL it refetches.
func TestJWKSProxy_Cache_TTLRefetch(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	up.cc = ""
	srv := httptest.NewServer(up)
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := NewHandler(Config{UpstreamURL: srv.URL, TTL: 5 * time.Minute, Clock: clk.Now})

	doGet(t, h)
	if up.hitCount() != 1 {
		t.Fatalf("first call hits = %d; want 1", up.hitCount())
	}
	doGet(t, h)
	if up.hitCount() != 1 {
		t.Fatalf("second call within TTL hits = %d; want 1 (served from cache)", up.hitCount())
	}
	clk.Advance(6 * time.Minute)
	doGet(t, h)
	if up.hitCount() != 2 {
		t.Fatalf("call after TTL hits = %d; want 2 (refetch)", up.hitCount())
	}
}

// RJU-05 — rotation: Hydra publishes a new kid; after TTL iam refetches and serves
// the updated keyset containing the new Hydra kid (still never a kacho-* kid).
func TestJWKSProxy_RJU05_RotationNewKid(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	up.cc = ""
	srv := httptest.NewServer(up)
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	h := NewHandler(Config{UpstreamURL: srv.URL, TTL: 5 * time.Minute, Clock: clk.Now})

	rec := doGet(t, h)
	if kids := kidsOf(t, rec.Body.Bytes()); len(kids) != 1 || kids[0] != "hydra-kid-1" {
		t.Fatalf("pre-rotation kids = %v; want [hydra-kid-1]", kids)
	}

	up.setBody(hydraJWKS2) // Hydra rotates
	clk.Advance(6 * time.Minute)

	rec = doGet(t, h)
	kids := kidsOf(t, rec.Body.Bytes())
	found := false
	for _, k := range kids {
		if k == "hydra-kid-2" {
			found = true
		}
		if strings.HasPrefix(k, "kacho-") {
			t.Fatalf("rotation served a kacho-* kid %q", k)
		}
	}
	if !found {
		t.Fatalf("post-rotation kids = %v; want to contain hydra-kid-2", kids)
	}
}

// The JWKS route rejects non-GET methods (it is a read-only well-known endpoint).
func TestJWKSProxy_MethodNotAllowed(t *testing.T) {
	up := newUpstream(hydraJWKS1)
	srv := httptest.NewServer(up)
	defer srv.Close()

	h := NewHandler(Config{UpstreamURL: srv.URL})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, WellKnownJWKSPath, nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d; want 405", rec.Code)
	}
}
