// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package iamhooks_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/handler/iamhooks"
)

// fakeProvisioner records the last ProvisionInput it received and can be
// configured to return an error (use-case failure path).
type fakeProvisioner struct {
	mu      sync.Mutex
	called  bool
	last    iamhooks.ProvisionInput
	retErr  error
	callCnt int
}

func (f *fakeProvisioner) Provision(_ context.Context, in iamhooks.ProvisionInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.callCnt++
	f.last = in
	return f.retErr
}

func (f *fakeProvisioner) snapshot() (bool, int, iamhooks.ProvisionInput) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called, f.callCnt, f.last
}

func newProvisionHandler(t *testing.T, prov iamhooks.UserProvisioner, logBuf io.Writer) *iamhooks.ProvisionHookHandler {
	t.Helper()
	if logBuf == nil {
		logBuf = io.Discard
	}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return iamhooks.NewProvisionHookHandler(
		iamhooks.ProvisionHookConfig{HookSharedSecret: "secret"},
		prov,
		logger,
	)
}

// identity-payload.jsonnet emits {external_id, email, display_name} — the
// shape the handler decodes. Keep this body in lockstep with the jsonnet
// authored in kacho-deploy.
const validProvisionBody = `{
	"external_id": "kratos-uuid-1",
	"email": "alice@example.com",
	"display_name": "Alice Example"
}`

func TestProvisionHook_HappyPath_CallsProvisionerAnd200(t *testing.T) {
	prov := &fakeProvisioner{}
	var logBuf bytes.Buffer
	h := newProvisionHandler(t, prov, &logBuf)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(validProvisionBody))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	called, cnt, last := prov.snapshot()
	require.True(t, called, "provisioner must be invoked on a valid hook call")
	assert.Equal(t, 1, cnt)
	assert.Equal(t, "kratos-uuid-1", last.ExternalID)
	assert.Equal(t, "alice@example.com", last.Email)
	assert.Equal(t, "Alice Example", last.DisplayName)
	// PII leak-lock (audit r3): the success INFO log must correlate by external_id
	// only — the end-user email must NOT leak into logs.
	assert.NotContains(t, logBuf.String(), "alice@example.com", "end-user email (PII) must not leak into logs")
}

func TestProvisionHook_MissingToken_401_ProvisionerNotCalled(t *testing.T) {
	prov := &fakeProvisioner{}
	h := newProvisionHandler(t, prov, nil)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(validProvisionBody))
	// no X-Kacho-Hook-Token header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	called, _, _ := prov.snapshot()
	assert.False(t, called, "provisioner must NOT be called without a valid token")
}

func TestProvisionHook_WrongToken_401_ProvisionerNotCalled(t *testing.T) {
	prov := &fakeProvisioner{}
	h := newProvisionHandler(t, prov, nil)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(validProvisionBody))
	req.Header.Set("X-Kacho-Hook-Token", "wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	called, _, _ := prov.snapshot()
	assert.False(t, called)
}

func TestProvisionHook_MalformedJSON_400_ProvisionerNotCalled(t *testing.T) {
	prov := &fakeProvisioner{}
	h := newProvisionHandler(t, prov, nil)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(`{not-json`))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	called, _, _ := prov.snapshot()
	assert.False(t, called, "provisioner must NOT be called on a malformed body")
}

// TestProvisionHook_ProvisionerError_500_AndLogged — a use-case failure MUST
// surface as a 5xx (so Kratos does not silently treat it as OK) AND be logged
// (so a broken hook is observable, not silent — the entire point of C4).
func TestProvisionHook_ProvisionerError_500_AndLogged(t *testing.T) {
	prov := &fakeProvisioner{retErr: errors.New("upsert: db unavailable")}
	var logBuf bytes.Buffer
	h := newProvisionHandler(t, prov, &logBuf)

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(validProvisionBody))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code, "use-case error must be a 5xx, not a silent 200; body: %s", w.Body.String())
	called, _, _ := prov.snapshot()
	assert.True(t, called)
	assert.Contains(t, logBuf.String(), "provision", "the hook failure must be logged so it is observable")
	// PII leak-lock (audit r3): the end-user email must NEVER appear in the failure log.
	assert.NotContains(t, logBuf.String(), "alice@example.com", "end-user email (PII) must not leak into logs")
}

func TestProvisionHook_WrongMethod_405(t *testing.T) {
	prov := &fakeProvisioner{}
	h := newProvisionHandler(t, prov, nil)

	req := httptest.NewRequest("GET", "/iam/v1/hooks/provision", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// TestProvisionHook_OversizedBody_413 — a post-auth caller (holding the hook
// shared-secret) that streams a body larger than the hook body cap must be
// rejected with 413 BEFORE the JSON decoder allocates it, and the use-case must
// NOT be invoked (CWE-770 unbounded-allocation guard on the :9092 hook mux).
func TestProvisionHook_OversizedBody_413(t *testing.T) {
	prov := &fakeProvisioner{}
	h := newProvisionHandler(t, prov, nil)

	// >1 MiB of valid JSON: a single huge string field. The decoder must never
	// buffer the whole thing — MaxBytesReader trips first.
	huge := strings.Repeat("a", (1<<20)+4096)
	body := `{"external_id":"` + huge + `","email":"a@b.c","display_name":"x"}`

	req := httptest.NewRequest("POST", "/iam/v1/hooks/provision", strings.NewReader(body))
	req.Header.Set("X-Kacho-Hook-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized hook body must be capped at 413; body: %s", w.Body.String())
	called, _, _ := prov.snapshot()
	assert.False(t, called, "use-case must not run on an over-cap body")
}
