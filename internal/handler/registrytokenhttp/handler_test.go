// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
)

// fakeIssuer — scripted TokenIssuer (SA-key path + anonymous path).
type fakeIssuer struct {
	out     registrytokenuc.IssueOutput
	err     error
	gotUser string
	gotPass string
	gotSvc  string

	// Anonymous-pull path.
	anonEnabled bool
	anonOut     registrytokenuc.IssueOutput
	anonErr     error
	gotAnonSvc  string
}

func (f *fakeIssuer) Execute(_ context.Context, in registrytokenuc.IssueInput) (registrytokenuc.IssueOutput, error) {
	f.gotUser, f.gotPass, f.gotSvc = in.Username, in.Password, in.Service
	return f.out, f.err
}

func (f *fakeIssuer) AnonymousEnabled() bool { return f.anonEnabled }

func (f *fakeIssuer) ExecuteAnonymous(_ context.Context, service string) (registrytokenuc.IssueOutput, error) {
	f.gotAnonSvc = service
	return f.anonOut, f.anonErr
}

func basic(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

// rawJSONField returns the raw (un-decoded) JSON bytes of a top-level field, so a
// test can assert its wire shape (e.g. a quoted string vs a bare number).
func rawJSONField(t *testing.T, body []byte, field string) string {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	v, ok := raw[field]
	if !ok {
		t.Fatalf("field %q absent from body %s", field, body)
	}
	return string(v)
}

func newTokenHandler(iss TokenIssuer) *TokenHandler {
	return NewTokenHandler(Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, iss)
}

// TestToken_NoAuthorization_401Challenge — an anonymous request gets 401 with a
// Bearer WWW-Authenticate challenge naming the realm + service (secure-by-default).
func TestToken_NoAuthorization_401Challenge(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local&scope=repository:reg-A/app:pull,push", nil)
	newTokenHandler(&fakeIssuer{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wa, "Bearer ") ||
		!strings.Contains(wa, `realm="https://api.kacho.local/iam/token"`) ||
		!strings.Contains(wa, `service="registry.kacho.local"`) {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
}

// TestToken_ValidBasic_200DockerBody — valid Basic creds → 200 with the
// Docker-compatible {token, access_token, expires_in} body; the handler forwards
// service + credentials to the use-case.
func TestToken_ValidBasic_200DockerBody(t *testing.T) {
	iss := &fakeIssuer{out: registrytokenuc.IssueOutput{Token: "the.jwt.token", ExpiresIn: 300, IssuedAt: 1700000000}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local&scope=repository:reg-A/app:pull", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	newTokenHandler(iss).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if body["token"] != "the.jwt.token" || body["access_token"] != "the.jwt.token" {
		t.Fatalf("token/access_token = %v/%v", body["token"], body["access_token"])
	}
	if body["expires_in"].(float64) != 300 {
		t.Fatalf("expires_in = %v; want 300", body["expires_in"])
	}
	// issued_at MUST be an RFC3339 STRING (Docker Registry v2 token spec: the
	// docker client parses it via `time.Time.UnmarshalJSON`, which accepts ONLY a
	// JSON string). Serializing it as a bare Unix-epoch NUMBER breaks `docker
	// login` with «Time.UnmarshalJSON: input is not a JSON string» → no bearer is
	// minted → all pull/push 401. Assert both: (1) generic-JSON value is a string,
	// (2) the raw bytes for the field start with a quote, (3) it round-trips into
	// the SAME struct shape the docker client uses (IssuedAt time.Time).
	ia, ok := body["issued_at"].(string)
	if !ok {
		t.Fatalf("issued_at = %v (%T); want RFC3339 string", body["issued_at"], body["issued_at"])
	}
	if _, err := time.Parse(time.RFC3339, ia); err != nil {
		t.Fatalf("issued_at %q not RFC3339: %v", ia, err)
	}
	if want := time.Unix(1700000000, 0).UTC().Format(time.RFC3339); ia != want {
		t.Fatalf("issued_at = %q; want %q", ia, want)
	}
	// Raw JSON value must be a quoted string (a bare number has no leading quote).
	if raw := rawJSONField(t, rec.Body.Bytes(), "issued_at"); !strings.HasPrefix(raw, `"`) {
		t.Fatalf("issued_at raw JSON = %s; want a quoted string", raw)
	}
	// Docker-client fidelity: unmarshalling into `struct{ IssuedAt time.Time }`
	// (exactly what the docker client does) must SUCCEED — this is the failure
	// mode the fix guards against.
	var dockerView struct {
		IssuedAt time.Time `json:"issued_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dockerView); err != nil {
		t.Fatalf("docker-client unmarshal (time.Time) failed: %v", err)
	}
	if iss.gotUser != "cid-ci" || iss.gotPass != "sa-key-private-pem" || iss.gotSvc != "registry.kacho.local" {
		t.Fatalf("use-case input = %q/%q/%q", iss.gotUser, iss.gotPass, iss.gotSvc)
	}
}

// TestToken_InvalidCredentials_401 — a use-case ErrUnauthenticated → 401 challenge
// (no token leaked).
func TestToken_InvalidCredentials_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cid-ci", "wrong"))
	newTokenHandler(&fakeIssuer{err: registrytokenuc.ErrUnauthenticated}).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("401 body must not carry a token: %s", rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Bearer ") {
		t.Fatal("401 must carry a Bearer challenge")
	}
}

// TestToken_IssuerUnavailable_503 — Hydra being unreachable (a hard mint-path
// dependency) is fail-closed 503 with no token and no raw error leaked.
func TestToken_IssuerUnavailable_503(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	newTokenHandler(&fakeIssuer{err: registrytokenuc.ErrIssuerUnavailable}).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Fatalf("503 body must not carry a token: %s", rec.Body.String())
	}
}

// TestToken_NonBasicScheme_401 — a Bearer/garbage Authorization is not accepted as
// Basic; fail-closed 401.
func TestToken_NonBasicScheme_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	newTokenHandler(&fakeIssuer{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
}
