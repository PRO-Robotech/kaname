// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// anonConfig — a Config with anonymous pull ENABLED: a configured public
// identity whose Hydra client_id the registry data-plane resolves to the FGA
// wildcard AnonymousSubject (`user:*`). No user/SA credential is ever presented
// for the anonymous flow — the shim holds the anon signing key.
func anonConfig() Config {
	return Config{
		AssertionAudience: "https://hydra.api.kacho.cloud/oauth2/token",
		DefaultService:    "registry.kacho.local",
		Anonymous: AnonymousIdentity{
			ClientID:      "registry-anonymous",
			KeyID:         "anon_key1",
			PrivateKeyPEM: "-----anon-private-pem-----",
		},
	}
}

// TestExecuteAnonymous_IssuesReadOnlyPublicBearer — RG-1-B13. A `/token` request
// WITHOUT Basic creds (the docker anon-pull flow) mints a Bearer whose subject
// resolves to the public `user:*` principal, requested for the registry
// data-plane audience, with a bounded short-lived TTL. NO user credential is
// validated (anonymous = wildcard, not a specific user).
func TestExecuteAnonymous_IssuesReadOnlyPublicBearer(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 0)
	val := &fakeValidator{} // MUST NOT be invoked for an anonymous token.
	sig := &fakeSigner{}
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "hydra-anon-jwt", ExpiresIn: 120}}

	uc := NewIssueRegistryTokenUseCase(anonConfig(), val, sig, ex).
		WithClock(func() time.Time { return fixedNow }).
		WithJTIFunc(func() (string, error) { return "jti-anon", nil })

	if !uc.AnonymousEnabled() {
		t.Fatal("AnonymousEnabled() = false; want true when an anon identity is configured")
	}

	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if err != nil {
		t.Fatalf("ExecuteAnonymous: %v", err)
	}
	if out.Token != "hydra-anon-jwt" || out.ExpiresIn != 120 {
		t.Fatalf("out = %+v; want the anon Hydra bearer relayed", out)
	}
	// No user/SA credential is presented or validated for an anon token.
	if val.gotUser != "" || val.gotPass != "" {
		t.Errorf("validator invoked for anon token (%q,%q); anon presents no credential", val.gotUser, val.gotPass)
	}
	// The assertion is signed AS the configured anon identity — the client_id the
	// data-plane resolves to the public AnonymousSubject (`user:*`), NOT a user SA.
	if sig.got.ClientID != "registry-anonymous" || sig.got.KeyID != "anon_key1" {
		t.Errorf("anon assertion identity = (%q,%q); want the configured anon client", sig.got.ClientID, sig.got.KeyID)
	}
	if sig.got.PrivateKeyPEM != "-----anon-private-pem-----" {
		t.Errorf("anon assertion must be signed with the configured anon key, not a presented one")
	}
	// Bounded, short-lived TTL: the assertion is clamped to (0, MaxAssertionTTL].
	if ttl := sig.got.ExpiresAt - sig.got.IssuedAt; ttl <= 0 || ttl > int64(MaxAssertionTTL.Seconds()) {
		t.Errorf("anon assertion exp-iat = %d; want bounded (0, %d]", ttl, int64(MaxAssertionTTL.Seconds()))
	}
	// The requested token audience is the registry data-plane service.
	if ex.got.Audience != "registry.kacho.local" {
		t.Errorf("anon exchange aud = %q; want the registry data-plane service", ex.got.Audience)
	}
	// Contract: the anonymous principal is the FGA wildcard.
	if AnonymousSubject != "user:*" {
		t.Errorf("AnonymousSubject = %q; want the FGA wildcard user:*", AnonymousSubject)
	}
}

// TestExecuteAnonymous_ReadOnlyScope_NoWriteVerb — RG-1-B14. The anonymous token
// requests ONLY the read-only floor scope and NEVER a write/push verb, so a
// `docker push` with an anon token is denied downstream (403 DENIED): public-ness
// grants `user:*` a read wildcard only, never write.
func TestExecuteAnonymous_ReadOnlyScope_NoWriteVerb(t *testing.T) {
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "t", ExpiresIn: 60}}
	uc := NewIssueRegistryTokenUseCase(anonConfig(), &fakeValidator{}, &fakeSigner{}, ex)

	if _, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local"); err != nil {
		t.Fatalf("ExecuteAnonymous: %v", err)
	}
	// The requested scope is exactly the read-only floor.
	if ex.got.Scope != AnonymousReadScope {
		t.Fatalf("anon exchange scope = %q; want the read-only AnonymousReadScope", ex.got.Scope)
	}
	// Defense-in-depth: the anon scope carries NO write verb of any spelling.
	for _, writeVerb := range []string{"push", "write", "delete", "*"} {
		if strings.Contains(ex.got.Scope, writeVerb) {
			t.Errorf("anon scope %q carries write verb %q; anon is a read-only floor (B14)", ex.got.Scope, writeVerb)
		}
	}
	// The read-only scope must actually grant a read (pull) verb.
	if !strings.Contains(AnonymousReadScope, "pull") {
		t.Errorf("AnonymousReadScope = %q; want a read (pull) verb", AnonymousReadScope)
	}
}

// TestExecuteAnonymous_Disabled_FailClosed — anonymous pull DISABLED (no anon
// identity configured) fails closed with ErrUnauthenticated and performs NO
// exchange. Secure-by-default: the shim only serves anon tokens when explicitly
// configured; otherwise no-creds → 401 challenge at the handler.
func TestExecuteAnonymous_Disabled_FailClosed(t *testing.T) {
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "should-not-happen"}}
	uc := NewIssueRegistryTokenUseCase(
		Config{AssertionAudience: "aud", DefaultService: "svc"}, // no Anonymous identity.
		&fakeValidator{}, &fakeSigner{}, ex)

	if uc.AnonymousEnabled() {
		t.Fatal("AnonymousEnabled() = true; want false when no anon identity is configured")
	}
	out, err := uc.ExecuteAnonymous(context.Background(), "svc")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v; want ErrUnauthenticated (fail-closed → 401 challenge)", err)
	}
	if out.Token != "" || ex.got.ClientAssertion != "" {
		t.Fatal("disabled anon must not issue a token or perform an exchange")
	}
}

// TestExecuteAnonymous_IssuerUnavailable_FailClosed — Hydra unreachable during
// the anon exchange surfaces as ErrIssuerUnavailable (→ 503), never a token.
func TestExecuteAnonymous_IssuerUnavailable_FailClosed(t *testing.T) {
	uc := NewIssueRegistryTokenUseCase(anonConfig(), &fakeValidator{}, &fakeSigner{},
		&fakeExchanger{err: ErrIssuerUnavailable})
	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v; want ErrIssuerUnavailable", err)
	}
	if out.Token != "" {
		t.Fatal("no token on issuer-unavailable")
	}
}
