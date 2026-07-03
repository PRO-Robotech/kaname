// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// fakeValidator — a scripted APITokenValidator.
type fakeValidator struct {
	subject Subject
	err     error
	gotUser string
	gotPass string
}

func (f *fakeValidator) Validate(_ context.Context, u, p string) (Subject, error) {
	f.gotUser, f.gotPass = u, p
	return f.subject, f.err
}

// staticRSAProvider — a fixed RS256 key for signer wiring in tests.
type staticRSAProvider struct {
	kid  string
	priv *rsa.PrivateKey
}

func (s staticRSAProvider) CurrentRSA(context.Context) (string, *rsa.PrivateKey, error) {
	return s.kid, s.priv, nil
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	return k
}

// TestExecute_HappyPath_MintsVerifiableIdentityJWT — valid creds → an RS256 JWT
// carrying the resolved subject, verifiable against the signing public key, with
// iss/aud/exp/iat/jti and exp = iat + TTL (identity-only, no scope claim).
func TestExecute_HappyPath_MintsVerifiableIdentityJWT(t *testing.T) {
	priv := genRSA(t)
	fixedNow := time.Unix(1_700_000_000, 0)

	uc := NewIssueRegistryTokenUseCase(
		Config{Issuer: "https://api.kacho.local/iam/token", DefaultService: "registry.kacho.local", TTL: 3 * time.Minute},
		&fakeValidator{subject: Subject{ID: "sva0123456789abcde"}},
		NewRS256Signer(staticRSAProvider{kid: "kacho-rs256-1", priv: priv}),
	).WithClock(func() time.Time { return fixedNow }).
		WithJTIFunc(func() (string, error) { return "jti-fixed", nil })

	out, err := uc.Execute(context.Background(), IssueInput{
		Username: "sva0123456789abcde", Password: "the-sa-key", Service: "registry.kacho.local",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Token == "" {
		t.Fatal("expected a non-empty token")
	}
	if out.ExpiresIn != 180 {
		t.Fatalf("expires_in = %d; want 180", out.ExpiresIn)
	}

	got, err := registrytoken.VerifyRS256(out.Token, &priv.PublicKey)
	if err != nil {
		t.Fatalf("token must verify against signing key: %v", err)
	}
	if got.Issuer != "https://api.kacho.local/iam/token" {
		t.Errorf("iss = %q", got.Issuer)
	}
	if got.Subject != "sva0123456789abcde" {
		t.Errorf("sub = %q; want the resolved subject id", got.Subject)
	}
	if got.Audience != "registry.kacho.local" {
		t.Errorf("aud = %q; want the service", got.Audience)
	}
	if got.IssuedAt != fixedNow.Unix() {
		t.Errorf("iat = %d; want %d", got.IssuedAt, fixedNow.Unix())
	}
	if got.ExpiresAt != fixedNow.Add(3*time.Minute).Unix() {
		t.Errorf("exp = %d; want iat+TTL", got.ExpiresAt)
	}
	if got.JTI != "jti-fixed" {
		t.Errorf("jti = %q", got.JTI)
	}
}

// TestExecute_ServiceFallsBackToDefault — empty ?service= → DefaultService aud.
func TestExecute_ServiceFallsBackToDefault(t *testing.T) {
	priv := genRSA(t)
	uc := NewIssueRegistryTokenUseCase(
		Config{Issuer: "iss", DefaultService: "registry.kacho.local", TTL: time.Minute},
		&fakeValidator{subject: Subject{ID: "sva1"}},
		NewRS256Signer(staticRSAProvider{kid: "k", priv: priv}),
	)
	out, err := uc.Execute(context.Background(), IssueInput{Username: "sva1", Password: "x"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got, _ := registrytoken.VerifyRS256(out.Token, &priv.PublicKey)
	if got.Audience != "registry.kacho.local" {
		t.Errorf("aud = %q; want DefaultService fallback", got.Audience)
	}
}

// TestExecute_InvalidCredentials_Unauthenticated — a validator rejection surfaces
// as ErrUnauthenticated (fail-closed) and NO token is minted.
func TestExecute_InvalidCredentials_Unauthenticated(t *testing.T) {
	priv := genRSA(t)
	uc := NewIssueRegistryTokenUseCase(
		Config{Issuer: "iss", DefaultService: "svc", TTL: time.Minute},
		&fakeValidator{err: ErrInvalidCredentials},
		NewRS256Signer(staticRSAProvider{kid: "k", priv: priv}),
	)
	out, err := uc.Execute(context.Background(), IssueInput{Username: "sva1", Password: "wrong"})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v; want ErrUnauthenticated", err)
	}
	if out.Token != "" {
		t.Fatal("no token must be minted on invalid credentials")
	}
}

// TestExecute_TTLClampedToMax — a TTL above the ceiling is clamped to MaxTTL.
func TestExecute_TTLClampedToMax(t *testing.T) {
	priv := genRSA(t)
	uc := NewIssueRegistryTokenUseCase(
		Config{Issuer: "iss", DefaultService: "svc", TTL: time.Hour}, // > MaxTTL
		&fakeValidator{subject: Subject{ID: "sva1"}},
		NewRS256Signer(staticRSAProvider{kid: "k", priv: priv}),
	)
	if uc.TTL() != MaxTTL {
		t.Fatalf("TTL() = %v; want clamp to %v", uc.TTL(), MaxTTL)
	}
	out, err := uc.Execute(context.Background(), IssueInput{Username: "sva1", Password: "x"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.ExpiresIn != int(MaxTTL.Seconds()) {
		t.Fatalf("expires_in = %d; want %d", out.ExpiresIn, int(MaxTTL.Seconds()))
	}
}
