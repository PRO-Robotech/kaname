// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeValidator — a scripted CredentialValidator.
type fakeValidator struct {
	cred    Credential
	err     error
	gotUser string
	gotPass string
}

func (f *fakeValidator) Validate(_ context.Context, clientID, privateKeyPEM string) (Credential, error) {
	f.gotUser, f.gotPass = clientID, privateKeyPEM
	return f.cred, f.err
}

// fakeSigner — records the assertion input and returns a canned assertion.
type fakeSigner struct {
	got AssertionInput
	err error
}

func (f *fakeSigner) Sign(in AssertionInput) (string, error) {
	f.got = in
	if f.err != nil {
		return "", f.err
	}
	return "assertion.for." + in.ClientID, nil
}

// fakeExchanger — a scripted TokenExchanger.
type fakeExchanger struct {
	out ExchangeOutput
	err error
	got ExchangeInput
}

func (f *fakeExchanger) Exchange(_ context.Context, in ExchangeInput) (ExchangeOutput, error) {
	f.got = in
	return f.out, f.err
}

// TestExecute_HappyPath_BrokersHydraToken — a valid SA-key is verified, an ES256
// client_assertion is built (kid, iss=sub=client_id, aud=assertion-audience,
// exp≤60s), and the shim relays Hydra's access_token in the docker form.
func TestExecute_HappyPath_BrokersHydraToken(t *testing.T) {
	fixedNow := time.Unix(1_700_000_000, 0)
	val := &fakeValidator{cred: Credential{ClientID: "cid-ci", KeyID: "soc_key1", Subject: "sva0123456789abcde"}}
	sig := &fakeSigner{}
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "hydra-jwt", ExpiresIn: 3600}}

	uc := NewIssueRegistryTokenUseCase(
		Config{AssertionAudience: "https://hydra.api.kacho.cloud/oauth2/token", DefaultService: "registry.kacho.local"},
		val, sig, ex,
	).WithClock(func() time.Time { return fixedNow }).
		WithJTIFunc(func() (string, error) { return "jti-fixed", nil })

	out, err := uc.Execute(context.Background(), IssueInput{
		Username: "cid-ci", Password: "-----private-pem-----", Service: "registry.kacho.local",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Token != "hydra-jwt" || out.ExpiresIn != 3600 {
		t.Fatalf("out = %+v; want Hydra token + expires_in", out)
	}
	// The credential was verified with the presented client_id + private PEM.
	if val.gotUser != "cid-ci" || val.gotPass != "-----private-pem-----" {
		t.Errorf("validator got (%q,%q)", val.gotUser, val.gotPass)
	}
	// The assertion is built from the verified credential (identity is not taken
	// from the presented username after verification).
	if sig.got.ClientID != "cid-ci" || sig.got.KeyID != "soc_key1" {
		t.Errorf("assertion identity = (%q,%q)", sig.got.ClientID, sig.got.KeyID)
	}
	if sig.got.PrivateKeyPEM != "-----private-pem-----" {
		t.Errorf("assertion must be signed with the presented private key")
	}
	if sig.got.Audience != "https://hydra.api.kacho.cloud/oauth2/token" {
		t.Errorf("assertion aud = %q; want the Hydra token endpoint", sig.got.Audience)
	}
	if sig.got.JTI != "jti-fixed" || sig.got.IssuedAt != fixedNow.Unix() {
		t.Errorf("assertion jti/iat = %q/%d", sig.got.JTI, sig.got.IssuedAt)
	}
	if ttl := sig.got.ExpiresAt - sig.got.IssuedAt; ttl <= 0 || ttl > int64(MaxAssertionTTL.Seconds()) {
		t.Errorf("assertion exp-iat = %d; want (0, %d]", ttl, int64(MaxAssertionTTL.Seconds()))
	}
	// The requested token audience is the registry service.
	if ex.got.ClientAssertion != "assertion.for.cid-ci" || ex.got.Audience != "registry.kacho.local" {
		t.Errorf("exchange = %+v", ex.got)
	}
}

// TestExecute_ServiceFallsBackToDefault — empty ?service= → DefaultService as the
// requested token audience.
func TestExecute_ServiceFallsBackToDefault(t *testing.T) {
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "t", ExpiresIn: 60}}
	uc := NewIssueRegistryTokenUseCase(
		Config{AssertionAudience: "aud", DefaultService: "registry.kacho.local"},
		&fakeValidator{cred: Credential{ClientID: "cid", KeyID: "soc_1"}}, &fakeSigner{}, ex,
	)
	if _, err := uc.Execute(context.Background(), IssueInput{Username: "cid", Password: "x"}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if ex.got.Audience != "registry.kacho.local" {
		t.Errorf("requested aud = %q; want DefaultService", ex.got.Audience)
	}
}

// TestExecute_AnonymousOrInvalid_Unauthenticated — a missing credential and a
// validator rejection both fail closed as ErrUnauthenticated with NO exchange.
func TestExecute_AnonymousOrInvalid_Unauthenticated(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   IssueInput
		vErr error
	}{
		{"empty username", IssueInput{Username: "", Password: "x"}, nil},
		{"empty password", IssueInput{Username: "cid", Password: ""}, nil},
		{"validator reject", IssueInput{Username: "cid", Password: "x"}, ErrInvalidCredentials},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "should-not-happen"}}
			uc := NewIssueRegistryTokenUseCase(Config{AssertionAudience: "aud", DefaultService: "svc"},
				&fakeValidator{err: tc.vErr}, &fakeSigner{}, ex)
			out, err := uc.Execute(context.Background(), tc.in)
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("err = %v; want ErrUnauthenticated", err)
			}
			if out.Token != "" || ex.got.ClientAssertion != "" {
				t.Fatalf("no token / no exchange must occur on auth failure")
			}
		})
	}
}

// TestExecute_HydraUnavailable_FailClosed — the issuer being unreachable surfaces
// as ErrIssuerUnavailable (→ 503 at the handler), never a token.
func TestExecute_HydraUnavailable_FailClosed(t *testing.T) {
	uc := NewIssueRegistryTokenUseCase(Config{AssertionAudience: "aud", DefaultService: "svc"},
		&fakeValidator{cred: Credential{ClientID: "cid", KeyID: "soc_1"}}, &fakeSigner{},
		&fakeExchanger{err: ErrIssuerUnavailable})
	out, err := uc.Execute(context.Background(), IssueInput{Username: "cid", Password: "x"})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v; want ErrIssuerUnavailable", err)
	}
	if out.Token != "" {
		t.Fatal("no token on issuer-unavailable")
	}
}

// TestExecute_HydraRejected_Unauthenticated — a Hydra rejection (bad/revoked key)
// collapses to ErrUnauthenticated (→ 401 challenge), not a 503.
func TestExecute_HydraRejected_Unauthenticated(t *testing.T) {
	uc := NewIssueRegistryTokenUseCase(Config{AssertionAudience: "aud", DefaultService: "svc"},
		&fakeValidator{cred: Credential{ClientID: "cid", KeyID: "soc_1"}}, &fakeSigner{},
		&fakeExchanger{err: errors.New("rejected")})
	_, err := uc.Execute(context.Background(), IssueInput{Username: "cid", Password: "x"})
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v; want ErrUnauthenticated", err)
	}
}
