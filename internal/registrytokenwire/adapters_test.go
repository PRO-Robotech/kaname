// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenwire

import (
	"context"
	"errors"
	"testing"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeSAByID — a scripted reverse lookup by Hydra client_id.
type fakeSAByID struct {
	row domain.ServiceAccountOAuthClient
	err error
}

func (f fakeSAByID) GetByOAuthClientID(_ context.Context, _ domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return f.row, f.err
}

// TestSAClientLookup_MapsRegisteredKey — the adapter maps the SA row to the shim's
// RegisteredKey (kid=soc id, client_id=hydra id, subject=owning SA, public half).
func TestSAClientLookup_MapsRegisteredKey(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	row := domain.ServiceAccountOAuthClient{
		ID:            "soc_01abcdefghjkmnpqr",
		SvaID:         "sva_ci",
		OAuthClientID: "cid-ci",
		PublicKeyPEM:  "PEM-A",
		KeyAlgorithm:  "ES256",
		ExpiresAt:     &exp,
	}
	look := NewSAClientLookup(fakeSAByID{row: row})
	got, err := look.KeyByClientID(context.Background(), "cid-ci")
	if err != nil {
		t.Fatalf("KeyByClientID: %v", err)
	}
	want := registrytokenuc.RegisteredKey{
		ClientID:     "cid-ci",
		KeyID:        "soc_01abcdefghjkmnpqr",
		Subject:      "sva_ci",
		PublicKeyPEM: "PEM-A",
		KeyAlgorithm: "ES256",
		ExpiresAt:    &exp,
	}
	if got != want {
		t.Fatalf("RegisteredKey = %+v; want %+v", got, want)
	}
}

// TestSAClientLookup_PropagatesError — an unknown/failed lookup surfaces an error
// (the validator collapses it to ErrInvalidCredentials).
func TestSAClientLookup_PropagatesError(t *testing.T) {
	look := NewSAClientLookup(fakeSAByID{err: errors.New("not found")})
	if _, err := look.KeyByClientID(context.Background(), "cid-nope"); err == nil {
		t.Fatal("expected error for a failed lookup")
	}
}

// fakeHydraTokenClient — a scripted Hydra public token endpoint.
type fakeHydraTokenClient struct {
	out clients.TokenResponse
	err error
	got clients.ClientCredentialsRequest
}

func (f *fakeHydraTokenClient) ClientCredentials(_ context.Context, req clients.ClientCredentialsRequest) (clients.TokenResponse, error) {
	f.got = req
	return f.out, f.err
}

// TestHydraExchange_Happy — the adapter forwards the exchange and returns Hydra's
// access_token.
func TestHydraExchange_Happy(t *testing.T) {
	fc := &fakeHydraTokenClient{out: clients.TokenResponse{AccessToken: "hydra-jwt", ExpiresIn: 3600}}
	out, err := NewHydraExchange(fc).Exchange(context.Background(), registrytokenuc.ExchangeInput{
		ClientAssertion: "assertion", Audience: "registry.kacho.local", Scope: "reg",
	})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if out.AccessToken != "hydra-jwt" || out.ExpiresIn != 3600 {
		t.Fatalf("out = %+v", out)
	}
	if fc.got.ClientAssertion != "assertion" || fc.got.Audience != "registry.kacho.local" || fc.got.Scope != "reg" {
		t.Fatalf("forwarded request = %+v", fc.got)
	}
}

// TestHydraExchange_UnavailableMapsToIssuerUnavailable — a Hydra-unavailable
// client error maps to the use-case's fail-closed 503 sentinel.
func TestHydraExchange_UnavailableMapsToIssuerUnavailable(t *testing.T) {
	fc := &fakeHydraTokenClient{err: clients.ErrHydraUnavailable}
	_, err := NewHydraExchange(fc).Exchange(context.Background(), registrytokenuc.ExchangeInput{ClientAssertion: "a"})
	if !errors.Is(err, registrytokenuc.ErrIssuerUnavailable) {
		t.Fatalf("err = %v; want ErrIssuerUnavailable", err)
	}
}

// TestHydraExchange_RejectedMapsToInvalidCredentials — a Hydra rejection maps to
// the credential-invalid sentinel (→ 401 challenge upstream), not a 503.
func TestHydraExchange_RejectedMapsToInvalidCredentials(t *testing.T) {
	fc := &fakeHydraTokenClient{err: clients.ErrHydraRejected}
	_, err := NewHydraExchange(fc).Exchange(context.Background(), registrytokenuc.ExchangeInput{ClientAssertion: "a"})
	if !errors.Is(err, registrytokenuc.ErrInvalidCredentials) {
		t.Fatalf("err = %v; want ErrInvalidCredentials", err)
	}
}
