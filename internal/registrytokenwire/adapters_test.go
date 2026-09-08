// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenwire

import (
	"context"
	"errors"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/clients"
)

// Проб обратного резолва ключа служебной учётки здесь больше нет: адаптер снят
// вместе с приёмом ключевого материала в поле пароля (задача #1143). Остался
// обмен у прежнего издателя — им пользуется АНОНИМНЫЙ поток на контуре, ещё не
// переведённом на нашу чеканку.

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
