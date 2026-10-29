// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package presentedcred_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

// basicAuthorityProbe хранит только исход; проверяемый читатель определяет полосу.
type basicAuthorityProbe struct {
	credential domain.BasicCredential
	err        error
	calls      int
}

func (a *basicAuthorityProbe) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	a.calls++
	return a.credential, a.err
}

func TestDirectOpaqueCredential(t *testing.T) {
	raw, _, err := credsecret.Mint("sak-direct")
	if err != nil {
		t.Fatal(err)
	}
	a := &basicAuthorityProbe{}
	s := newStand(t, func(c *presentedcred.Config, s *stand) {
		c.BasicCredentials = a
		a.credential = domain.BasicCredential{PrincipalType: "service_account", PrincipalID: "sva-direct", CredentialID: "sak-direct", ExpiresAt: s.now.Add(time.Hour)}
	})
	for range 2 {
		p, seen, err := s.present(t, raw)
		if err != nil || !seen || p.Type != "service_account" || p.ID != "sva-direct" {
			t.Fatalf("identity: %v %v %v", p, seen, err)
		}
	}
	if a.calls != 2 {
		t.Fatal("opaque result was cached")
	}
	a.err = domain.ErrBasicCredentialRefused
	if _, seen, err := s.present(t, raw); seen || status.Code(err) != codes.Unauthenticated {
		t.Fatal("revocation ignored", err)
	}
	a.err = errors.New("authority unavailable")
	if _, seen, err := s.present(t, raw); seen || status.Code(err) != codes.Unavailable {
		t.Fatal("authority failure misclassified", err)
	}
	a.err = nil
	before := a.calls
	if _, seen, err := s.present(t, "kacho_malformed"); seen || status.Code(err) != codes.Unauthenticated {
		t.Fatal("malformed opaque accepted", err)
	}
	if a.calls != before {
		t.Fatal("malformed credential reached authority")
	}
	if _, seen, err := s.present(t, s.good(t)); err != nil || !seen {
		t.Fatal("JWT regressed", err)
	}
	if a.calls != before {
		t.Fatal("JWT reached opaque authority")
	}
}

func TestDirectOpaqueAuthorityContract(t *testing.T) {
	raw, _, err := credsecret.Mint("sak-direct")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*domain.BasicCredential)
	}{
		{"empty-principal", func(c *domain.BasicCredential) { c.PrincipalID = "" }},
		{"system-principal", func(c *domain.BasicCredential) { c.PrincipalType = "system" }},
		{"wrong-credential", func(c *domain.BasicCredential) { c.CredentialID = "sak-other" }},
		{"missing-expiry", func(c *domain.BasicCredential) { c.ExpiresAt = time.Time{} }},
		{"expired", func(c *domain.BasicCredential) { c.ExpiresAt = time.Time{}.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &basicAuthorityProbe{}
			s := newStand(t, func(c *presentedcred.Config, s *stand) {
				c.BasicCredentials = a
				a.credential = domain.BasicCredential{PrincipalType: "user", PrincipalID: testPrincipalID, CredentialID: "sak-direct", ExpiresAt: s.now.Add(time.Hour)}
			})
			if _, seen, err := s.present(t, raw); !seen || err != nil {
				t.Fatal("lawful twin failed", err)
			}
			tc.mutate(&a.credential)
			if _, seen, err := s.present(t, raw); seen || status.Code(err) != codes.Unauthenticated {
				t.Fatal("invalid authority result accepted", err)
			}
		})
	}
}
