// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

// ecKeyPEMs mints an ECDSA P-256 keypair and returns (privatePKCS8PEM,
// publicSPKIPEM) — the shapes the SA-key issuer persists (public) and hands the
// holder once (private).
func ecKeyPEMs(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal spki: %v", err)
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privPEM, pubPEM
}

// fakeClientLookup — a scripted SAClientLookup keyed by Hydra client_id.
type fakeClientLookup struct {
	byClient map[string]RegisteredKey
	err      error
}

func (f fakeClientLookup) KeyByClientID(_ context.Context, clientID string) (RegisteredKey, error) {
	if f.err != nil {
		return RegisteredKey{}, f.err
	}
	k, ok := f.byClient[clientID]
	if !ok {
		return RegisteredKey{}, errors.New("not found")
	}
	return k, nil
}

// TestSAKeyValidator_ValidPrivateKey_ResolvesCredential — presenting the issued
// private-key PEM whose public half is the registered key for the client_id
// yields the credential (client_id + kid) the assertion is built from.
func TestSAKeyValidator_ValidPrivateKey_ResolvesCredential(t *testing.T) {
	priv, pub := ecKeyPEMs(t)
	v := NewSAKeyValidator(fakeClientLookup{byClient: map[string]RegisteredKey{
		"cid-ci": {ClientID: "cid-ci", KeyID: "soc_key1", Subject: "sva0000000000000aa", PublicKeyPEM: pub, KeyAlgorithm: "ES256"},
	}})

	cred, err := v.Validate(context.Background(), "cid-ci", priv)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cred.ClientID != "cid-ci" || cred.KeyID != "soc_key1" {
		t.Fatalf("cred = %+v; want client_id + kid", cred)
	}
	if cred.Subject != "sva0000000000000aa" {
		t.Errorf("subject = %q; want owning SA", cred.Subject)
	}
}

// TestSAKeyValidator_Rejections — every failure mode returns ErrInvalidCredentials
// (no oracle distinguishing which check failed).
func TestSAKeyValidator_Rejections(t *testing.T) {
	priv, pub := ecKeyPEMs(t)
	otherPriv, _ := ecKeyPEMs(t)
	past := time.Now().Add(-time.Hour)

	base := map[string]RegisteredKey{
		"cid-ok":        {ClientID: "cid-ok", KeyID: "soc_1", PublicKeyPEM: pub, KeyAlgorithm: "ES256"},
		"cid-expired":   {ClientID: "cid-expired", KeyID: "soc_2", PublicKeyPEM: pub, KeyAlgorithm: "ES256", ExpiresAt: &past},
		"cid-federated": {ClientID: "cid-federated", KeyID: "soc_3", PublicKeyPEM: "" /* federated: no key */},
	}
	v := NewSAKeyValidator(fakeClientLookup{byClient: base})

	cases := []struct {
		name, client, pass string
	}{
		{"empty client", "", priv},
		{"empty password", "cid-ok", ""},
		{"unparseable password", "cid-ok", "-----not a key-----"},
		{"unknown client", "cid-nope", priv},
		{"key does not match registered", "cid-ok", otherPriv},
		{"registered key expired", "cid-expired", priv},
		{"federated client has no docker key", "cid-federated", priv},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), c.client, c.pass)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v; want ErrInvalidCredentials", err)
			}
		})
	}
}

// TestSAKeyValidator_LookupError_FailsClosed — a store failure collapses to
// ErrInvalidCredentials (no token, and no leak of subject existence).
func TestSAKeyValidator_LookupError_FailsClosed(t *testing.T) {
	priv, _ := ecKeyPEMs(t)
	v := NewSAKeyValidator(fakeClientLookup{err: errors.New("db down")})
	if _, err := v.Validate(context.Background(), "cid-ok", priv); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v; want ErrInvalidCredentials", err)
	}
}
