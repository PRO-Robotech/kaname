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
// publicSPKIPEM) — the exact shapes the SA-key issuer persists (public) and hands
// the holder once (private).
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

// fakeLookup — a scripted SAKeyLookup.
type fakeLookup struct {
	bySubject map[string][]SAKeyRef
	err       error
}

func (f fakeLookup) PublicKeysForSubject(_ context.Context, subjectID string) ([]SAKeyRef, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.bySubject[subjectID], nil
}

// TestSAKeyValidator_ValidPrivateKey_Authenticates — presenting the issued
// private-key PEM whose public half is a registered, non-expired key resolves the
// subject.
func TestSAKeyValidator_ValidPrivateKey_Authenticates(t *testing.T) {
	priv, pub := ecKeyPEMs(t)
	v := NewSAKeyValidator(fakeLookup{bySubject: map[string][]SAKeyRef{
		"sva0000000000000aa": {{PublicKeyPEM: pub}},
	}})

	subj, err := v.Validate(context.Background(), "sva0000000000000aa", priv)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if subj.ID != "sva0000000000000aa" {
		t.Fatalf("subject = %q; want the SA id", subj.ID)
	}
}

// TestSAKeyValidator_Rejections — every failure mode returns ErrInvalidCredentials
// (no oracle distinguishing which check failed).
func TestSAKeyValidator_Rejections(t *testing.T) {
	priv, pub := ecKeyPEMs(t)
	otherPriv, _ := ecKeyPEMs(t)
	past := time.Now().Add(-time.Hour)

	base := map[string][]SAKeyRef{
		"sva0000000000000aa": {{PublicKeyPEM: pub}},
		"sva0000000000000bb": {{PublicKeyPEM: pub, ExpiresAt: &past}}, // expired
	}

	cases := []struct {
		name, user, pass string
	}{
		{"non-sva username", "usr0000000000000aa", priv},
		{"empty username", "", priv},
		{"unparseable password", "sva0000000000000aa", "-----not a key-----"},
		{"empty password", "sva0000000000000aa", ""},
		{"no registered key for subject", "sva0000000000000zz", priv},
		{"key does not match registered", "sva0000000000000aa", otherPriv},
		{"registered key expired", "sva0000000000000bb", priv},
	}
	v := NewSAKeyValidator(fakeLookup{bySubject: base})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), c.user, c.pass)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("err = %v; want ErrInvalidCredentials", err)
			}
		})
	}
}
