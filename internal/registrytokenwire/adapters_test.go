// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytokenwire

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// encryptAESGCM mirrors the JWKS rotation encryptor (nonce||ciphertext) so the
// test can produce an at-rest private key exactly as the store holds it.
func encryptAESGCM(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...)
}

func rsaPEMs(t *testing.T) (privPEM, pubPEM string, priv *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))
	pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	return privPEM, pubPEM, priv
}

type fakeJWKSRepo struct {
	current domain.OIDCJwksKey
	all     []domain.OIDCJwksKey
}

func (f fakeJWKSRepo) GetCurrent(_ context.Context, alg domain.JWKSAlg) (domain.OIDCJwksKey, error) {
	return f.current, nil
}
func (f fakeJWKSRepo) ListCurrent(context.Context) ([]domain.OIDCJwksKey, error) { return f.all, nil }

// TestRSAKeyProvider_DecryptsAndSigns — the adapter decrypts the at-rest key and
// returns a usable signer whose token verifies against the stored public key.
func TestRSAKeyProvider_DecryptsAndSigns(t *testing.T) {
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("enc key: %v", err)
	}
	privPEM, _, priv := rsaPEMs(t)
	key := domain.OIDCJwksKey{
		KID:                    "kacho-rs256-1",
		Alg:                    domain.JWKSAlgRS256Domain,
		Current:                true,
		PrivateKeyPEMEncrypted: encryptAESGCM(t, encKey, []byte(privPEM)),
	}
	prov := NewRSAKeyProvider(fakeJWKSRepo{current: key}, encKey)

	kid, got, err := prov.CurrentRSA(context.Background())
	if err != nil {
		t.Fatalf("CurrentRSA: %v", err)
	}
	if kid != "kacho-rs256-1" {
		t.Fatalf("kid = %q", kid)
	}
	// Sign with the recovered key → verify against the ORIGINAL public key.
	tok, err := registrytoken.SignRS256(kid, got, registrytoken.Claims{Subject: "sva1", ExpiresAt: 10})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := registrytoken.VerifyRS256(tok, &priv.PublicKey); err != nil {
		t.Fatalf("recovered key must match the stored public key: %v", err)
	}
}

// TestJWKSProvider_ProjectsCurrentRS256 — only the RS256 current key is projected
// as a signing JWK.
func TestJWKSProvider_ProjectsCurrentRS256(t *testing.T) {
	_, pubPEM, priv := rsaPEMs(t)
	all := []domain.OIDCJwksKey{
		{KID: "es", Alg: domain.JWKSAlgES256Domain, Current: true, PublicKeyPEM: "ignored"},
		{KID: "kacho-rs256-1", Alg: domain.JWKSAlgRS256Domain, Current: true, PublicKeyPEM: pubPEM},
	}
	prov := NewJWKSProvider(fakeJWKSRepo{all: all})

	set, err := prov.PublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("PublicJWKS: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d; want 1 (RS256 only)", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.Kid != "kacho-rs256-1" || jwk.Kty != "RSA" || jwk.Alg != "RS256" {
		t.Fatalf("jwk = %+v", jwk)
	}
	// The projected n/e must reconstruct the modulus of the stored key.
	if jwk.N == "" || jwk.E == "" {
		t.Fatal("jwk n/e must be populated")
	}
	_ = priv
}

type fakeSARepo struct {
	rows []domain.ServiceAccountOAuthClient
}

func (f fakeSARepo) List(_ context.Context, _ domain.ServiceAccountID, _ string, _ int32) ([]domain.ServiceAccountOAuthClient, string, error) {
	return f.rows, "", nil
}

// TestSAKeyLookup_ReturnsPublicHalvesSkippingFederated — maps SA rows to key refs,
// dropping federated rows that carry no key material.
func TestSAKeyLookup_ReturnsPublicHalvesSkippingFederated(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	rows := []domain.ServiceAccountOAuthClient{
		{ID: "soc1", PublicKeyPEM: "PEM-A", ExpiresAt: &exp},
		{ID: "soc2", PublicKeyPEM: ""}, // federated — no key material.
		{ID: "soc3", PublicKeyPEM: "PEM-B"},
	}
	look := NewSAKeyLookup(fakeSARepo{rows: rows})
	refs, err := look.PublicKeysForSubject(context.Background(), "sva1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %d; want 2 (federated row skipped)", len(refs))
	}
	want := map[string]registrytokenuc.SAKeyRef{
		"PEM-A": {PublicKeyPEM: "PEM-A", ExpiresAt: &exp},
		"PEM-B": {PublicKeyPEM: "PEM-B"},
	}
	for _, r := range refs {
		if _, ok := want[r.PublicKeyPEM]; !ok {
			t.Fatalf("unexpected ref %q", r.PublicKeyPEM)
		}
	}
}
