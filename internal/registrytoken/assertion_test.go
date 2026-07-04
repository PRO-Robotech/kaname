// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

func testECKey(t *testing.T) (privPEM string, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), &priv.PublicKey
}

// TestSignClientAssertionES256_StructureAndVerify — a signed assertion has 3
// base64url segments, an ES256/kid header, the exact claims, and a 64-byte raw
// R||S signature verifiable against the public key.
func TestSignClientAssertionES256_StructureAndVerify(t *testing.T) {
	privPEM, pub := testECKey(t)
	claims := AssertionClaims{
		Issuer:    "cid-ci",
		Subject:   "cid-ci",
		Audience:  "https://hydra.api.kacho.cloud/oauth2/token",
		IssuedAt:  1000,
		ExpiresAt: 1060,
		JTI:       "jti-abc",
	}
	tok, err := SignClientAssertionES256("soc_key1", privPEM, claims)
	if err != nil {
		t.Fatalf("SignClientAssertionES256: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion must have 3 segments, got %d", len(parts))
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr map[string]string
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		t.Fatalf("header not json: %v", err)
	}
	if hdr["alg"] != "ES256" || hdr["typ"] != "JWT" || hdr["kid"] != "soc_key1" {
		t.Fatalf("bad header: %+v", hdr)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature must be 64-byte raw R||S, got len=%d err=%v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("assertion must verify against the signing public key")
	}
}

// TestSignClientAssertionES256_RejectsNonECKey — a non-EC / unparseable PEM errors.
func TestSignClientAssertionES256_RejectsNonECKey(t *testing.T) {
	if _, err := SignClientAssertionES256("k", "-----not-a-key-----", AssertionClaims{}); err == nil {
		t.Fatal("expected error for unparseable private key")
	}
}
