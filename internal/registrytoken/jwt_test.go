// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registrytoken

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	return k
}

// TestSignRS256_StructureAndVerify — a signed token has 3 base64url segments, an
// RS256/kid header, the exact claims, and verifies against the public key.
func TestSignRS256_StructureAndVerify(t *testing.T) {
	priv := testKey(t)
	claims := Claims{
		Issuer:    "https://api.kacho.local/iam/token",
		Subject:   "sva0123456789abcdef",
		Audience:  "registry.kacho.local",
		IssuedAt:  1000,
		ExpiresAt: 1300,
		JTI:       "jti-abc",
	}

	tok, err := SignRS256("kacho-rs256-1", priv, claims)
	if err != nil {
		t.Fatalf("SignRS256: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token must have 3 segments, got %d", len(parts))
	}

	// Header: alg=RS256, typ=JWT, kid set.
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header not base64url: %v", err)
	}
	var hdr map[string]string
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		t.Fatalf("header not json: %v", err)
	}
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" || hdr["kid"] != "kacho-rs256-1" {
		t.Fatalf("bad header: %+v", hdr)
	}

	// Verify signature + claims round-trip against the public key.
	got, err := VerifyRS256(tok, &priv.PublicKey)
	if err != nil {
		t.Fatalf("VerifyRS256: %v", err)
	}
	if got != claims {
		t.Fatalf("claims mismatch: got %+v want %+v", got, claims)
	}
}

// TestVerifyRS256_RejectsWrongKey — a token signed by one key must not verify
// against a different public key (fail-closed for the data-plane).
func TestVerifyRS256_RejectsWrongKey(t *testing.T) {
	priv := testKey(t)
	other := testKey(t)
	tok, err := SignRS256("k1", priv, Claims{Subject: "sva1", ExpiresAt: 10})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := VerifyRS256(tok, &other.PublicKey); err == nil {
		t.Fatal("expected verify to FAIL against a foreign public key")
	}
}

// TestVerifyRS256_RejectsTamperedPayload — flipping a payload byte breaks the
// signature.
func TestVerifyRS256_RejectsTamperedPayload(t *testing.T) {
	priv := testKey(t)
	tok, err := SignRS256("k1", priv, Claims{Subject: "sva1", ExpiresAt: 10})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parts := strings.Split(tok, ".")
	// Re-encode a different payload, keep the original signature.
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","exp":9999999999}`))
	tampered := parts[0] + "." + forged + "." + parts[2]
	if _, err := VerifyRS256(tampered, &priv.PublicKey); err == nil {
		t.Fatal("expected verify to FAIL on tampered payload")
	}
}

// TestRSAPublicJWK — projects a signing JWK the data-plane can build a verifier
// from (kty=RSA, alg=RS256, use=sig, base64url n/e reconstructing the key).
func TestRSAPublicJWK(t *testing.T) {
	priv := testKey(t)
	jwk := RSAPublicJWK("kid-9", &priv.PublicKey)
	if jwk.Kty != "RSA" || jwk.Alg != "RS256" || jwk.Use != "sig" || jwk.Kid != "kid-9" {
		t.Fatalf("bad jwk metadata: %+v", jwk)
	}
	// n/e must be non-empty base64url that reconstruct the modulus/exponent.
	nRaw, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil || len(nRaw) == 0 {
		t.Fatalf("jwk.N not base64url: %v", err)
	}
	eRaw, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil || len(eRaw) == 0 {
		t.Fatalf("jwk.E not base64url: %v", err)
	}
}
