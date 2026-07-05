// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// TestES256AssertionSigner_ProducesVerifiableAssertion — the signer emits a
// compact ES256 JWS with the kid header and RFC 7523 claims (iss=sub=client_id,
// aud, iat, exp, jti), signed by the presented private key (raw R||S, 64 bytes).
func TestES256AssertionSigner_ProducesVerifiableAssertion(t *testing.T) {
	privPEM, pubPEM := ecKeyPEMs(t)

	signer := ES256AssertionSigner{}
	tok, err := signer.Sign(AssertionInput{
		KeyID:         "soc_key1",
		ClientID:      "cid-ci",
		Audience:      "https://hydra.api.kacho.cloud/oauth2/token",
		PrivateKeyPEM: privPEM,
		IssuedAt:      1_700_000_000,
		ExpiresAt:     1_700_000_060,
		JTI:           "jti-1",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS must have 3 parts, got %d", len(parts))
	}

	var hdr struct{ Alg, Typ, Kid string }
	decodeJSON(t, parts[0], &hdr)
	if hdr.Alg != "ES256" || hdr.Typ != "JWT" || hdr.Kid != "soc_key1" {
		t.Fatalf("header = %+v; want ES256/JWT/soc_key1", hdr)
	}

	var pl struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	var raw map[string]any
	decodeJSON(t, parts[1], &raw)
	pl.Iss, _ = raw["iss"].(string)
	pl.Sub, _ = raw["sub"].(string)
	pl.Aud, _ = raw["aud"].(string)
	pl.Jti, _ = raw["jti"].(string)
	if f, ok := raw["iat"].(float64); ok {
		pl.Iat = int64(f)
	}
	if f, ok := raw["exp"].(float64); ok {
		pl.Exp = int64(f)
	}
	if pl.Iss != "cid-ci" || pl.Sub != "cid-ci" {
		t.Errorf("iss/sub = %q/%q; want client_id both", pl.Iss, pl.Sub)
	}
	if pl.Aud != "https://hydra.api.kacho.cloud/oauth2/token" {
		t.Errorf("aud = %q", pl.Aud)
	}
	if pl.Iat != 1_700_000_000 || pl.Exp != 1_700_000_060 || pl.Jti != "jti-1" {
		t.Errorf("iat/exp/jti = %d/%d/%q", pl.Iat, pl.Exp, pl.Jti)
	}

	// Verify the ES256 signature (raw R||S) against the public key.
	pub := parseECPub(t, pubPEM)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature must be 64-byte raw R||S, got len=%d err=%v", len(sig), err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("assertion signature must verify against the presented public key")
	}
}

// TestES256AssertionSigner_BadKey_Errors — a non-EC / unparseable private key is
// an error (the shim maps it to a fail-closed 401, no token).
func TestES256AssertionSigner_BadKey_Errors(t *testing.T) {
	if _, err := (ES256AssertionSigner{}).Sign(AssertionInput{
		KeyID: "k", ClientID: "cid", Audience: "aud", PrivateKeyPEM: "-----not-a-key-----",
	}); err == nil {
		t.Fatal("expected error for unparseable private key")
	}
}

func decodeJSON(t *testing.T, seg string, v any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("json: %v", err)
	}
}

func parseECPub(t *testing.T, pubPEM string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("bad pub pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pub: %v", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not EC")
	}
	return ec
}
