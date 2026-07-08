// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytoken — ES256 client_assertion crypto for the Docker Registry
// v2 auth-server (`/iam/token`) shim.
//
// The shim does NOT mint the registry token itself: it signs a short-lived RFC
// 7523 client_assertion (JWS ES256) from the presented SA-key private half and
// exchanges it with Ory Hydra (`client_credentials` + `private_key_jwt`); Hydra
// is the issuer. This package assembles that assertion with pure stdlib crypto
// (RFC 7519 JWT + RFC 7515 JWS, ECDSA P-256 / SHA-256), so no external JWT
// dependency is pulled in.
package registrytoken

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// AssertionClaims — the client_assertion payload (RFC 7523 registered claims).
// For `private_key_jwt` the issuer and subject are both the OAuth2 client_id.
type AssertionClaims struct {
	Issuer    string // iss — the Hydra client_id.
	Subject   string // sub — the Hydra client_id (== iss).
	Audience  string // aud — the Hydra token endpoint URL.
	IssuedAt  int64  // iat — unix seconds.
	ExpiresAt int64  // exp — unix seconds (short TTL, ≤60s).
	JTI       string // jti — unique assertion id (replay protection).
}

// assertionHeader — protected JOSE header.
type assertionHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// assertionPayload — wire projection of AssertionClaims (registered claim names).
type assertionPayload struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	JTI       string `json:"jti,omitempty"`
}

// SignClientAssertionES256 assembles and signs a compact JWS (JWT) with ES256
// over the given claims, using kid in the protected header so Hydra selects the
// registered verification key. privateKeyPEM is the presented PKCS#8 EC private
// key (the SA-key secret). The ECDSA signature is the JWS raw form: R||S, each
// left-padded to 32 bytes (RFC 7518 §3.4).
func SignClientAssertionES256(kid, privateKeyPEM string, claims AssertionClaims) (string, error) {
	if kid == "" {
		return "", errors.New("registrytoken: empty kid")
	}
	priv, err := parseECPrivatePEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	hdr, err := json.Marshal(assertionHeader{Alg: "ES256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", fmt.Errorf("registrytoken: marshal header: %w", err)
	}
	pl, err := json.Marshal(assertionPayload(claims))
	if err != nil {
		return "", fmt.Errorf("registrytoken: marshal payload: %w", err)
	}
	signingInput := b64(hdr) + "." + b64(pl)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("registrytoken: sign: %w", err)
	}
	// JWS ES256 signature: fixed-length R||S (32 bytes each for P-256).
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseECPrivatePEM parses a PKCS#8 EC (P-256) private-key PEM.
func parseECPrivatePEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("registrytoken: invalid private PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registrytoken: parse private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("registrytoken: assertion key is not ECDSA")
	}
	return ecKey, nil
}

// NewJTI mints a random 128-bit assertion id (base64url) for the `jti` claim.
func NewJTI() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("registrytoken: jti entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// b64 — base64url (no padding) of raw bytes.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
