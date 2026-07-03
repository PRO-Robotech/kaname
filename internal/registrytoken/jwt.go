// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytoken — RS256 identity-JWT crypto for the Docker Registry v2
// auth-server (`/token`) endpoint.
//
// The endpoint mints a short-lived identity-JWT carrying WHO the caller is (a
// verified subject id), NOT a pre-issued registry scope: kacho-registry
// re-checks authorization per request against IAM (Вариант B). The token is a
// standard RS256 JWT verifiable through the JWKS this package projects, so any
// JWKS-aware verifier accepts it.
//
// Pure stdlib crypto (no external JWT dependency) — the header/payload/signature
// are RFC 7519 (JWT) + RFC 7515 (JWS, RSASSA-PKCS1-v1_5 SHA-256) hand-assembled.
package registrytoken

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Claims — the identity-JWT payload (RFC 7519 registered claims subset). The
// token carries identity only: no registry scope/permission is embedded.
type Claims struct {
	Issuer    string // iss — the IAM token-issuer URL.
	Subject   string // sub — the authenticated subject id (e.g. a ServiceAccount id).
	Audience  string // aud — the registry service name (e.g. registry.kacho.local).
	IssuedAt  int64  // iat — unix seconds.
	ExpiresAt int64  // exp — unix seconds (short TTL, <=5m).
	JTI       string // jti — unique token id (replay/audit).
}

// jwtHeader — protected JOSE header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// jwtPayload — wire projection of Claims (registered claim names).
type jwtPayload struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	JTI       string `json:"jti,omitempty"`
}

// SignRS256 assembles and signs a compact JWS (JWT) with RS256 over the given
// claims, using kid in the protected header so verifiers select the right JWKS
// key. Returns the compact `header.payload.signature` string.
func SignRS256(kid string, priv *rsa.PrivateKey, claims Claims) (string, error) {
	if priv == nil {
		return "", errors.New("registrytoken: nil signing key")
	}
	if kid == "" {
		return "", errors.New("registrytoken: empty kid")
	}
	hdr, err := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", fmt.Errorf("registrytoken: marshal header: %w", err)
	}
	pl, err := json.Marshal(jwtPayload{
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Audience:  claims.Audience,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		JTI:       claims.JTI,
	})
	if err != nil {
		return "", fmt.Errorf("registrytoken: marshal payload: %w", err)
	}
	signingInput := b64(hdr) + "." + b64(pl)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("registrytoken: sign: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyRS256 parses a compact RS256 JWT, verifies its signature against pub, and
// returns the decoded claims. It does NOT enforce exp/aud/iss (callers decide the
// policy) — it proves only that the token was signed by the holder of pub.
func VerifyRS256(token string, pub *rsa.PublicKey) (Claims, error) {
	if pub == nil {
		return Claims{}, errors.New("registrytoken: nil verification key")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("registrytoken: malformed compact JWT")
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("registrytoken: header decode: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return Claims{}, fmt.Errorf("registrytoken: header parse: %w", err)
	}
	if hdr.Alg != "RS256" {
		return Claims{}, fmt.Errorf("registrytoken: unexpected alg %q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("registrytoken: signature decode: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, fmt.Errorf("registrytoken: signature invalid: %w", err)
	}
	plRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("registrytoken: payload decode: %w", err)
	}
	var pl jwtPayload
	if err := json.Unmarshal(plRaw, &pl); err != nil {
		return Claims{}, fmt.Errorf("registrytoken: payload parse: %w", err)
	}
	return Claims{
		Issuer:    pl.Issuer,
		Subject:   pl.Subject,
		Audience:  pl.Audience,
		IssuedAt:  pl.IssuedAt,
		ExpiresAt: pl.ExpiresAt,
		JTI:       pl.JTI,
	}, nil
}

// JWK — RSA JSON Web Key (RFC 7517) projection for the JWKS endpoint.
type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// JWKS — JWK Set wrapper (the `/token/jwks` response body).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// RSAPublicJWK projects an RSA public key to a signing JWK (alg=RS256, use=sig).
// n is the big-endian modulus; e is the big-endian exponent (minimal-length,
// RFC 7518 §6.3.1), both base64url without padding.
func RSAPublicJWK(kid string, pub *rsa.PublicKey) JWK {
	eBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(eBuf, uint64(pub.E)) //nolint:gosec // exponent is small (65537), fits uint64.
	// Trim leading zero bytes to the minimal big-endian encoding.
	eTrim := eBuf
	for len(eTrim) > 1 && eTrim[0] == 0 {
		eTrim = eTrim[1:]
	}
	return JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eTrim),
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
	}
}

// NewJTI mints a random 128-bit token id (base64url) for the `jti` claim.
func NewJTI() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("registrytoken: jti entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// b64 — base64url (no padding) of raw bytes.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
