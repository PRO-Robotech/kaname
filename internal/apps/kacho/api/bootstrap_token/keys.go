// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// keys.go — derive the PUBLIC JWK (Hydra registration) from the env-held
// bootstrap ES256 private key. The private half is supplied at wire-time from a
// k8s Secret and is used only in-memory to sign client_assertions — it is NEVER
// persisted (parity with the SA-key posture: iam stores only the public JWK).
package bootstrap_token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// ErrSigningKeyNotConfigured — the bootstrap signing key env/Secret is absent.
// The mint path fails closed (no token) rather than fabricating a credential.
var ErrSigningKeyNotConfigured = errors.New("bootstrap token: signing key not configured")

// publicJWKFromPrivatePEM parses a PKCS#8 ES256 (P-256) private-key PEM and
// projects the PUBLIC key to a Hydra JWK (`alg=ES256`, `use=sig`, given kid) plus
// the SPKI public PEM (stored in the mapping row for rotation diagnostics). The
// private half never leaves this function's caller.
func publicJWKFromPrivatePEM(privatePEM, kid string) (clients.JWK, string, error) {
	if kid == "" {
		return clients.JWK{}, "", errors.New("bootstrap token: empty kid")
	}
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return clients.JWK{}, "", errors.New("bootstrap token: invalid private PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return clients.JWK{}, "", fmt.Errorf("bootstrap token: parse private key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return clients.JWK{}, "", errors.New("bootstrap token: signing key is not ECDSA")
	}
	if priv.Curve != nil && priv.Params().Name != "P-256" {
		return clients.JWK{}, "", fmt.Errorf("bootstrap token: unsupported curve %q (want P-256/ES256)", priv.Params().Name)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return clients.JWK{}, "", fmt.Errorf("bootstrap token: marshal spki: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// P-256 coordinates are 32 bytes; left-pad short big.Int encodings.
	jwk := clients.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(padLeft(priv.X.Bytes(), 32)),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(priv.Y.Bytes(), 32)),
		Kid: kid,
		Alg: "ES256",
		Use: "sig",
	}
	return jwk, string(pubPEM), nil
}

// padLeft returns a size-byte slice with b zero-padded on the left (unchanged
// when already >= size).
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
