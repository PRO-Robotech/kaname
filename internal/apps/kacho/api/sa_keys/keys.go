// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// keys.go — Phase 3a (private_key_jwt) keypair helpers for SA Keys.
//
// Generates ECDSA P-256 keypairs, encodes them as PKCS#8 / SPKI PEM, and
// projects the public key to a JWK suitable for Hydra client registration.
// The private key never persists in kacho-iam DB; we only keep the public
// PEM for rotation diagnostics and the algorithm string.
package sa_keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// generatedKey holds all artifacts produced by generateES256Key.
type generatedKey struct {
	PrivatePEM string
	PublicPEM  string
	JWK        clients.JWK
	Algorithm  string
}

// generateES256Key mints a fresh ECDSA P-256 keypair, returning PKCS#8
// PEM (private), SPKI PEM (public), and a JWK projection of the public
// key with `alg=ES256`, `use=sig`, and the supplied `kid`.
func generateES256Key(kid string) (generatedKey, error) {
	if kid == "" {
		return generatedKey{}, fmt.Errorf("kid required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return generatedKey{}, fmt.Errorf("generate ecdsa p256: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return generatedKey{}, fmt.Errorf("marshal pkcs8: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return generatedKey{}, fmt.Errorf("marshal spki: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// P-256 coordinate size is 32 bytes; left-pad if the big.Int Bytes
	// representation came back short.
	xBytes := padLeft(priv.X.Bytes(), 32)
	yBytes := padLeft(priv.Y.Bytes(), 32)

	jwk := clients.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Kid: kid,
		Alg: "ES256",
		Use: "sig",
	}

	return generatedKey{
		PrivatePEM: string(privPEM),
		PublicPEM:  string(pubPEM),
		JWK:        jwk,
		Algorithm:  "ES256",
	}, nil
}

// padLeft returns a `size`-byte slice with the input zero-padded on the
// left. If `b` is already >= size it is returned unchanged.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
