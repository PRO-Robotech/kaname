// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keys.go — Phase 3a (private_key_jwt) keypair helpers for SA Keys.
//
// Generates ECDSA P-256 keypairs and encodes them as PKCS#8 / SPKI PEM. The
// private key never persists in kaname DB; we keep only the public PEM (the
// signature of `client_assertion` is checked against it) and the algorithm
// string. A JWK projection used to be built here for the registration of the
// client at the previous external issuer; that registration is gone
// (kaname#362), and the projection with it.
package sa_keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// generatedKey holds all artifacts produced by generateES256Key.
type generatedKey struct {
	PrivatePEM string
	PublicPEM  string
	Algorithm  string
}

// generateES256Key mints a fresh ECDSA P-256 keypair, returning PKCS#8 PEM
// (private) and SPKI PEM (public) with `alg=ES256`.
func generateES256Key() (generatedKey, error) {
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

	return generatedKey{
		PrivatePEM: string(privPEM),
		PublicPEM:  string(pubPEM),
		Algorithm:  "ES256",
	}, nil
}
