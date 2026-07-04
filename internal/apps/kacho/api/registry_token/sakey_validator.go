// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"
)

// errInvalidPEM — an internal parse sentinel; callers collapse it to
// ErrInvalidCredentials (no detail leaks to the client).
var errInvalidPEM = errors.New("registry token: invalid key PEM")

// RegisteredKey — the SA-key registered for a Hydra client_id: its PUBLIC half
// (SPKI PEM), the JWK kid (the SA-OAuth-client id) and owning ServiceAccount,
// plus an optional expiry. kacho-iam never stores the private half. A federated
// client carries no key material (PublicKeyPEM empty) — the docker path rejects it.
type RegisteredKey struct {
	ClientID     string
	KeyID        string // the registered JWK kid → assertion header kid.
	Subject      string // owning ServiceAccount id.
	PublicKeyPEM string
	KeyAlgorithm string
	ExpiresAt    *time.Time // nil → no expiry.
}

// SAClientLookup — reverse lookup of the SA-key registered for a Hydra client_id.
// The composition root wires it to the SA-key store; the use-case package stays
// free of pgx.
type SAClientLookup interface {
	KeyByClientID(ctx context.Context, clientID string) (RegisteredKey, error)
}

// SAKeyValidator — the CredentialValidator for the docker path: the Basic user is
// the Hydra client_id and the Basic password IS the issued SA-key private-key PEM
// (the one-shot secret the holder possesses). It authenticates by resolving the
// registered key for the client_id and matching the derived public half against
// it — so a rotated/revoked key stops working, and possession of the private key
// is proof of identity. The verified (client_id, kid) then builds the assertion.
//
// Any failure (empty input, unparseable key, unknown/federated client, no match,
// expired) returns ErrInvalidCredentials — no distinction leaks which check failed.
type SAKeyValidator struct {
	lookup SAClientLookup
	now    func() time.Time
}

// NewSAKeyValidator — builder.
func NewSAKeyValidator(l SAClientLookup) *SAKeyValidator {
	return &SAKeyValidator{lookup: l, now: time.Now}
}

// WithClock overrides the clock (expiry tests).
func (v *SAKeyValidator) WithClock(now func() time.Time) *SAKeyValidator {
	v.now = now
	return v
}

// Validate resolves the credential from (clientID, private-key PEM).
func (v *SAKeyValidator) Validate(ctx context.Context, clientID, privateKeyPEM string) (Credential, error) {
	if clientID == "" || privateKeyPEM == "" {
		return Credential{}, ErrInvalidCredentials
	}
	presented, err := publicDERFromPrivatePEM(privateKeyPEM)
	if err != nil {
		return Credential{}, ErrInvalidCredentials
	}

	key, err := v.lookup.KeyByClientID(ctx, clientID)
	if err != nil {
		// Store failure / unknown client → fail-closed. Distinguishing this from
		// a genuine mismatch would leak client existence, so collapse to the same
		// sentinel.
		return Credential{}, ErrInvalidCredentials
	}
	if key.PublicKeyPEM == "" || key.KeyID == "" {
		// Federated client (no key material) or a row missing its kid — the docker
		// private_key_jwt path cannot authenticate it.
		return Credential{}, ErrInvalidCredentials
	}
	if key.ExpiresAt != nil && !key.ExpiresAt.After(v.now()) {
		return Credential{}, ErrInvalidCredentials
	}
	registered, err := publicDERFromPublicPEM(key.PublicKeyPEM)
	if err != nil {
		return Credential{}, ErrInvalidCredentials
	}
	if !bytes.Equal(presented, registered) {
		return Credential{}, ErrInvalidCredentials
	}
	return Credential{ClientID: clientID, KeyID: key.KeyID, Subject: key.Subject}, nil
}

// publicDERFromPrivatePEM parses a PKCS#8 private-key PEM and returns the PKIX
// (SPKI) DER encoding of its public half — the canonical form compared against a
// stored public key.
func publicDERFromPrivatePEM(privatePEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return nil, errInvalidPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errInvalidPEM
	}
	return x509.MarshalPKIXPublicKey(signer.Public())
}

// publicDERFromPublicPEM parses a PKIX (SPKI) public-key PEM and re-marshals it to
// canonical DER (so comparison is whitespace/encoding-independent).
func publicDERFromPublicPEM(publicPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(publicPEM))
	if block == nil {
		return nil, errInvalidPEM
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKIXPublicKey(pub)
}
