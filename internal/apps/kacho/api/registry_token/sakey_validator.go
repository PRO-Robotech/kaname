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
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// errInvalidPEM — an internal parse sentinel; callers collapse it to
// ErrInvalidCredentials (no detail leaks to the client).
var errInvalidPEM = errors.New("registry token: invalid key PEM")

// SAKeyRef — one registered ServiceAccount key: its PUBLIC half (SPKI PEM) plus
// an optional expiry. kacho-iam never stores the private half.
type SAKeyRef struct {
	PublicKeyPEM string
	ExpiresAt    *time.Time // nil → no expiry.
}

// SAKeyLookup — reads the PUBLIC keys currently registered for a subject
// (ServiceAccount id). The composition root wires it to the SA-key store; the
// use-case package stays free of pgx.
type SAKeyLookup interface {
	PublicKeysForSubject(ctx context.Context, subjectID string) ([]SAKeyRef, error)
}

// SAKeyValidator — the MVP APITokenValidator: the presented password IS the
// issued SA-key private-key PEM (the one-shot secret the holder possesses). It
// authenticates by deriving the public half and matching a REGISTERED,
// non-expired key for the named subject — so a rotated/revoked key stops working,
// and possession of the private key is proof of identity.
//
// Any failure (bad subject prefix, unparseable key, no matching/expired key)
// returns ErrInvalidCredentials — no distinction leaks which check failed.
type SAKeyValidator struct {
	lookup SAKeyLookup
	now    func() time.Time
}

// NewSAKeyValidator — builder.
func NewSAKeyValidator(l SAKeyLookup) *SAKeyValidator {
	return &SAKeyValidator{lookup: l, now: time.Now}
}

// WithClock overrides the clock (expiry tests).
func (v *SAKeyValidator) WithClock(now func() time.Time) *SAKeyValidator {
	v.now = now
	return v
}

// Validate resolves the subject from (username=SA-id, password=SA-key private PEM).
func (v *SAKeyValidator) Validate(ctx context.Context, username, password string) (Subject, error) {
	if username == "" || !strings.HasPrefix(username, domain.PrefixServiceAccount) {
		return Subject{}, ErrInvalidCredentials
	}
	presented, err := publicDERFromPrivatePEM(password)
	if err != nil {
		return Subject{}, ErrInvalidCredentials
	}

	refs, err := v.lookup.PublicKeysForSubject(ctx, username)
	if err != nil {
		// Store unavailable → fail-closed (no token). Distinguishing this from a
		// genuine mismatch would leak subject existence, so collapse to the same
		// sentinel.
		return Subject{}, ErrInvalidCredentials
	}

	now := v.now()
	for _, ref := range refs {
		if ref.ExpiresAt != nil && !ref.ExpiresAt.After(now) {
			continue // expired registered key — never authenticates.
		}
		registered, derr := publicDERFromPublicPEM(ref.PublicKeyPEM)
		if derr != nil {
			continue // skip a malformed stored key rather than fail the whole match.
		}
		if bytes.Equal(presented, registered) {
			return Subject{ID: username}, nil
		}
	}
	return Subject{}, ErrInvalidCredentials
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
