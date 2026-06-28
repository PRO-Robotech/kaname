// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"regexp"
	"time"

	"go.uber.org/multierr"
)

// OIDCJwksKey — JWKS rotation tracking. Inv:
//   - Partial UNIQUE per `alg` WHERE current=true (1 current row per alg).
//   - CHECK current=true ⇔ rotated_at IS NULL.
//   - Rotation flow — single-statement CTE (migration 0014).
//
// **SENSITIVE**: PrivateKeyPEMEncrypted — bytea, encrypted at rest. НИКОГДА не
// сериализуется в публичные proto / JSON-ответы (инфра-чувствительные данные).
type OIDCJwksKey struct {
	KID                    string
	Alg                    JWKSAlg
	Current                bool
	RotatedAt              *time.Time
	ExpiresAt              time.Time
	PublicKeyPEM           string
	PrivateKeyPEMEncrypted []byte
	CreatedAt              time.Time
}

func (k OIDCJwksKey) Validate() error {
	var errs error
	errs = multierr.Append(errs, k.Alg.Validate())
	if l := len(k.KID); l < 1 || l > 128 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument kid: length must be 1..128"))
	}
	if !jwksKIDRe.MatchString(k.KID) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument kid: must match [A-Za-z0-9._:-]+"))
	}
	if l := len(k.PublicKeyPEM); l < 1 || l > 16384 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument public_key_pem: length must be 1..16384"))
	}
	if l := len(k.PrivateKeyPEMEncrypted); l < 1 || l > 32768 {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument private_key_pem_encrypted: length must be 1..32768 bytes"))
	}
	if !k.CreatedAt.IsZero() && !k.ExpiresAt.After(k.CreatedAt) {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument expires_at: must be > created_at"))
	}
	// rotation consistency: current=true ⇔ rotated_at IS NULL.
	if k.Current && k.RotatedAt != nil {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument rotated_at: must be NULL when current=true"))
	}
	if !k.Current && k.RotatedAt == nil {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument rotated_at: must be set when current=false"))
	}
	return errs
}

var jwksKIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// JWKSAlg — supported algs (migration 0014 CHECK).
type JWKSAlg string

const (
	JWKSAlgRS256Domain JWKSAlg = "RS256"
	JWKSAlgES256Domain JWKSAlg = "ES256"
	JWKSAlgEdDSADomain JWKSAlg = "EdDSA"
)

func (a JWKSAlg) Validate() error {
	switch a {
	case JWKSAlgRS256Domain, JWKSAlgES256Domain, JWKSAlgEdDSADomain:
		return nil
	default:
		return fmt.Errorf("Illegal argument alg %q (allowed: RS256|ES256|EdDSA)", string(a))
	}
}
