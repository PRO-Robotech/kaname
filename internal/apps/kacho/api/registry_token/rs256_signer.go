// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// RSAKeyProvider — supplies the CURRENT RS256 signing key (kid + private key).
// The composition root wires it to iam's oidc_jwks_keys store (decrypting the
// at-rest private key); the use-case package stays free of the key storage.
type RSAKeyProvider interface {
	CurrentRSA(ctx context.Context) (kid string, priv *rsa.PrivateKey, err error)
}

// RS256Signer — the TokenSigner backed by the current oidc_jwks RS256 key.
type RS256Signer struct {
	provider RSAKeyProvider
}

// NewRS256Signer — builder.
func NewRS256Signer(p RSAKeyProvider) *RS256Signer { return &RS256Signer{provider: p} }

// Sign mints an RS256 JWT for claims using the current signing key + its kid.
func (s *RS256Signer) Sign(ctx context.Context, claims registrytoken.Claims) (string, error) {
	kid, priv, err := s.provider.CurrentRSA(ctx)
	if err != nil {
		return "", fmt.Errorf("registry token: current signing key: %w", err)
	}
	return registrytoken.SignRS256(kid, priv, claims)
}
