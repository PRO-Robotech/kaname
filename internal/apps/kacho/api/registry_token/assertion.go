// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

import "github.com/PRO-Robotech/kacho/services/iam/internal/registrytoken"

// ES256AssertionSigner — the AssertionSigner that signs a client_assertion (JWS)
// with ES256 using the presented SA-key private half. Pure crypto (stdlib), no
// infra — the private key is supplied per call (the Basic password), not stored.
type ES256AssertionSigner struct{}

// Sign builds and signs the RFC 7523 client_assertion.
func (ES256AssertionSigner) Sign(in AssertionInput) (string, error) {
	return registrytoken.SignClientAssertionES256(in.KeyID, in.PrivateKeyPEM, registrytoken.AssertionClaims{
		Issuer:    in.ClientID,
		Subject:   in.ClientID,
		Audience:  in.Audience,
		IssuedAt:  in.IssuedAt,
		ExpiresAt: in.ExpiresAt,
		JTI:       in.JTI,
	})
}
