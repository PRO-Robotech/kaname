// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package registry_token

// sakey_validator_disabled_test.go — the docker path agrees with the provider
// path about which accounts are allowed to authenticate.
//
// This validator already refuses an EXPIRED key, deliberately using the same
// predicate the provider path uses, so a credential cannot be alive on one and
// dead on the other at the same instant. Whether the owning account may
// authenticate at all is the same kind of fact and gets the same treatment: the
// registered key carries its owner's state, and a key whose owner may not
// authenticate is refused here rather than authenticated and turned away three
// hops later with nothing to say why.
//
// The answer stays the single ErrInvalidCredentials every other failure
// collapses into. Telling a caller that the account exists but is disabled
// would answer a question they did not authenticate to ask.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stateLookup — a registered key whose owning account carries the state under
// test. The key material itself is valid and matching: the only thing in
// question is whether the owner may authenticate.
type stateLookup struct{ key RegisteredKey }

var errNoSuchClient = errors.New("no such client")

func (l stateLookup) KeyByClientID(_ context.Context, clientID string) (RegisteredKey, error) {
	if clientID != l.key.ClientID {
		return RegisteredKey{}, errNoSuchClient
	}
	return l.key, nil
}

// newMatchingKeyPair returns a PKCS#8 private-key PEM and the SPKI public PEM
// registered against it — a credential that authenticates on its own merits, so
// a refusal can only come from the account state.
func newMatchingKeyPair(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func newStateValidator(t *testing.T, subjectEnabled bool) (*SAKeyValidator, string) {
	t.Helper()
	privPEM, pubPEM := newMatchingKeyPair(t)
	return NewSAKeyValidator(stateLookup{key: RegisteredKey{
		ClientID:       "docker-client-of-sa",
		KeyID:          "soc00000000000000001",
		Subject:        "sva00000000000000001",
		PublicKeyPEM:   pubPEM,
		KeyAlgorithm:   "Ed25519",
		SubjectEnabled: subjectEnabled,
	}}), privPEM
}

func TestSAKeyValidator_DisabledServiceAccount_Refused(t *testing.T) {
	v, privPEM := newStateValidator(t, false)

	cred, err := v.Validate(context.Background(), "docker-client-of-sa", privPEM)

	require.ErrorIs(t, err, ErrInvalidCredentials,
		"a key whose owning account may not authenticate must not authenticate on the "+
			"docker path either; the two paths cannot disagree about the same account")
	assert.Empty(t, cred.ClientID, "no credential may be handed back")
	assert.Empty(t, cred.Subject)
}

// The control. `SubjectEnabled` is false in every zero value, so a check on a
// field the lookup does not populate refuses every docker login there is —
// every image push and pull in the platform.
func TestSAKeyValidator_EnabledServiceAccount_StillAuthenticates(t *testing.T) {
	v, privPEM := newStateValidator(t, true)

	cred, err := v.Validate(context.Background(), "docker-client-of-sa", privPEM)

	require.NoError(t, err, "an enabled account with a matching key must still authenticate")
	assert.Equal(t, "docker-client-of-sa", cred.ClientID)
	assert.Equal(t, "sva00000000000000001", cred.Subject)
}
