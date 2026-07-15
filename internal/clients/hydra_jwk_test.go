// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestPublicKeyPEMToJWK_ES256 — ES256 EC-ключ корректно кодируется в JWK: x/y —
// fixed-length (32 байта) координаты несжатой точки. Пинит замену deprecated
// ecdsa.PublicKey.X/Y на PublicKey.Bytes() (Go 1.26).
func TestPublicKeyPEMToJWK_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	jwk, err := publicKeyPEMToJWK(domain.JWKSAlgES256Domain, "kid-1", pemStr)
	require.NoError(t, err)
	require.Equal(t, "EC", jwk["kty"])
	require.Equal(t, "P-256", jwk["crv"])
	require.Equal(t, "ES256", jwk["alg"])

	raw, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	require.Len(t, raw, 65, "P-256 uncompressed point = 0x04 || X(32) || Y(32)")

	x, err := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	require.NoError(t, err)
	y, err := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
	require.NoError(t, err)
	require.Len(t, x, 32, "JWK x — fixed-length 32-byte coordinate")
	require.Len(t, y, 32, "JWK y — fixed-length 32-byte coordinate")
	require.Equal(t, raw[1:33], x, "JWK x = uncompressed X")
	require.Equal(t, raw[33:65], y, "JWK y = uncompressed Y")
}
