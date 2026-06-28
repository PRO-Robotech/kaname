// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decryptAESGCM — test-only inverse of the production encryptAESGCM, used to
// round-trip-verify the bootstrap private-key encryption. There is no production
// JWKS read/recovery path that decrypts PrivateKeyPEMEncrypted, so the decrypt
// helper lives here (in the _test file) rather than padding the production binary
// with a never-invoked crypto path (ban #13 spirit).
func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// jwks_aesgcm_internal_test.go — in-package round-trip coverage for the
// AES-GCM helpers used to encrypt the bootstrapped JWKS private key. Lives in
// package service so it can exercise the unexported decryptAESGCM directly
// (there is no production read/recovery path that decrypts the stored key).

const aesGCMTestKey32 = "0123456789abcdef0123456789abcdef" // 32-byte AES-256 key

func TestEncryptAESGCM_DecryptRoundTrip(t *testing.T) {
	plaintext := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpUFAKE\n-----END RSA PRIVATE KEY-----\n")

	encrypted, err := encryptAESGCM([]byte(aesGCMTestKey32), plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
	require.NotEqual(t, plaintext, encrypted, "ciphertext must differ from plaintext")

	decrypted, err := decryptAESGCM([]byte(aesGCMTestKey32), encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "decrypt must round-trip the original plaintext")
}

func TestDecryptAESGCM_TamperedFails(t *testing.T) {
	encrypted, err := encryptAESGCM([]byte(aesGCMTestKey32), []byte("sensitive-pem-body"))
	require.NoError(t, err)

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0xFF

	_, derr := decryptAESGCM([]byte(aesGCMTestKey32), tampered)
	assert.Error(t, derr, "tampered ciphertext must fail GCM authentication")
}
