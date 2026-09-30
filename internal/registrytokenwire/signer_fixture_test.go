// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signer_fixture_test.go — НАШ подписант для проб сборки полосы (kaname#494).
//
// Полоса без нашего подписанта не собирается: другого издателя у неё нет. Значит
// каждая проба, которой нужна собранная полоса, подаёт подписанта — и подаёт
// НАСТОЯЩЕГО, построенного тем же конструктором, что композиционный корень, а не
// нулевую структуру: фикстура, снисходительнее продукта, зеленила бы полосу,
// которая на первом выпуске отказала бы.
package registrytokenwire_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// laneKeys — ключница пробы: один действующий подписной ключ.
type laneKeys struct{ mat tokensigner.SigningMaterial }

func (k laneKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

// ourSigner — подписант с одним ключом P-256.
func ourSigner(t *testing.T) *tokensigner.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ подписанта: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("закрытая половина: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("открытая половина: %v", err)
	}
	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      "https://kaname.kacho.local",
		Clock:       time.Now,
		MaxTokenTTL: 30 * time.Minute,
	}, laneKeys{mat: tokensigner.SigningMaterial{
		KID:           domain.KeyID("lane-1"),
		Algorithm:     domain.SigningAlgorithm("ES256"),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}})
	if err != nil {
		t.Fatalf("подписант: %v", err)
	}
	return s
}
