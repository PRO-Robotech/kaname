// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// registry_lane_signer_test.go — НАШ подписант для проб корня, собирающих полосу
// выдачи докер-токена (kaname#494).
//
// Полоса без нашего подписанта не собирается: другого издателя у неё нет.
// Подписант строится тем же конструктором, что у корня, а не подставляется
// нулевой структурой: фикстура, снисходительнее продукта, зеленила бы полосу,
// которая на первом выпуске отказала бы.

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

// registryLaneKeys — ключница пробы: один действующий подписной ключ.
type registryLaneKeys struct{ mat tokensigner.SigningMaterial }

func (k registryLaneKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

// registryLaneSigner — подписант с одним ключом P-256.
func registryLaneSigner(t *testing.T) *tokensigner.Signer {
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
	}, registryLaneKeys{mat: tokensigner.SigningMaterial{
		KID:           domain.KeyID("registry-lane-1"),
		Algorithm:     domain.SigningAlgorithm("ES256"),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}})
	if err != nil {
		t.Fatalf("подписант: %v", err)
	}
	return s
}
