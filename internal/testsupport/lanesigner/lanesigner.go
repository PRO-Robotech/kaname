// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package lanesigner — НАШ подписант для проб, собирающих полосу выдачи
// токена реестра (kaname#494).
//
// Полоса без нашего подписанта не собирается: другого издателя у неё нет.
// Значит каждая проба, которой нужна собранная полоса, подаёт подписанта — и
// подаёт НАСТОЯЩЕГО, построенного тем же конструктором `tokensigner.New`, что
// композиционный корень, а не нулевую структуру: фикстура, снисходительнее
// продукта, зеленила бы полосу, которая на первом выпуске отказала бы.
//
// Дом один на всех потребителей (kaname#573): прежде подписант лежал двумя
// копиями — у проб корня `cmd/kaname` и у проб `internal/registrytokenwire`, —
// и копии расходятся молча.
package lanesigner

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

const (
	// Issuer — издатель подписанта пробы.
	Issuer = "https://kaname.kacho.local"
	// KeyID — идентификатор единственного подписного ключа.
	KeyID = domain.KeyID("lane-1")
	// MaxTokenTTL — объявленный потолок срока.
	MaxTokenTTL = 30 * time.Minute
)

// keys — ключница пробы: один действующий подписной ключ.
type keys struct{ mat tokensigner.SigningMaterial }

func (k keys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

// New строит подписанта с одним свежим ключом P-256 (ES256). Отказ построения
// роняет пробу: полоса без подписанта не собирается, и продолжать нечего.
func New(t testing.TB) *tokensigner.Signer {
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
		Issuer:      Issuer,
		Clock:       time.Now,
		MaxTokenTTL: MaxTokenTTL,
	}, keys{mat: tokensigner.SigningMaterial{
		KID:           KeyID,
		Algorithm:     domain.SigningAlgorithm("ES256"),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
	}})
	if err != nil {
		t.Fatalf("подписант: %v", err)
	}
	return s
}
