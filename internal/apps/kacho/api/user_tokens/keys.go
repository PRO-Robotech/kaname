// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// keys.go — helpers генерации пары ключей (private_key_jwt) для User-токенов.
//
// Генерирует пары ECDSA P-256, кодирует их как PKCS#8 / SPKI PEM и проецирует
// публичный ключ в JWK для регистрации клиента в Hydra. Приватный ключ никогда
// не персистится в kacho-iam DB; храним только публичный PEM (для диагностики
// ротации) и строку алгоритма.
package user_tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// generatedKey — артефакты, произведённые generateES256Key.
type generatedKey struct {
	PrivatePEM string
	PublicPEM  string
	JWK        clients.JWK
	Algorithm  string
}

// generateES256Key генерирует свежую пару ECDSA P-256, возвращая PKCS#8 PEM
// (private), SPKI PEM (public) и JWK-проекцию публичного ключа с `alg=ES256`,
// `use=sig` и переданным `kid`.
func generateES256Key(kid string) (generatedKey, error) {
	if kid == "" {
		return generatedKey{}, fmt.Errorf("kid required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return generatedKey{}, fmt.Errorf("generate ecdsa p256: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return generatedKey{}, fmt.Errorf("marshal pkcs8: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return generatedKey{}, fmt.Errorf("marshal spki: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Размер координаты P-256 — 32 байта; left-pad, если big.Int.Bytes вернул короче.
	xBytes := padLeft(priv.X.Bytes(), 32)
	yBytes := padLeft(priv.Y.Bytes(), 32)

	jwk := clients.JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Kid: kid,
		Alg: "ES256",
		Use: "sig",
	}

	return generatedKey{
		PrivatePEM: string(privPEM),
		PublicPEM:  string(pubPEM),
		JWK:        jwk,
		Algorithm:  "ES256",
	}, nil
}

// padLeft возвращает slice длины `size` с входом, дополненным нулями слева.
// Если `b` уже >= size — возвращается без изменений.
func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
