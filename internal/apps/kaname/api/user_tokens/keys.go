// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keys.go — helpers генерации пары ключей (private_key_jwt) для User-токенов.
//
// Генерирует пары ECDSA P-256 и кодирует их как PKCS#8 / SPKI PEM. Приватный
// ключ никогда не персистится в kaname DB; храним только публичный PEM (по нему
// проверяется подпись `client_assertion`) и строку алгоритма. Проекция в JWK
// для регистрации клиента у внешнего поставщика снята: регистрации у этого
// удостоверения нет с #1121, а читателя у проекции не было с тех пор ни одного.
package user_tokens

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// generatedKey — артефакты, произведённые generateES256Key.
type generatedKey struct {
	PrivatePEM string
	PublicPEM  string
	Algorithm  string
}

// generateES256Key генерирует свежую пару ECDSA P-256, возвращая PKCS#8 PEM
// (private) и SPKI PEM (public) с `alg=ES256`.
func generateES256Key() (generatedKey, error) {
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

	return generatedKey{
		PrivatePEM: string(privPEM),
		PublicPEM:  string(pubPEM),
		Algorithm:  "ES256",
	}, nil
}
