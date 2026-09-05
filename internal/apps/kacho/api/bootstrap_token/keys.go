// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keys.go — derive the PUBLIC key of the bootstrap client from the env-held
// bootstrap ES256 private key. The private half is supplied at wire-time from a
// k8s Secret and is NEVER persisted — iam records only the public half (parity
// with the SA-key posture).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СНЯТО ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ (задача #1119)
//
// Файл проецировал наш открытый ключ в ФОРМУ ПОСТАВЩИКА (его JWK с его `kid`),
// чтобы тот принял нашу подпись. Формы поставщика на этом пути больше нет:
// удостоверение подписывает наш подписант своим ключом из ключницы, и `kid`
// проставляет он.
//
// Осталось то, у чего предмет НЕ исчез: разбор ключа и его проверка (PKCS#8,
// ECDSA, кривая P-256) плюс открытая половина в форме SPKI — она пишется в
// строку соответствия и остаётся НАШЕЙ записью о ключе бутстрап-клиента,
// которой пользуется приёмная сторона выдачи по предъявленному ключу.
package bootstrap_token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ErrSigningKeyNotConfigured — the bootstrap signing key env/Secret is absent.
// The mint path fails closed (no token) rather than fabricating a credential.
var ErrSigningKeyNotConfigured = errors.New("bootstrap token: signing key not configured")

// publicKeyPEMFromPrivatePEM parses a PKCS#8 ES256 (P-256) private-key PEM and
// returns the SPKI public PEM recorded in the mapping row. The private half never
// leaves this function's caller.
//
// Проверки формы ключа остаются СТРОГИМИ, хотя подписывает теперь не он: строка
// соответствия объявляет алгоритм `ES256`, и запись под этим именем ключа другой
// кривой сделала бы объявление ложным — а читает его приёмная сторона.
func publicKeyPEMFromPrivatePEM(privatePEM string) (string, error) {
	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		return "", errors.New("bootstrap token: invalid private PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("bootstrap token: parse private key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("bootstrap token: signing key is not ECDSA")
	}
	if priv.Curve != nil && priv.Params().Name != "P-256" {
		return "", fmt.Errorf("bootstrap token: unsupported curve %q (want P-256/ES256)", priv.Params().Name)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("bootstrap token: marshal spki: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})), nil
}
