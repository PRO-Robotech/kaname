// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package signingkeygen порождает подписной ключ объявленного алгоритма и
// проверяет предъявленный ключ против объявленного порога стойкости.
//
// Алгоритм закрепляется за ключом В МОМЕНТ ПОРОЖДЕНИЯ и дальше хранится рядом
// с ним (приёмка §6.3). Ни один вход запроса алгоритм не выбирает: заголовок
// предъявленного токена лишь СВЕРЯЕТСЯ с тем, что закреплено за найденным
// ключом.
package signingkeygen

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Material — порождённая пара. Приватная половина живёт здесь ровно до
// обёртки; в хранимую строку она попадает уже обёрнутой.
type Material struct {
	Algorithm     domain.SigningAlgorithm
	PublicKeyPEM  string
	PrivateKeyPEM []byte
}

// rsaBits — длина модуля порождаемого RSA-ключа. Берётся из объявленного
// порога, а не из своей константы: два числа об одном предмете разошлись бы.
func rsaBits() int { return domain.SigningAlgRS256.MinBits() }

// Generate порождает ключ названного алгоритма.
func Generate(alg domain.SigningAlgorithm) (Material, error) {
	switch alg {
	case domain.SigningAlgRS256:
		key, err := rsa.GenerateKey(rand.Reader, rsaBits())
		if err != nil {
			return Material{}, fmt.Errorf("signingkeygen: rsa: %w", err)
		}
		return encode(alg, key, &key.PublicKey)
	case domain.SigningAlgES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Material{}, fmt.Errorf("signingkeygen: ecdsa: %w", err)
		}
		return encode(alg, key, &key.PublicKey)
	case domain.SigningAlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Material{}, fmt.Errorf("signingkeygen: ed25519: %w", err)
		}
		return encode(alg, priv, pub)
	default:
		return Material{}, fmt.Errorf("signingkeygen: %w", ErrUnknownAlgorithm{Algorithm: string(alg)})
	}
}

// ErrUnknownAlgorithm — алгоритм вне закрытого словаря.
type ErrUnknownAlgorithm struct{ Algorithm string }

func (e ErrUnknownAlgorithm) Error() string {
	return fmt.Sprintf("signing algorithm %q is not one of %v", e.Algorithm, domain.SigningAlgorithms())
}

func encode(alg domain.SigningAlgorithm, priv, pub any) (Material, error) {
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Material{}, fmt.Errorf("signingkeygen: marshal private: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return Material{}, fmt.Errorf("signingkeygen: marshal public: %w", err)
	}
	return Material{
		Algorithm:     alg,
		PublicKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}),
	}, nil
}

// StrengthOf возвращает стойкость предъявленного публичного ключа в тех же
// единицах, в которых объявлен порог (domain.SigningAlgorithm.MinBits).
func StrengthOf(publicKeyPEM string) (domain.SigningAlgorithm, int, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", 0, fmt.Errorf("signingkeygen: public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", 0, fmt.Errorf("signingkeygen: parse public key: %w", err)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return domain.SigningAlgRS256, k.N.BitLen(), nil
	case *ecdsa.PublicKey:
		return domain.SigningAlgES256, k.Curve.Params().BitSize, nil
	case ed25519.PublicKey:
		return domain.SigningAlgEdDSA, 256, nil
	default:
		return "", 0, fmt.Errorf("signingkeygen: unsupported public key type %T", pub)
	}
}

// CheckStrength сверяет предъявленный ключ с объявленным порогом.
//
// Текст отказа называет И порог, И предъявленную величину: отказ, не
// называющий обе, оставляет оператора гадать, на сколько он промахнулся.
func CheckStrength(alg domain.SigningAlgorithm, publicKeyPEM string) error {
	gotAlg, bits, err := StrengthOf(publicKeyPEM)
	if err != nil {
		return err
	}
	if gotAlg != alg {
		return fmt.Errorf("signingkeygen: key is %s, algorithm declared %s", gotAlg, alg)
	}
	if min := alg.MinBits(); bits < min {
		return fmt.Errorf("signingkeygen: %s key is %d bits, minimum is %d", alg, bits, min)
	}
	return nil
}
