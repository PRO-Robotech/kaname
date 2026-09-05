// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// f1b_binding_test.go — Ф1б-10: привязка токена к ключу владельца получает
// ПРОИЗВОДСТВЕННОГО читателя на живом контуре.
//
// # Что здесь закрывается
//
// Подписант умеет проставлять привязку с фазы Ф1, и его собственная проба это
// утверждает. Но производственный вызывающий её не передавал вовсе: поля не
// было во входе контура. Возможность, у которой нет ни одного вызывающего, —
// тот же класс, что хранилище без читателя: она выглядит существующей, потому
// что запись в неё удаётся.
//
// # Чего эта проба НЕ утверждает
//
// Она не утверждает, что на конкретном стенде материал привязки предъявляется.
// Это свойство ПОСАДКИ слушателя (запрашивает ли он клиентский сертификат), а
// не дерева. Предмет здесь — что предъявленный материал ДОХОДИТ до подписанта
// и попадает в токен, а непредъявленный не превращается в выдуманный.
package registrytokenwire

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

// f1bKeys — ключница пробы: один действующий подписной ключ.
type f1bKeys struct{ mat tokensigner.SigningMaterial }

func (k f1bKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

func f1bSigner(t *testing.T) *tokensigner.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      "https://iam.kacho.local",
		Clock:       time.Now,
		MaxTokenTTL: 30 * time.Minute,
	}, f1bKeys{mat: tokensigner.SigningMaterial{
		KID: domain.KeyID("f1b-1"), Algorithm: domain.SigningAlgorithm("ES256"),
		PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM,
	}})
	require.NoError(t, err)
	return s
}

// f1bCnfOf достаёт привязку из выпущенного токена, не проверяя подписи: предмет
// пробы — СОСТАВ утверждений, а не проверка.
func f1bCnfOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	claims := jwt.MapClaims{}
	_, _, err := parser.ParseUnverified(raw, claims)
	require.NoError(t, err)
	cnf, _ := claims["cnf"].(map[string]any)
	return cnf
}

// TestF1b10_PresentedMaterialReachesTheSignerThroughTheLiveContour.
func TestF1b10_PresentedMaterialReachesTheSignerThroughTheLiveContour(t *testing.T) {
	minter := NewLocalMinter(f1bSigner(t), 5*time.Minute)

	const thumbprint = "TCyU4b8s7Yy0aBcDeFgHiJkLmNoPqRsTuVwXyZ012ab"

	bound, err := minter.MintToken(context.Background(), registrytokenuc.MintInput{
		Subject: "sva-ci", Audience: "registry.kacho.local", Scope: "repository:app:pull",
		// Материал ПРЕДЪЯВЛЕН при выдаче — отпечаток проверенного клиентского
		// сертификата (RFC 8705).
		ConfirmationX5TS256: thumbprint,
	})
	require.NoError(t, err)
	cnf := f1bCnfOf(t, bound.AccessToken)
	require.NotNil(t, cnf, "предъявленный материал не доехал до подписанта — привязка не "+
		"проставлена вовсе")
	require.Equal(t, thumbprint, cnf["x5t#S256"],
		"привязка проставлена НЕ тем отпечатком, что предъявлен")

	// Зеркальная половина: материал НЕ предъявлен ⇒ привязки нет. Она не
	// выдумывается подписантом и не появляется там, где её не просили — иначе
	// человеческий принципал получил бы отказ, которого фаза не вводила.
	plain, err := minter.MintToken(context.Background(), registrytokenuc.MintInput{
		Subject: "sva-ci", Audience: "registry.kacho.local",
	})
	require.NoError(t, err)
	require.Nil(t, f1bCnfOf(t, plain.AccessToken),
		"привязка появилась там, где материал не предъявляли — она выдумана")
}

// TestF1b10_ProofOfPossessionThumbprintTravelsToo — вторая форма материала
// (RFC 9449) доходит тем же путём.
func TestF1b10_ProofOfPossessionThumbprintTravelsToo(t *testing.T) {
	minter := NewLocalMinter(f1bSigner(t), 5*time.Minute)
	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	out, err := minter.MintToken(context.Background(), registrytokenuc.MintInput{
		Subject: "sva-ci", Audience: "registry.kacho.local", ConfirmationJKT: jkt,
	})
	require.NoError(t, err)
	cnf := f1bCnfOf(t, out.AccessToken)
	require.NotNil(t, cnf)
	require.Equal(t, jkt, cnf["jkt"])
}
