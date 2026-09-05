// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_contour_integration_test.go — контур своей чеканки целиком, против
// настоящей базы: ключница → подписант → публикуемый набор → авторитет отзыва.
//
// Пробы уровней проверяют части. Эта проверяет, что части СХОДЯТСЯ: токен,
// выпущенный нашим подписантом, проверяется ключом из НАШЕЙ записи набора, а
// после записи отзыва тот же токен перестаёт быть действительным. Две пробы по
// половине этого не утверждают: каждая была бы зелена о своей стороне, а
// вопрос «про один ли они предмет» не задаётся ни одной.
package pg_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/jwksproxyhttp"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

const contourIssuer = "https://iam.kacho.local"

// TestTokenContour_MintedTokenVerifiesAgainstOurPublishedSet — контур сходится.
func TestTokenContour_MintedTokenVerifiesAgainstOurPublishedSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	at := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }

	wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
	require.NoError(t, err)
	repo := kachopg.NewSigningKeyRepo(pool)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgES256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        clock,
	}, repo, repo, wrapper)
	require.NoError(t, err)
	require.NoError(t, ks.EnsureSigningKey(ctx))

	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: contourIssuer, Clock: clock, MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ks)
	require.NoError(t, err)

	// Выпуск.
	tok, err := signer.Sign(ctx, tokensigner.Request{
		Subject: "sva-contour", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err)

	// Публикация: ключ, которым подписано, УЖЕ в ответе эндпоинта. Предикат
	// сформулирован на ОТВЕТЕ, а не на строке в базе: строка в базе не
	// означает, что потребитель ключ увидит.
	keySet := jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: ks})
	rec := httptest.NewRecorder()
	keySet.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/keys", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), string(tok.KID),
		"ключ, которым подписан токен, обязан быть в ответе публикатора")

	// Проверка токена ключом ИЗ ОТВЕТА публикатора — не из памяти процесса:
	// иначе проба утверждала бы о ключнице, а не о том, что публикуемое
	// пригодно для проверки.
	verifyKey := publicKeyFromKeySet(t, rec.Body.String(), string(tok.KID))
	parsed, err := jwt.NewParser(
		jwt.WithValidMethods(tokenpolicy.Algorithms()),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(contourIssuer),
		jwt.WithAudience("registry.kacho.local"),
		jwt.WithTimeFunc(clock),
	).Parse(tok.Token, func(*jwt.Token) (any, error) { return verifyKey, nil })
	require.NoError(t, err, "токен обязан проверяться ключом из публикуемого набора")
	require.True(t, parsed.Valid)

	// Отзыв читается НА ПРЕДЪЯВЛЕНИИ — вопрос ставится СКВОЗЬ обе стороны:
	// записали отзыв, предъявили токен, получили отказ.
	revocations := kachopg.NewMintedTokenRevocationRepo(pool)
	authority := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer: contourIssuer, Keys: ks, Revocations: revocations, Clock: clock,
	})

	// Положительный контроль: НЕ отозванный субъект при ДОСТУПНОМ авторитете
	// принимается. Без него авторитет, который всегда отвечает отказом,
	// проходит пробу целиком.
	require.True(t, introspect(t, authority, tok.Token), "живой токен объявлен недействительным")

	require.NoError(t, revocations.Revoke(ctx, "sva-contour", at.Add(time.Second), "ключ утёк", "usr-admin"))
	require.False(t, introspect(t, authority, tok.Token), "отозванный субъект остался действительным")

	// И токен ДРУГОГО субъекта отзывом не задет: отзыв адресный, а не
	// «закрыть всех».
	other, err := signer.Sign(ctx, tokensigner.Request{
		Subject: "sva-other", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 5 * time.Minute,
	})
	require.NoError(t, err)
	require.True(t, introspect(t, authority, other.Token), "отзыв задел постороннего субъекта")

	// Ротация не рвёт живой токен: после смены подписывающего прежний ключ
	// остаётся в наборе, и подписанное им по-прежнему проверяется.
	_, err = ks.Rotate(ctx)
	require.NoError(t, err)
	rec = httptest.NewRecorder()
	keySet.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/keys", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), string(tok.KID),
		"ротация вынесла из набора ключ, которым подписаны живые токены")
	require.True(t, introspect(t, authority, other.Token), "ротация сделала живой токен недействительным")
}

func introspect(t *testing.T, h http.Handler, token string) bool {
	t.Helper()
	body := strings.NewReader(url.Values{"token": {token}}.Encode())
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode, "авторитет обязан ответить по существу: %s", raw)
	var out struct {
		Active bool `json:"active"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out.Active
}

// publicKeyFromKeySet собирает публичный ключ ИЗ ОТВЕТА публикатора ровно так,
// как это сделал бы потребитель: по объявленным координатам, а не заглядывая
// во внутренности процесса. Разбор здесь — часть утверждения: документ,
// который потребитель разобрать не может, набором не является.
func publicKeyFromKeySet(t *testing.T, body, kid string) any {
	t.Helper()
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &doc))
	for _, k := range doc.Keys {
		if k.Kid != kid {
			continue
		}
		require.Equal(t, "EC", k.Kty)
		require.Equal(t, "P-256", k.Crv)
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		require.NoError(t, err)
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		require.NoError(t, err)
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
	}
	t.Fatalf("ключ %q не найден в ответе публикатора", kid)
	return nil
}
