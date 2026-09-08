// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signer_test.go — сценарии F1-10, F1-12, F1-14, F1-15 приёмки F1.
package tokensigner_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// stubKeys — подставной источник подписного материала.
//
// Дублёр НЕ снисходительнее настоящего: он отдаёт ровно то, что ключница
// отдала бы после разворачивания обёртки, и на отсутствие подписывающего
// отвечает отказом, а не нулевой структурой.
type stubKeys struct {
	mat tokensigner.SigningMaterial
	err error
}

func (s stubKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return s.mat, s.err
}

func newMaterial(t *testing.T, kid string) tokensigner.SigningMaterial {
	t.Helper()
	m, err := signingkeygen.Generate(domain.SigningAlgRS256)
	require.NoError(t, err)
	return tokensigner.SigningMaterial{
		KID:           domain.KeyID(kid),
		Algorithm:     domain.SigningAlgRS256,
		PrivateKeyPEM: m.PrivateKeyPEM,
		PublicKeyPEM:  m.PublicKeyPEM,
	}
}

func fixedClock(at time.Time) tokensigner.Clock { return func() time.Time { return at } }

func mustSigner(t *testing.T, keys tokensigner.KeyProvider, clock tokensigner.Clock) *tokensigner.Signer {
	t.Helper()
	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      "https://kaname.kacho.local",
		Clock:       clock,
		MaxTokenTTL: time.Hour,
	}, keys)
	require.NoError(t, err)
	return s
}

// parseHeaderAndClaims разбирает выпущенный токен БЕЗ проверки подписи —
// пробе нужен состав, а не вердикт.
func parseHeaderAndClaims(t *testing.T, raw string) (map[string]any, jwt.MapClaims) {
	t.Helper()
	claims := jwt.MapClaims{}
	tok, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	require.NoError(t, err)
	return tok.Header, claims
}

// TestSigner_F1_10_KidAlwaysPresentAndDistinct — F1-10.
func TestSigner_F1_10_KidAlwaysPresentAndDistinct(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	// Then — токен несёт kid ВСЕГДА.
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kacho-a")}, fixedClock(now))
	out, err := s.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: time.Minute,
	})
	require.NoError(t, err)
	header, _ := parseHeaderAndClaims(t, out.Token)
	require.Equal(t, "kacho-a", header["kid"])

	// And — идентификаторы ключей в наборе попарно различны; утверждение на
	// наборе из ТРЁХ ключей: на одном свойство не измеряется вовсе.
	set := []string{
		string(newMaterialKID(t, "kacho-a")),
		string(newMaterialKID(t, "kacho-b")),
		string(newMaterialKID(t, "kacho-c")),
	}
	seen := map[string]bool{}
	for _, kid := range set {
		require.False(t, seen[kid], "идентификаторы ключей набора обязаны быть попарно различны")
		seen[kid] = true
	}
	require.Len(t, seen, 3)
}

func newMaterialKID(t *testing.T, kid string) domain.KeyID {
	t.Helper()
	return newMaterial(t, kid).KID
}

// TestSigner_F1_12_ExpiryIsMandatoryAtIssue — F1-12.
func TestSigner_F1_12_ExpiryIsMandatoryAtIssue(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kacho-a")}, fixedClock(now))
	base := tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"}, TokenType: "at+jwt",
	}

	// Then — выпущенный токен несёт срок.
	ok := base
	ok.TTL = time.Minute
	out, err := s.Sign(context.Background(), ok)
	require.NoError(t, err)
	_, claims := parseHeaderAndClaims(t, out.Token)
	require.Equal(t, float64(now.Add(time.Minute).Unix()), claims["exp"])

	// And — выпуск БЕЗ срока отвергается НА ВЫПУСКЕ, а не оставляется
	// на усмотрение проверяющего.
	noTTL := base
	noTTL.TTL = 0
	_, err = s.Sign(context.Background(), noTTL)
	require.ErrorIs(t, err, tokensigner.ErrExpiryRequired)

	// And — срок в прошлом отвергается тем же отказом.
	past := base
	past.TTL = -time.Minute
	_, err = s.Sign(context.Background(), past)
	require.ErrorIs(t, err, tokensigner.ErrExpiryRequired)
}

// TestSigner_F1_14_ClockIsAnInput — F1-14.
func TestSigner_F1_14_ClockIsAnInput(t *testing.T) {
	mat := newMaterial(t, "kacho-a")
	req := tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: time.Minute,
	}

	forward := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	backward := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, at := range []time.Time{forward, backward} {
		s := mustSigner(t, stubKeys{mat: mat}, fixedClock(at))
		out, err := s.Sign(context.Background(), req)
		require.NoError(t, err)
		_, claims := parseHeaderAndClaims(t, out.Token)
		require.Equal(t, float64(at.Unix()), claims["iat"],
			"отметки времени обязаны следовать ПЕРЕДАННОМУ источнику")
		require.Equal(t, float64(at.Add(time.Minute).Unix()), claims["exp"])
		require.Equal(t, at.Add(time.Minute), out.ExpiresAt)
	}
}

// TestSigner_F1_15_ConfirmationComesFromPresentedMaterial — F1-15 (часть на
// стороне подписанта; живой контур — в интеграционной пробе выдачи).
func TestSigner_F1_15_ConfirmationComesFromPresentedMaterial(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kacho-a")}, fixedClock(now))
	base := tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: time.Minute,
	}

	// Then — привязка проставляется из ПРЕДЪЯВЛЕННОГО материала.
	bound := base
	bound.Confirmation = &tokensigner.Confirmation{JKT: "thumb-of-proof-key"}
	out, err := s.Sign(context.Background(), bound)
	require.NoError(t, err)
	_, claims := parseHeaderAndClaims(t, out.Token)
	cnf, ok := claims["cnf"].(map[string]any)
	require.True(t, ok, "привязка обязана быть в токене машинного принципала")
	require.Equal(t, "thumb-of-proof-key", cnf["jkt"])

	// And — отпечаток клиентского сертификата ложится в своё поле.
	mtls := base
	mtls.Confirmation = &tokensigner.Confirmation{X5TS256: "thumb-of-client-cert"}
	out, err = s.Sign(context.Background(), mtls)
	require.NoError(t, err)
	_, claims = parseHeaderAndClaims(t, out.Token)
	cnf, ok = claims["cnf"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "thumb-of-client-cert", cnf["x5t#S256"])

	// And — привязка НЕ появляется там, где её не просили: сужение здесь было
	// бы новым отказом человеческому принципалу, не входящим в предмет фазы.
	out, err = s.Sign(context.Background(), base)
	require.NoError(t, err)
	_, claims = parseHeaderAndClaims(t, out.Token)
	_, present := claims["cnf"]
	require.False(t, present, "привязка не выдумывается подписантом")

	// And — пустая привязка не выражается как «привязка есть»: запрошенная,
	// но не заполненная — отказ, а не токен с пустым отпечатком.
	empty := base
	empty.Confirmation = &tokensigner.Confirmation{}
	_, err = s.Sign(context.Background(), empty)
	require.ErrorIs(t, err, tokensigner.ErrEmptyConfirmation)
}

// TestSigner_MandatoryClaimsAndIssuer — состав, который проверяющий обязан
// требовать, обязан ПРОИЗВОДИТЬСЯ: проверка без производителя не падает
// никогда, а требование без проверки не действует.
func TestSigner_MandatoryClaimsAndIssuer(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kacho-a")}, fixedClock(now))
	out, err := s.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: time.Minute,
	})
	require.NoError(t, err)
	header, claims := parseHeaderAndClaims(t, out.Token)
	require.Equal(t, "RS256", header["alg"])
	require.Equal(t, "at+jwt", header["typ"])
	require.Equal(t, "https://kaname.kacho.local", claims["iss"])
	require.Equal(t, "sva-1", claims["sub"])
	require.NotEmpty(t, claims["jti"], "у токена обязан быть идентификатор: без него отзыв не адресуется")

	// Отказ выпуска БЕЗ адресата — незаданный адресат означает «любой».
	_, err = s.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-1", TokenType: "at+jwt", TTL: time.Minute,
	})
	require.ErrorIs(t, err, tokensigner.ErrAudienceRequired)

	// И без субъекта: токен, не называющий, за кого он говорит, не отзывается.
	_, err = s.Sign(context.Background(), tokensigner.Request{
		Audience: []string{"registry.kacho.local"}, TokenType: "at+jwt", TTL: time.Minute,
	})
	require.ErrorIs(t, err, tokensigner.ErrSubjectRequired)
}

// TestSigner_TTLIsCappedByDeclaredCeiling — потолок срока объявлен ЧИСЛОМ и
// является слагаемым арифметики отсрочки (§6.4). Запрошенный сверх потолка
// отвергается, а не молча урезается: урезание — то же «принято и
// проигнорировано», только у величины.
func TestSigner_TTLIsCappedByDeclaredCeiling(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	s := mustSigner(t, stubKeys{mat: newMaterial(t, "kacho-a")}, fixedClock(now))
	_, err := s.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: 2 * time.Hour,
	})
	require.ErrorIs(t, err, tokensigner.ErrTTLAboveCeiling)

	// Положительный контроль: срок РОВНО на потолке проходит — иначе проба
	// зелена на подписанте, отвергающем любой срок.
	out, err := s.Sign(context.Background(), tokensigner.Request{
		Subject: "sva-1", Audience: []string{"registry.kacho.local"},
		TokenType: "at+jwt", TTL: time.Hour,
	})
	require.NoError(t, err)
	require.Equal(t, now.Add(time.Hour), out.ExpiresAt)
}

// TestSigner_RefusesToBuildWithoutClockOrIssuer — часы и издатель суть входы,
// а не умолчания: подписант без них не строится.
func TestSigner_RefusesToBuildWithoutClockOrIssuer(t *testing.T) {
	keys := stubKeys{mat: newMaterial(t, "kacho-a")}
	_, err := tokensigner.New(tokensigner.Config{Clock: fixedClock(time.Now()), MaxTokenTTL: time.Hour}, keys)
	require.Error(t, err, "издатель обязателен: незаданный означает «не сужаем»")

	_, err = tokensigner.New(tokensigner.Config{Issuer: "https://kaname.kacho.local", MaxTokenTTL: time.Hour}, keys)
	require.Error(t, err, "часы — вход, а не системное время")

	_, err = tokensigner.New(tokensigner.Config{Issuer: "https://kaname.kacho.local", Clock: fixedClock(time.Now())}, keys)
	require.Error(t, err, "потолок срока обязан быть объявлен числом")

	// Положительный контроль — с полным набором подписант строится.
	_, err = tokensigner.New(tokensigner.Config{
		Issuer: "https://kaname.kacho.local", Clock: fixedClock(time.Now()), MaxTokenTTL: time.Hour,
	}, keys)
	require.NoError(t, err)
}
