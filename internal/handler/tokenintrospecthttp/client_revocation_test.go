// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_revocation_test.go — второй ключ отсечки: КЛИЕНТ (приёмка F2, F2-32,
// сторона авторитета).
//
// # Почему двух проб по половине недостаточно
//
// Первая половина — «после отзыва новый токен не выдаётся» — верна и зелена.
// Вторая — «отозванный токен не проходит» — верна и зелена на токене,
// отозванном ПО СУБЪЕКТУ. Целое ломается ровно посередине: если отзыв КЛИЕНТА
// не порождает отсечки для уже выданных ИМ токенов, обе половины остаются
// зелёными, а токен уволенного клиента продолжает ходить до истечения срока.
//
// Это тот самый разрыв, невидимый ни с одной стороны по отдельности: каждая
// сторона исправна и проверена своими пробами, а вопрос, который задаёт одна,
// не тот, на который отвечает другая.
package tokenintrospecthttp_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/signingkeygen"
)

// errAuthorityDown — недоступность источника отсечек.
var errAuthorityDown = errors.New("revocation authority is down")

// mintWithClaims чеканит токен с произвольным составом утверждений.
func mintWithClaims(t *testing.T, label, sub string, iat time.Time, extra map[string]any, pub *domain.PublishedKey) string {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(mat.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	// Идентификатор ключа обязан быть РАЗНЫМ у каждого токена пробы: два
	// токена одного субъекта с одним kid перетёрли бы друг друга в наборе, и
	// проба покраснела бы на подписи, ничего не сказав о предмете.
	kid := "kacho-" + label
	claims := jwt.MapClaims{
		"iss": testIssuer, "sub": sub, "aud": []string{"registry.kacho.local"},
		"iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(5 * time.Minute).Unix(),
		"jti": "tok-" + label,
	}
	for k, v := range extra {
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	tok.Header["typ"] = "at+jwt"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	*pub = domain.PublishedKey{KID: domain.KeyID(kid), Algorithm: domain.SigningAlgES256, PublicKeyPEM: mat.PublicKeyPEM}
	return raw
}

// TestF2_32_RevokingTheClientStopsTokensItAlreadyIssued — отзыв клиента доходит
// до предъявления.
func TestF2_32_RevokingTheClientStopsTokensItAlreadyIssued(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	iat := now.Add(-time.Minute)

	const (
		owner       = "usr_0123456789abcdefg"
		userClient  = "uoc_0123456789abcdefg"
		saOwner     = "sva_0123456789abcdefg"
		saKeyClient = "soc_0123456789abcdefg"
	)

	var userPub, saPub, freshPub domain.PublishedKey
	userToken := mintWithClaims(t, "user-client", owner, iat, map[string]any{"kacho_user_token_id": userClient}, &userPub)
	saToken := mintWithClaims(t, "sa-client", saOwner, iat, map[string]any{"kacho_sa_key_id": saKeyClient}, &saPub)
	freshToken := mintWithClaims(t, "fresh-client", owner, iat, map[string]any{"kacho_user_token_id": "uoc_zzzzzzzzzzzzzzzzz"}, &freshPub)

	keys := stubKeys{keys: []domain.PublishedKey{userPub, saPub, freshPub}}

	// (1) Положительный контроль: пока отсечек нет, ОБА токена проходят. Без
	// него проба зелена на авторитете, отвергающем всё.
	h := newHandler(keys, stubRevocations{before: map[string]time.Time{}}, now)
	for name, tok := range map[string]string{"клиент пользователя": userToken, "ключ служебной учётки": saToken} {
		code, body := ask(t, h, tok)
		if code != 200 || body["active"] != true {
			t.Fatalf("%s: до отзыва токен обязан проходить, получено code=%d body=%v", name, code, body)
		}
	}

	// (2) Отсечка, ключуемая КЛИЕНТОМ, — каждый повод отдельным входом.
	//
	// Реализация, читающая только субъекта, зелена на половине класса: она
	// пропустит оба этих токена, при том что клиент, которым они выданы, снят.
	for name, c := range map[string]struct {
		client string
		token  string
	}{
		"клиент пользовательского токена": {userClient, userToken},
		"клиент ключа служебной учётки":   {saKeyClient, saToken},
	} {
		h := newHandler(keys, stubRevocations{before: map[string]time.Time{
			c.client: now, // отсечка ПОЗЖЕ выпуска токена
		}}, now)
		code, body := ask(t, h, c.token)
		if code != 200 || body["active"] != false {
			t.Fatalf("%s: отзыв клиента обязан снимать уже выданные им токены, получено code=%d body=%v", name, code, body)
		}

		// Токен ДРУГОГО клиента того же владельца отсечкой по клиенту не
		// затронут: отзыв снимает выданное ЭТИМ клиентом, а не блокирует
		// принципала целиком.
		if c.client == userClient {
			code, body = ask(t, h, freshToken)
			if code != 200 || body["active"] != true {
				t.Fatalf("отсечка по клиенту задела чужой токен: code=%d body=%v", code, body)
			}
		}
	}

	// (3) Отсечка, ключуемая СУБЪЕКТОМ, продолжает действовать — второй ключ
	// добавлен к существующему механизму, а не подменил его.
	h = newHandler(keys, stubRevocations{before: map[string]time.Time{owner: now}}, now)
	if code, body := ask(t, h, userToken); code != 200 || body["active"] != false {
		t.Fatalf("отзыв субъекта обязан действовать по-прежнему: code=%d body=%v", code, body)
	}

	// (4) Отзыв действует ВПЕРЁД: выпущенное ПОСЛЕ отсечки снова действительно,
	// иначе отзыв означал бы вечную блокировку клиента, а не снятие выданного.
	h = newHandler(keys, stubRevocations{before: map[string]time.Time{
		userClient: iat.Add(-time.Hour),
	}}, now)
	if code, body := ask(t, h, userToken); code != 200 || body["active"] != true {
		t.Fatalf("отсечка раньше выпуска не должна снимать токен: code=%d body=%v", code, body)
	}

	// (5) Недоступность источника отсечек — ОТКАЗ, а не «не отозван».
	h = newHandler(keys, stubRevocations{err: errAuthorityDown}, now)
	if code, _ := ask(t, h, userToken); code != 503 {
		t.Fatalf("недоступность авторитета обязана давать отказ, а не суждение: code=%d", code)
	}
}

// TestTokenWithoutIssuedAtIsRefusedBecauseItCannotBeRevoked — токен без отметки
// выпуска не сопоставим НИ С КАКОЙ отсечкой.
//
// Принять его значило бы завести материал, который отозвать нечем ни сегодня,
// ни завтра, — при том что снаружи он выглядит обыкновенным.
func TestTokenWithoutIssuedAtIsRefusedBecauseItCannotBeRevoked(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(mat.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": testIssuer, "sub": "usr_0123456789abcdefg", "aud": []string{"registry.kacho.local"},
		"exp": now.Add(5 * time.Minute).Unix(), "jti": "tok-no-iat",
	})
	tok.Header["kid"] = "kacho-no-iat"
	tok.Header["typ"] = "at+jwt"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}

	keys := stubKeys{keys: []domain.PublishedKey{{
		KID: "kacho-no-iat", Algorithm: domain.SigningAlgES256, PublicKeyPEM: mat.PublicKeyPEM,
	}}}
	// Отсечек нет вовсе — и всё же токен отвергается: предмет не в отсечке, а
	// в невозможности его когда-либо отозвать.
	h := newHandler(keys, stubRevocations{before: map[string]time.Time{}}, now)
	if code, body := ask(t, h, raw); code != 200 || body["active"] != false {
		t.Fatalf("токен без отметки выпуска обязан отвергаться: code=%d body=%v", code, body)
	}
}
