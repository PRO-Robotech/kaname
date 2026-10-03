// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package lanesigner_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kaname/internal/testsupport/lanesigner"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// TestNew_IssuesARealES256Token — предмет пакета: подписант пробы выпускает
// настоящий токен, а не принимает вход молча. Выпуск идёт продуктовым `Sign`
// (тот же отсев запроса, та же подпись), заголовок несёт алгоритм ключа и его
// идентификатор.
func TestNew_IssuesARealES256Token(t *testing.T) {
	s := lanesigner.New(t)
	if got := s.Issuer(); got != lanesigner.Issuer {
		t.Fatalf("издатель %q, ожидался %q", got, lanesigner.Issuer)
	}
	tok, err := s.Sign(context.Background(), tokensigner.Request{
		Subject:   "probe",
		Audience:  []string{"registry"},
		TokenType: "JWT",
		TTL:       time.Minute,
	})
	if err != nil {
		t.Fatalf("выпуск: %v", err)
	}
	if tok.KID != lanesigner.KeyID {
		t.Fatalf("идентификатор ключа %q, ожидался %q", tok.KID, lanesigner.KeyID)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok.Token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("разбор выпущенного: %v", err)
	}
	if alg := parsed.Header["alg"]; alg != "ES256" {
		t.Fatalf("алгоритм в заголовке %v, ожидался ES256", alg)
	}
	if kid := parsed.Header["kid"]; kid != string(lanesigner.KeyID) {
		t.Fatalf("kid в заголовке %v, ожидался %q", kid, lanesigner.KeyID)
	}
}

// TestNew_IsNotMoreLenientThanTheProduct — законный близнец отказа: запрос,
// который продукт отвергает, подписант пробы тоже отвергает. Фикстура,
// пропускающая такой запрос, зеленила бы полосу, отказывающую на первом выпуске.
func TestNew_IsNotMoreLenientThanTheProduct(t *testing.T) {
	s := lanesigner.New(t)
	_, err := s.Sign(context.Background(), tokensigner.Request{
		Subject:   "probe",
		Audience:  []string{"registry"},
		TokenType: "JWT",
		TTL:       s.MaxTokenTTL() + time.Second,
	})
	if err == nil {
		t.Fatal("срок выше потолка выпущен — подписант пробы снисходительнее продукта")
	}
}
