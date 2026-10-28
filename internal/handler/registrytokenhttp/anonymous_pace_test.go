// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenhttp

// anonymous_pace_test.go — анонимная выдача сверх темпа источника отвечает
// кодом превышения со сроком ожидания (kaname#928).
//
// Полоса здесь НАСТОЯЩАЯ — вариант использования и производственный темп на
// неподвижных часах; дублёр только у подписанта. Источник выводит правило,
// поданное обработчику, а не заголовок, который прислал предъявитель.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/exchangepace"
)

type anonMinter struct{ calls int }

func (m *anonMinter) MintToken(context.Context, registrytokenuc.MintInput) (registrytokenuc.MintOutput, error) {
	m.calls++
	return registrytokenuc.MintOutput{AccessToken: "anon.jwt.token", ExpiresIn: 120}, nil
}

// pacedAnonHandler — обработчик над настоящей полосой с темпом perSec на
// источник; источник — адрес пира запроса.
func pacedAnonHandler(t *testing.T, perSec int) (*TokenHandler, *anonMinter) {
	t.Helper()
	at := time.Unix(1_700_000_000, 0)
	pace, err := exchangepace.New(perSec, func() time.Time { return at })
	if err != nil {
		t.Fatalf("темп пробы: %v", err)
	}
	m := &anonMinter{}
	uc, err := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		AllowedAudiences: []string{"registry.kacho.local"},
		DefaultService:   "registry.kacho.local",
		Anonymous:        registrytokenuc.AnonymousIdentity{ClientID: "registry-anonymous", Pace: pace},
	}, m)
	if err != nil {
		t.Fatalf("полоса пробы: %v", err)
	}
	h := NewTokenHandler(Config{
		Realm:          "https://api.example.test/iam/token",
		DefaultService: "registry.kacho.local",
		Source:         func(r *http.Request) string { return strings.Split(r.RemoteAddr, ":")[0] },
	}, uc)
	return h, m
}

func anonPullFrom(h http.Handler, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local&scope=repository:pub/app:pull", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestToken_AnonymousBeyondThePacePerSourceIs429WithRetryAfter(t *testing.T) {
	h, m := pacedAnonHandler(t, 1)

	if first := anonPullFrom(h, "192.0.2.10:40000"); first.Code != http.StatusOK {
		t.Fatalf("первый вход источника в пределах темпа: статус %d, тело %q", first.Code, first.Body.String())
	}
	rec := anonPullFrom(h, "192.0.2.10:40001")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("второй вход источника при темпе 1 в секунду: статус %d, ждали 429; тело %q",
			rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, ждали срок целыми секундами вверх: 1", got)
	}
	if body := rec.Body.String(); body != tooManyBody+"\n" {
		t.Errorf("тело отказа по темпу = %q, ждали фиксированное %q", body, tooManyBody)
	}
	assertNoBearerHandedOut(t, rec.Body.Bytes())
	if m.calls != 1 {
		t.Fatalf("подписант позван %d раз; сверх темпа чеканки нет", m.calls)
	}

	// Законный близнец: другой источник в пределах темпа.
	if twin := anonPullFrom(h, "192.0.2.20:40000"); twin.Code != http.StatusOK {
		t.Fatalf("другой источник в пределах темпа: статус %d, тело %q", twin.Code, twin.Body.String())
	}
}
