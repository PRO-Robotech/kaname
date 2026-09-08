// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// serve_client_token_wiring_test.go — приземление токен-эндпоинта платформы
// (приёмка F2, F2-45 сторона поверхности, §9.1 п. 11).
//
// # Что здесь утверждается и почему именно это
//
// Не «эндпоинт написан», а «эндпоинт ДОСТИЖИМ ровно там, где объявлен». Обе
// половины несущие: собранный и никуда не смонтированный эндпоинт зелен по
// всем своим пробам и не обслуживает ни одного клиента; смонтированный на
// внутренний слушатель — выставляет наружу то, чего наружу быть не должно.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/clienttokenwire"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

type wiringResolver struct{}

func (wiringResolver) ResolveAssertionClient(context.Context, string) (domain.AssertionClient, error) {
	return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
}

// wiringIssuers — перечень доверенных издателей. Пустой: проба утверждает
// ДОСТИЖИМОСТЬ поверхности, а не исход разрешения, и пустой перечень отвечает
// тем же признаком, что настоящий.
type wiringIssuers struct{}

func (wiringIssuers) ResolveTrustedIssuer(context.Context, string, string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	return domain.TrustedIssuer{}, domain.AssertionClient{}, domain.ErrTrustedIssuerUnknown
}

type wiringReplay struct{}

func (wiringReplay) Redeem(context.Context, string, string, time.Time) error { return nil }

type wiringClaims struct{}

func (wiringClaims) ClaimsForAssertionClient(context.Context, domain.AssertionClient, service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	return map[string]any{}, service.ResolvedPrincipal{}, nil
}

type wiringSigner struct{}

func (wiringSigner) Sign(context.Context, tokensigner.Request) (tokensigner.Token, error) {
	return tokensigner.Token{}, nil
}
func (wiringSigner) Issuer() string { return "https://kaname.kacho.local" }

// TestF2_45_ClientTokenEndpointSharesTheDeclaredIssuingSurface — оба вида
// предъявления живут на ОДНОЙ внешне досягаемой поверхности и не затирают друг
// друга.
//
// Пула здесь нет намеренно: и вызов-приглашение прежнего пути, и отказ нашего
// наступают до любого обращения к базе, поэтому поверхность проверяется без неё.
func TestF2_45_ClientTokenEndpointSharesTheDeclaredIssuingSurface(t *testing.T) {
	mux, err := registrytokenwire.Build(nil, registrytokenwire.BuildConfig{
		Realm:   "https://api.kacho.local/iam/token",
		Service: "registry.kacho.local",
	})
	if err != nil {
		t.Fatalf("сборка поверхности выдачи: %v", err)
	}

	h, err := clienttokenwire.New(clienttokenwire.BuildConfig{
		ExpectedAudience:         "https://kaname.kacho.local",
		AssertionLifetimeCeiling: tokenpolicy.MaxAssertionLifetime,
		FederatedLifetimeCeiling: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:                tokenpolicy.ClockSkew,
		Clock:                    time.Now,
		AllowedAudiences:         []string{"registry.kacho.local"},
		DefaultAudience:          "registry.kacho.local",
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		PeerTimeout:              3 * time.Second,
	}, wiringResolver{}, wiringIssuers{}, wiringReplay{}, wiringSigner{}, wiringClaims{})
	if err != nil {
		t.Fatalf("сборка токен-эндпоинта: %v", err)
	}
	// Ровно так, как это делает композиционный корень.
	mux.Handle(clienttokenhttp.TokenPath, h)

	// (1) Наш путь обслуживается: объявленный метод доходит до обработчика.
	// Отказ здесь — отказ АУТЕНТИФИКАЦИИ (клиента такого нет), а не «нет
	// маршрута»: именно этим достижимость отличается от своего отсутствия.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath,
		strings.NewReader("grant_type="+tokenpolicy.GrantTypeClientCredentials+
			"&client_assertion_type="+tokenpolicy.ClientAssertionType+
			"&client_assertion=a.b.c"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusNotFound {
		t.Fatalf("%s не смонтирован на поверхности выдачи", clienttokenhttp.TokenPath)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("%s ответил %d, ожидался отказ аутентификации 401", clienttokenhttp.TokenPath, rec.Code)
	}

	// (2) Прежний путь НЕ затёрт: два эндпоинта на одной поверхности обязаны
	// сосуществовать, иначе перевод одного вида выдачи ломает другой.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath, nil))
	if rec.Code == http.StatusNotFound {
		t.Fatalf("%s перестал резолвиться после монтирования соседа", registrytokenhttp.TokenPath)
	}

	// (3) Соседние пути этой поверхностью не обслуживаются — положительный
	// контроль к первым двум: без него проба зелена на муксе, отвечающем на всё.
	for _, path := range []string{"/", "/iam/v1/token/extra", "/.well-known/jwks.json", "/iam/v1/introspect"} {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("путь %s обслуживается поверхностью выдачи (код %d), а объявлен не был", path, rec.Code)
		}
	}
}

// TestServeMountsTheClientTokenEndpointOnTheExternalSurfaceAndNowhereElse —
// перечень мест регистрации ВЫВОДИТСЯ из исходника корня, а не выписывается.
//
// Утверждение о единственном маршруте оставалось бы зелёным, уедь второй не
// туда: поэтому считается число регистраций, а не факт наличия одной.
func TestServeMountsTheClientTokenEndpointOnTheExternalSurfaceAndNowhereElse(t *testing.T) {
	src := readFileT(t, "serve.go")

	if !strings.Contains(src, "buildClientTokenEndpoint(pool, cfg, tokenSigner, logger)") {
		t.Error("serve.go: токен-эндпоинт платформы не собирается — эндпоинт без производственного вызывающего")
	}
	if !strings.Contains(src, "mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)") {
		t.Error("serve.go: токен-эндпоинт платформы не смонтирован ни на одну поверхность")
	}

	// Регистрация ровно одна, и она не на внутренних слушателях. Внутренние
	// муксы корня названы поимённо: строка, монтирующая наш путь на любой из
	// них, есть нарушение ban #6 — административная поверхность наружу.
	if n := strings.Count(src, "clienttokenhttp.TokenPath"); n != 1 {
		t.Errorf("serve.go: путь токен-эндпоинта упомянут %d раз(а), ожидалась одна регистрация", n)
	}
	for _, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, "clienttokenhttp.TokenPath") {
			continue
		}
		for _, internalMux := range []string{"jwksMux", "metricsMux", "hooksMux", "internalSrv"} {
			if strings.Contains(line, internalMux) {
				t.Errorf("serve.go: токен-эндпоинт смонтирован на внутренний слушатель (%s): %s", internalMux, strings.TrimSpace(line))
			}
		}
	}
}

var _ = client_token.Input{}
var _ = clientassertion.OutcomeAccepted
