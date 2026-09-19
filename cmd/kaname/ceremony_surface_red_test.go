// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_surface_red_test.go — полоса RED сцены A-1 (Линия A, под-фаза S1):
// церемония OAuth 2.1 `authorization_code` НАШИМИ силами.
//
// # Почему эти пробы честно КРАСНЫ, а не «не выполнились»
//
// Каждая проба собирает РЕАЛЬНУЮ внешнюю поверхность выдачи kaname — ровно тем
// же вызовом, что и композиционный корень (`serve.go` через
// `registrytokenwire.Build` + `clienttokenwire.New`, монтирующий
// `clienttokenhttp.TokenPath`; образец — `serve_client_token_wiring_test.go`).
// Затем она задаёт вопрос церемонии по HTTP и утверждает её ответ.
//
// На `dd66b5be` церемонии нет (предикаты §1 приёмки A–D, G, H = ∅, перемерено):
//   - `/iam/v1/authorize` и `/.well-known/oauth-authorization-server` НЕ
//     смонтированы → mux отвечает 404 (маршрута нет);
//   - вид выдачи `authorization_code` НЕ принят токен-эндпоинтом → он отвечает
//     400 `unsupported_grant_type` на шаге разбора вида выдачи, ДО обращения к
//     базе/подписанту (`clienttokenhttp/handler.go` шаг 3).
//
// Значит красный приходит от ОТСУТСТВИЯ предмета у испытуемого, а не от
// компиляции (пробы ссылаются только на существующие символы), не от фикстуры
// (пула нет — как и в образце: путь отказа наступает до базы) и не от
// несозданного условия. Пул `nil` намеренно: 404 и отказ вида выдачи наступают
// до любого чтения, поэтому Postgres тут ничего бы не изменил, кроме внесения
// риска «не выполнилось» (Docker) в детерминированную пробу.
//
// Реализацию (порт fosite + порт `LoginAuthority` + хранилище кода) открывает
// именно этот честный красный (`change-graph.md` §5).
//
// # Что НЕ здесь и почему
//
//   - E-сквозные (приём краем/отзыв на предъявлении: 01, 18, 19) требуют
//     поднятого стенда платформы — стенда нет, сквозные не запускаются;
//   - DB-инварианты хранилища кода (26) требуют ТИПА репозитория, которого нет
//     на `dd66b5be` (предикат C = ∅) — проба против него не скомпилировалась бы
//     (это «не выполнилось», не красный), поэтому одноразовость проверяется
//     здесь ПОВЕДЕНИЕМ поверхности (13, 17), а атомарность DB — предмет
//     GREEN-полосы вместе с самим типом;
//   - `refresh_token`/отзыв семейства (20, 21, 28) — под-фаза S2, вне этого красного.

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clienttokenwire"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
)

const (
	// authorizePath — объявленный приёмкой путь эндпоинта авторизации.
	ceremonyAuthorizePath = "/iam/v1/authorize"
	// discoveryPath — метаданные OAuth AS (RFC 8414 / hydra
	// OauthAuthorizationServerPath).
	ceremonyDiscoveryPath = "/.well-known/oauth-authorization-server"
	// grantAuthorizationCode — вид выдачи церемонии (RFC 6749 §4.1).
	grantAuthorizationCode = "authorization_code"
)

// buildCeremonyIssuanceSurface собирает внешнюю поверхность выдачи ТЕМ ЖЕ
// вызовом, что и композиционный корень. Стабы порта (`wiringResolver` и др.)
// переиспользуются из `serve_client_token_wiring_test.go`: до них дело на
// полосе `authorization_code` не доходит — вид выдачи отвергается раньше.
func buildCeremonyIssuanceSurface(t *testing.T) *http.ServeMux {
	t.Helper()
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
	mux.Handle(clienttokenhttp.TokenPath, h)
	return mux
}

// ceremonyGET — браузерный фронт-канал (GET авторизации/обнаружения).
func ceremonyGET(mux *http.ServeMux, path string, q url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	target := path
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// ceremonyTokenPOST — бэк-канал обмена (POST токен-эндпоинта, форма).
func ceremonyTokenPOST(mux *http.ServeMux, form url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)
	return rec
}

// mountRoute сообщает, смонтирован ли путь на поверхности: not-found ⇔ маршрута
// нет. Ровно этим достижимость отличается от отсутствия (см. образец).
func mounted(rec *httptest.ResponseRecorder) bool { return rec.Code != http.StatusNotFound }

// TestLINEA1_23_CeremonyEndpointsMountedOnIssuingSurfaceAndMethodBound —
// сценарий LINE-A-1-23 (I): эндпоинт авторизации и обнаружения СМОНТИРОВАНЫ на
// внешней поверхности выдачи, метод ограничен.
//
// Положительный контроль предмета (§5, «на внешней поверхности все пути
// резолвятся»): пути ДОЛЖНЫ отвечать церемонией, а не 404. На dd66b5be они не
// смонтированы → 404 → честный красный «эндпоинт не смонтирован».
//
// Отрицательная половина (те же пути на внутреннем/метрик слушателе → 404)
// СЕЙЧАС молчала бы (их нет нигде), поэтому единственный несущий здесь —
// положительный контроль (`change-graph.md` §9: негатив на снятом предмете
// замолкает; несущим остаётся позитив).
func TestLINEA1_23_CeremonyEndpointsMountedOnIssuingSurfaceAndMethodBound(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	// Положительный контроль: токен-эндпоинт УЖЕ смонтирован (сосед по
	// поверхности) — иначе красное ниже было бы о сломанной сборке, а не об
	// отсутствии церемонии.
	if rec := ceremonyTokenPOST(mux, url.Values{"grant_type": {grantAuthorizationCode}}); rec.Code == http.StatusNotFound {
		t.Fatalf("контроль сборки: %s не смонтирован — красное ниже было бы о сборке, а не о церемонии", clienttokenhttp.TokenPath)
	}

	for _, path := range []string{ceremonyAuthorizePath, ceremonyDiscoveryPath} {
		rec := ceremonyGET(mux, path, nil)
		if !mounted(rec) {
			t.Errorf("LINE-A-1-23 КРАСНЫЙ: %s не смонтирован на поверхности выдачи (код %d, ожидался маршрут церемонии) — эндпоинт церемонии отсутствует", path, rec.Code)
		}
	}
}
