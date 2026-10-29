// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// serve_registry_token_anonymous_test.go — АНОНИМНЫЙ ТОКЕН РЕЕСТРА ВКЛЮЧАЕТСЯ
// НАСТРОЙКОЙ СЛУЖБЫ (kaname#495, исход (а)).
//
// # Почему через настройку, а не через BuildConfig
//
// Поле `BuildConfig.AnonymousClientID` существовало и прежде, и проба,
// заполняющая его сама, зеленела бы на посадке, где ручки нет вовсе: дефект
// жил ровно между настройкой и сборкой. Здесь значение приходит переменной
// окружения, загружается `config.Load`, перелагается той же функцией, что у
// корня (`registryTokenBuildConfig`), и полоса собирается тем же
// `registrytokenwire.Build`.
//
// # Пара
//
//   - ручка задана: вход без удостоверения получает 200 и токен НАШЕГО
//     подписанта за объявленного принципала, только на чтение;
//   - ручка не задана: тот же вход — 401-вызов (fail-closed).
//
// Положительный близнец с удостоверением владельца — интеграционная проба
// serve_registry_token_anonymous_integration_test.go: ему нужна база.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	"github.com/PRO-Robotech/kaname/internal/testsupport/lanesigner"
)

const (
	anonLaneService   = "registry.probe.local"
	anonLanePrincipal = "registry-anonymous"
	// anonLanePace — темп анонимной выдачи, которого пробы пары не исчерпают.
	anonLanePace = "50"
	// anonLaneTrustDomain и anonLaneForwarderSAN — домен доверия пробы и
	// объявленный в нём доверенный пересыльщик точки (kaname#930).
	anonLaneTrustDomain  = "kacho.cloud"
	anonLaneForwarderSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry"
	// anonLaneIssuer — издатель полосы пробы: умолчания у процесса нет (kaname#309).
	anonLaneIssuer = "https://access.example.test/iam/token"
)

// anonymousLaneFromSettings собирает докерную полосу из НАСТРОЙКИ службы: env →
// Load → страж старта → переложение корня → сборка. pool — nil для входа без
// удостоверения (он не доходит до базы), живой — для близнеца с удостоверением.
//
// pace — темп анонимной выдачи на источник (kaname#928) строкой переменной;
// пусто — переменная не задана.
func anonymousLaneFromSettings(t *testing.T, principal, pace string, pool *pgxpool.Pool) http.Handler {
	t.Helper()
	return anonymousLaneWithSourceRule(t, principal, pace, pool, nil)
}

// anonymousLaneWithSourceRule — та же сборка с правилом адреса источника
// rule; nil — правило над доменом доверия настройки.
func anonymousLaneWithSourceRule(t *testing.T, principal, pace string, pool *pgxpool.Pool, rule *issuingsource.Rule) http.Handler {
	t.Helper()
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE", anonLaneService)
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__ISSUER", anonLaneIssuer)
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_CLIENT_ID", principal)
	if pace != "" {
		t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_PER_SOURCE_PER_SEC", pace)
	}
	// Доверенный пересыльщик точки (kaname#930) — прокси реестра в домене
	// доверия пробы: без него страж старта не пускает анонимный поток.
	t.Setenv("KANAME_AUTHN__TRUST_DOMAIN", anonLaneTrustDomain)
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__ANONYMOUS_FORWARDER_SAN", anonLaneForwarderSAN)
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if err := cfg.APIServer.RegistryToken.Validate(cfg.AuthN.ClientToken, cfg.AuthN.TrustDomain()); err != nil {
		t.Fatalf("страж старта отверг настройку пробы: %v", err)
	}
	if rule == nil {
		roster, err := cfg.AuthN.LoadModuleRoster()
		if err != nil {
			t.Fatalf("перечень личностей модулей пробы: %v", err)
		}
		rule = issuingsource.New(cfg.AuthN.TrustDomain(), roster)
	}
	bc, err := registryTokenBuildConfig(cfg.APIServer.RegistryToken, registryTokenRuntime{
		signer:                 lanesigner.New(t),
		basicCredentialTimeout: credentialLanePeerTimeout,
		source:                 rule,
	})
	if err != nil {
		t.Fatalf("переложение настройки: %v", err)
	}
	mux, err := registrytokenwire.Build(pool, bc)
	if err != nil {
		t.Fatalf("registrytokenwire.Build: %v", err)
	}
	return mux
}

// anonymousPull — вход докер-клиента без удостоверения: `docker pull`
// публичного репозитория без `docker login`.
func anonymousPull(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	return anonymousPullFrom(t, h, "192.0.2.1:1234")
}

// anonymousPullFrom — тот же вход с адреса пира remote.
func anonymousPullFrom(t *testing.T, h http.Handler, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath+
		"?service="+anonLaneService+"&scope=repository:pub/app:pull", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// mintedClaims разбирает выданный токен. Подпись здесь не сверяется — сверяется
// издатель и идентификатор ключа подписанта пробы: токен выпущен НАШИМ
// подписантом, а не принесён кем-то.
func mintedClaims(t *testing.T, rec *httptest.ResponseRecorder) (jwt.MapClaims, map[string]any) {
	t.Helper()
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("тело ответа не несёт токена: %q (%v)", rec.Body.String(), err)
	}
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(body.Token, claims)
	if err != nil {
		t.Fatalf("разбор выданного токена: %v", err)
	}
	return claims, parsed.Header
}

func TestAnonymousRegistryToken_DeclaredPrincipalGetsOurReadOnlyToken(t *testing.T) {
	h := anonymousLaneFromSettings(t, anonLanePrincipal, anonLanePace, nil)
	rec := anonymousPull(t, h)
	if rec.Code != http.StatusOK {
		t.Fatalf("вход без удостоверения при заданной ручке: статус %d, ждали 200; тело %q",
			rec.Code, rec.Body.String())
	}
	claims, header := mintedClaims(t, rec)
	if claims["sub"] != anonLanePrincipal {
		t.Errorf("sub = %v, ждали объявленного принципала %q", claims["sub"], anonLanePrincipal)
	}
	if claims["scope"] != "registry:pull" {
		t.Errorf("scope = %v, ждали только чтение registry:pull", claims["scope"])
	}
	if claims["iss"] != lanesigner.Issuer || header["kid"] != string(lanesigner.KeyID) {
		t.Errorf("iss = %v, kid = %v — токен выпущен не нашим подписантом", claims["iss"], header["kid"])
	}
	aud, err := claims.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != anonLaneService {
		t.Errorf("aud = %v (%v), ждали ровно объявленного адресата %q", aud, err, anonLaneService)
	}
}

func TestAnonymousRegistryToken_UnsetKnobKeepsTheChallenge(t *testing.T) {
	h := anonymousLaneFromSettings(t, "", "", nil)
	rec := anonymousPull(t, h)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("вход без удостоверения без ручки: статус %d, ждали 401-вызов; тело %q",
			rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 без вызова на аутентификацию — докер-клиенту некуда идти за входом")
	}
}

// TestAnonymousRegistryToken_PaceFromSettingsRefusesBeyondTheLimit — темп
// анонимной выдачи, объявленный НАСТРОЙКОЙ службы, доезжает до собранной полосы
// (kaname#928): источник сверх темпа получает 429 со сроком ожидания, другой
// источник в пределах темпа — токен.
func TestAnonymousRegistryToken_PaceFromSettingsRefusesBeyondTheLimit(t *testing.T) {
	h := anonymousLaneFromSettings(t, anonLanePrincipal, "2", nil)
	for i := range 2 {
		if rec := anonymousPullFrom(t, h, "192.0.2.10:1234"); rec.Code != http.StatusOK {
			t.Fatalf("вход %d источника в пределах темпа: статус %d, тело %q", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := anonymousPullFrom(t, h, "192.0.2.10:1234")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("третий вход источника при темпе 2 в секунду из настройки: статус %d, ждали 429; тело %q",
			rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("отказ по темпу без срока ожидания")
	}
	if twin := anonymousPullFrom(t, h, "192.0.2.20:1234"); twin.Code != http.StatusOK {
		t.Fatalf("другой источник в пределах темпа: статус %d, тело %q", twin.Code, twin.Body.String())
	}
}
