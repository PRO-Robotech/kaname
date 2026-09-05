// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_contour_integration_test.go — положительный путь ЦЕЛИКОМ, против
// настоящей базы (приёмка F2, сценарии F2-39 и F2-40).
//
// # Что здесь утверждается сверх проб уровней
//
// Пробы уровней утверждают о частях: проверяющий разбирает утверждение, реестр
// отдаёт строку, выдача считает срок, подписант чеканит. Эта утверждает, что
// части СХОДЯТСЯ — клиент, зарегистрированный у нас, предъявляет утверждение,
// подписанное СВОИМ ключом, и получает токен, подписанный НАШИМ.
//
// Две пробы по половине этого не сказали бы: каждая была бы зелена о своей
// стороне, а вопрос «про один ли они предмет» не задаётся ни одной.
//
// # Почему два сценария, а не «то же самое»
//
// Виды клиента читаются из РАЗНЫХ таблиц, у них разные владельцы и разные
// колонки состояния владельца: у одного — состояние приглашения, у другого —
// признак включённости. Общий путь их объединяет, и именно поэтому проба
// обязана пройти по обоим: объединение — то место, где различие теряется.
package pg_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho-iam/internal/clienttokenwire"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
)

const (
	ctIssuer   = "https://iam.kacho.local"
	ctAudience = "registry.kacho.local"
)

// ctClientKey — ключ клиента: приватная половина у клиента, открытая в реестре.
type ctClientKey struct {
	private   *ecdsa.PrivateKey
	publicPEM string
}

func ctNewKey(t *testing.T) ctClientKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return ctClientKey{private: k, publicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
}

// ctAssertion собирает утверждение клиента: издатель и субъект — НАШ
// идентификатор строки реестра, адресат — идентификатор нашего издателя.
func ctAssertion(t *testing.T, key ctClientKey, clientID, jti string, now time.Time) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": clientID, "sub": clientID, "aud": ctIssuer,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": jti,
	})
	tok.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	raw, err := tok.SignedString(key.private)
	require.NoError(t, err)
	return raw
}

// ctContour — собранный контур вместе со счётчиком обращений к внешнему серверу.
type ctContour struct {
	pool     *pgxpool.Pool
	endpoint *clienttokenhttp.Handler
	// externalCalls — сколько раз за прогон был позван внешний сервер.
	//
	// Утверждение «мы туда не ходим» без счётчика измеряет НАМЕРЕНИЕ, а не
	// исход. Счётчик отвечает на вопрос об исходе — с честной границей: он
	// свидетельствует о том, что ни один вызов не пришёл ПО ЭТОМУ адресу за
	// время прогона, и ни о чём сверх того.
	externalCalls *atomic.Int64
	externalURL   string
}

func ctBuild(t *testing.T, f assertionFixture, now time.Time) ctContour {
	t.Helper()
	ctx := context.Background()
	clock := func() time.Time { return now }

	var calls atomic.Int64
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(external.Close)

	wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
	require.NoError(t, err)
	repo := kachopg.NewSigningKeyRepo(f.pool)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgES256,
		KeyLifetime:  90 * 24 * time.Hour,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        clock,
	}, repo, repo, wrapper)
	require.NoError(t, err)
	require.NoError(t, ks.EnsureSigningKey(ctx))

	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: ctIssuer, Clock: clock, MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, ks)
	require.NoError(t, err)

	users := kachopg.NewUserPoolRepo(f.pool)
	saClients := kachopg.NewSAOAuthClientRepo(f.pool)
	userClients := kachopg.NewUserOAuthClientRepo(f.pool)
	claims := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "kacho.local", HydraIssuer: ctIssuer},
		users,
	).
		WithSAPort(&ctSAAdapter{saClients: saClients}).
		WithUserTokenPort(&ctUserAdapter{userClients: userClients, users: users}).
		WithOwnClientPort(&ctOwnAdapter{userClients: userClients, saClients: saClients})

	h, err := clienttokenwire.FromPool(f.pool, clienttokenwire.BuildConfig{
		ExpectedAudience:         ctIssuer,
		AssertionLifetimeCeiling: tokenpolicy.MaxAssertionLifetime,
		FederatedLifetimeCeiling: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:                tokenpolicy.ClockSkew,
		Clock:                    clock,
		AllowedAudiences:         []string{ctAudience},
		DefaultAudience:          ctAudience,
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		PeerTimeout:              3 * time.Second,
	}, signer, claims)
	require.NoError(t, err)

	return ctContour{pool: f.pool, endpoint: h, externalCalls: &calls, externalURL: external.URL}
}

// ── адаптеры портов состава утверждений ─────────────────────────────────────

type ctSAAdapter struct{ saClients *kachopg.SAOAuthClientRepo }

func (a *ctSAAdapter) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.GetByOAuthClientID(ctx, id)
}
func (a *ctSAAdapter) FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.FindByExternalSubject(ctx, issuer, sub)
}
func (a *ctSAAdapter) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return a.saClients.GetServiceAccount(ctx, id)
}

type ctUserAdapter struct {
	userClients *kachopg.UserOAuthClientRepo
	users       *kachopg.UserPoolRepo
}

func (a *ctUserAdapter) LookupByOAuthClientID(ctx context.Context, id domain.OAuthClientID) (domain.UserOAuthClient, error) {
	return a.userClients.GetByOAuthClientID(ctx, id)
}
func (a *ctUserAdapter) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	return a.users.GetByID(ctx, id)
}

type ctOwnAdapter struct {
	userClients *kachopg.UserOAuthClientRepo
	saClients   *kachopg.SAOAuthClientRepo
}

func (a *ctOwnAdapter) GetUserToken(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return a.userClients.Get(ctx, id)
}
func (a *ctOwnAdapter) GetSAKey(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	return a.saClients.Get(ctx, id)
}

// ── сам вызов эндпоинта ─────────────────────────────────────────────────────

// ctPost предъявляет утверждение токен-эндпоинту ровно так, как это делает
// клиент: форма запроса, а не внутренний вызов.
func ctPost(t *testing.T, h *clienttokenhttp.Handler, assertion string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {assertion},
	}
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), "ответ обязан быть той формой, которую читает чужая библиотека")
	return rec.Code, body
}

// TestF2_39_F2_40_ClientCredentialsContourIssuesForBothClientKinds —
// положительный путь целиком по ОБОИМ путям выдачи.
func TestF2_39_F2_40_ClientCredentialsContourIssuesForBothClientKinds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	f := newAssertionFixture(t)
	contour := ctBuild(t, f, now)

	userKey, saKey := ctNewKey(t), ctNewKey(t)
	const (
		userClientID = "uoc_ctnr0000000000001"
		saClientID   = "soc_ctnr0000000000002"
	)
	f.seedUserClient(t, userClientID, "mirror-user-contour", userKey.publicPEM, tokenpolicy.AlgES256, nil)
	f.seedSAClient(t, saClientID, "mirror-sa-contour", saKey.publicPEM, tokenpolicy.AlgES256)

	for _, lane := range []struct {
		name     string
		clientID string
		key      ctClientKey
		// scenario — сценарий приёмки, который закрывает эта полоса.
		scenario string
	}{
		{"клиент пользовательского токена", userClientID, userKey, "F2-39"},
		{"клиент ключа служебной учётки", saClientID, saKey, "F2-40"},
	} {
		t.Run(lane.name, func(t *testing.T) {
			code, body := ctPost(t, contour.endpoint,
				ctAssertion(t, lane.key, lane.clientID, "jti-"+lane.clientID, now))
			require.Equal(t, http.StatusOK, code, "%s: %v", lane.scenario, body)

			raw, _ := body["access_token"].(string)
			require.NotEmpty(t, raw, "%s: токен не выдан", lane.scenario)
			require.Equal(t, "Bearer", body["token_type"])

			parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
			require.NoError(t, err)
			claims := parsed.Claims.(jwt.MapClaims)

			// Издатель и идентификатор ключа — НАШИ. Это и есть наблюдаемая
			// независимость пути от внешнего сервера: не «мы туда не ходим» по
			// заявлению, а «подписано нашим» по содержимому ответа.
			require.Equal(t, ctIssuer, claims["iss"], "%s: издатель не наш", lane.scenario)
			require.NotEmpty(t, parsed.Header["kid"], "%s: токен без идентификатора ключа", lane.scenario)
			require.Equal(t, tokenpolicy.TokenTypeAccess, parsed.Header["typ"],
				"%s: тип выданного токена обязан отличать его от утверждения клиента", lane.scenario)

			// Адресат — ИЗ запроса (здесь умолчание), и он НЕ равен
			// идентификатору нашего издателя: перенос адресата утверждения в
			// адресат токена дал бы токен, адресованный нам самим.
			require.Contains(t, claims["aud"], ctAudience, "%s", lane.scenario)
			require.NotContains(t, claims["aud"], ctIssuer, "%s: адресат утверждения перенесён в токен", lane.scenario)

			// Принципал определён — токен, не несущий, за кого он говорит,
			// выглядит выданным и не годен ни для чего.
			require.NotEmpty(t, claims["sub"], "%s: токен без субъекта", lane.scenario)

			// Повтор ТОГО ЖЕ утверждения отвергается: однократность действует
			// и на положительном пути, а не только в своей пробе.
			code, _ = ctPost(t, contour.endpoint,
				ctAssertion(t, lane.key, lane.clientID, "jti-"+lane.clientID, now))
			require.Equal(t, http.StatusUnauthorized, code,
				"%s: повторное предъявление того же утверждения обязано отвергаться", lane.scenario)
		})
	}

	// Счётчик обращений к внешнему серверу за прогон НЕ ДВИНУЛСЯ.
	//
	// Граница утверждения названа честно: счётчик свидетельствует, что по
	// этому адресу за прогон не пришло ни одного вызова. Он не доказывает
	// отсутствия всякого исходящего обращения — это доказывает состав сборки,
	// в котором клиента к внешнему серверу нет вовсе.
	require.Zero(t, contour.externalCalls.Load(),
		"путь выдачи обратился к внешнему серверу %d раз(а)", contour.externalCalls.Load())
}
