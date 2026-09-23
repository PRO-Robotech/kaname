// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_test.go — сборка токен-эндпоинта отказывает на вырожденной величине
// (приёмка F2, F2-22 сторона стража, F2-43 сторона стража, §9.4 предел времени).
//
// # Почему страж живёт здесь, а не только у настройки
//
// Настройка проверяет то, что назвал ОПЕРАТОР. Здесь проверяется то, что
// собрал КОМПОЗИЦИОННЫЙ КОРЕНЬ: потолок длительности утверждения и допуск
// расхождения часов приезжают не из профиля развёртывания, а из объявленного
// числа, и корень обязан их подать. Поданный ноль означает «любая длительность»
// и «часы не сверяем» — и обнаружилось бы это не на старте, а на первом
// принятом чужом утверждении, то есть никогда.
package clienttokenwire_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clienttokenwire"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// ── дублёры портов ──────────────────────────────────────────────────────────
//
// Дублёр не снисходительнее продукта: он не глотает то, на чём настоящий
// отвечает отказом, — он лишь запоминает, с каким сроком его позвали.

type recordingResolver struct {
	deadline time.Time
	had      bool
}

func (r *recordingResolver) ResolveAssertionClient(ctx context.Context, _ string) (domain.AssertionClient, error) {
	r.deadline, r.had = ctx.Deadline()
	return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
}

// recordingIssuers — перечень доверенных издателей. Как и реестр выше, он
// ничего не утверждает об исходе — лишь запоминает, с каким сроком его позвали.
type recordingIssuers struct {
	deadline time.Time
	had      bool
}

func (r *recordingIssuers) ResolveTrustedIssuer(ctx context.Context, _, _ string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	r.deadline, r.had = ctx.Deadline()
	return domain.TrustedIssuer{}, domain.AssertionClient{}, domain.ErrTrustedIssuerUnknown
}

type recordingReplay struct {
	called   bool
	deadline time.Time
	had      bool
}

func (r *recordingReplay) Redeem(ctx context.Context, _, _ string, _ time.Time) error {
	r.called = true
	r.deadline, r.had = ctx.Deadline()
	return nil
}

// recordingCutoffs — читатель отсечки отзыва-всех. Как и прочие дублёры, об
// исходе не утверждает ничего — лишь запоминает, с каким сроком его позвали.
type recordingCutoffs struct {
	called   bool
	deadline time.Time
	had      bool
}

func (r *recordingCutoffs) UserRevokedBefore(ctx context.Context, _ string) (time.Time, bool, error) {
	r.called = true
	r.deadline, r.had = ctx.Deadline()
	return time.Time{}, false, nil
}

type stubClaims struct{}

func (stubClaims) ClaimsForAssertionClient(context.Context, domain.AssertionClient, service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	return map[string]any{}, service.ResolvedPrincipal{}, nil
}

type stubSigner struct{}

func (stubSigner) Sign(context.Context, tokensigner.Request) (tokensigner.Token, error) {
	return tokensigner.Token{}, nil
}
func (stubSigner) Issuer() string { return "https://kaname.kacho.local" }

func full() clienttokenwire.BuildConfig {
	return clienttokenwire.BuildConfig{
		ExpectedAudience:         "https://kaname.kacho.local",
		AssertionLifetimeCeiling: tokenpolicy.MaxAssertionLifetime,
		FederatedLifetimeCeiling: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:                tokenpolicy.ClockSkew,
		Clock:                    time.Now,
		AllowedAudiences:         []string{"api.kacho.local"},
		DefaultAudience:          "api.kacho.local",
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		PeerTimeout:              3 * time.Second,
	}
}

func build(cfg clienttokenwire.BuildConfig) (*recordingResolver, *recordingReplay, error) {
	res, rep := &recordingResolver{}, &recordingReplay{}
	_, err := clienttokenwire.New(cfg, res, &recordingIssuers{}, rep, stubSigner{}, stubClaims{}, &recordingCutoffs{})
	return res, rep, err
}

// TestF2_22_CompositionRefusesADegenerateDeclaredNumber — каждая вырожденная
// величина отвергает сборку, полная — собирается.
func TestF2_22_CompositionRefusesADegenerateDeclaredNumber(t *testing.T) {
	// Положительный контроль ПЕРВЫМ: без него всё, что ниже, зелено на
	// сборке, не собирающейся ни при каком входе.
	_, _, err := build(full())
	require.NoError(t, err, "полная сборка обязана состояться")

	cases := []struct {
		name    string
		mutate  func(*clienttokenwire.BuildConfig)
		mustSay string
	}{
		{"ожидаемый адресат не задан", func(c *clienttokenwire.BuildConfig) { c.ExpectedAudience = " " }, "audience"},
		{"потолок длительности утверждения нулевой", func(c *clienttokenwire.BuildConfig) { c.AssertionLifetimeCeiling = 0 }, "lifetime"},
		{"потолок длительности утверждения отрицателен", func(c *clienttokenwire.BuildConfig) { c.AssertionLifetimeCeiling = -time.Second }, "lifetime"},
		{"федеративный потолок длительности нулевой", func(c *clienttokenwire.BuildConfig) { c.FederatedLifetimeCeiling = 0 }, "lifetime"},
		{"федеративный потолок длительности отрицателен", func(c *clienttokenwire.BuildConfig) { c.FederatedLifetimeCeiling = -time.Second }, "lifetime"},
		{"допуск часов отрицателен", func(c *clienttokenwire.BuildConfig) { c.ClockSkew = -time.Second }, "skew"},
		{"часы не поданы", func(c *clienttokenwire.BuildConfig) { c.Clock = nil }, "clock"},
		{"перечень адресатов пуст", func(c *clienttokenwire.BuildConfig) { c.AllowedAudiences = nil }, "audience"},
		{"срок токена нулевой", func(c *clienttokenwire.BuildConfig) { c.TokenTTL = 0 }, "lifetime"},
		{"потолок тела нулевой", func(c *clienttokenwire.BuildConfig) { c.BodyCeiling = 0 }, "body"},
		{"предел времени внешнего вызова не задан", func(c *clienttokenwire.BuildConfig) { c.PeerTimeout = 0 }, "timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full()
			tc.mutate(&cfg)
			_, _, err := build(cfg)
			require.Error(t, err, "вырожденная величина обязана отвергать сборку")
			require.Contains(t, err.Error(), tc.mustSay)
		})
	}
}

// TestCompositionRefusesAMissingPort — эндпоинт без порта не отказывает на
// первом запросе, он не собирается.
func TestCompositionRefusesAMissingPort(t *testing.T) {
	for name, call := range map[string]func() error{
		"без реестра": func() error {
			_, err := clienttokenwire.New(full(), nil, &recordingIssuers{}, &recordingReplay{}, stubSigner{}, stubClaims{}, &recordingCutoffs{})
			return err
		},
		"без перечня доверенных издателей": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, nil, &recordingReplay{}, stubSigner{}, stubClaims{}, &recordingCutoffs{})
			return err
		},
		"без однократности": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, nil, stubSigner{}, stubClaims{}, &recordingCutoffs{})
			return err
		},
		"без подписанта": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, &recordingReplay{}, nil, stubClaims{}, &recordingCutoffs{})
			return err
		},
		"без читателя отсечки отзыва-всех": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, &recordingReplay{}, stubSigner{}, stubClaims{}, nil)
			return err
		},
		"без источника состава": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, &recordingReplay{}, stubSigner{}, nil, &recordingCutoffs{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, call()) })
	}
}

// TestEveryExternalCallOfTheNewPathCarriesItsOwnDeadline — §9.4.
//
// Обязательство названо приёмкой отдельно и намеренно без своего сценария:
// ни одна проба контура не спрашивает, выставлен ли предел, — поэтому он
// проверяется здесь, на сборке, где предел и выставляется.
//
// Запрос идёт в обработчик, СОБРАННЫЙ [clienttokenwire.New], и срок смотрится у
// дублёров портов — там, куда вызов приходит на живом пути. Проба, зовущая
// обёртку напрямую, утверждала бы, что обёртка ставит срок, и молчала бы о том,
// ставит ли её сборка: снятая из сборки обёртка оставила бы её зелёной.
func TestEveryExternalCallOfTheNewPathCarriesItsOwnDeadline(t *testing.T) {
	cfg := full()
	key, pemKey := newClientKey(t)
	res := &keyedResolver{client: domain.AssertionClient{
		ID: deadlineClientID, Kind: domain.AssertionClientUser, OwnerID: deadlineOwnerID,
		PublicKeyPEM: pemKey, Algorithm: tokenpolicy.AlgES256, OwnerActive: true,
	}}
	rep := &recordingReplay{}
	cuts := &recordingCutoffs{}
	h, err := clienttokenwire.New(cfg, res, &recordingIssuers{}, rep, stubSigner{}, personClaims{}, cuts)
	require.NoError(t, err)

	// Контекст запроса — БЕЗ срока: будь предел у вызывающего, а не у сборки,
	// его здесь не было бы вовсе.
	req := assertionRequest(t, key, deadlineClientID, cfg.ExpectedAudience)
	_, had := req.Context().Deadline()
	require.False(t, had, "предпосылка: контекст запроса пробы не несёт срока")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Порт, до которого запрос не дошёл, — не «срок есть», а «не измерено».
	require.Truef(t, res.called, "запрос не дошёл до реестра (ответ %d %s) — предел не измерен", rec.Code, rec.Body.String())
	require.Truef(t, rep.called, "запрос не дошёл до однократности (ответ %d %s) — предел не измерен", rec.Code, rec.Body.String())
	require.Truef(t, cuts.called,
		"запрос не дошёл до чтения отсечки отзыва-всех (ответ %d %s) — предел не измерен", rec.Code, rec.Body.String())

	require.True(t, res.had, "чтение реестра обязано нести СВОЙ предел времени")
	require.LessOrEqual(t, time.Until(res.deadline), cfg.PeerTimeout)

	require.True(t, rep.had, "допуск однократности обязан нести СВОЙ предел времени")
	require.LessOrEqual(t, time.Until(rep.deadline), cfg.PeerTimeout)

	// Чтение отсечки отзыва-всех лежит на пути ВЫДАЧИ и идёт в базу — тот же
	// довод, что у реестра: без своего предела неотвечающая база держит
	// обработчик, и отказ приходит не туда, где причина.
	require.True(t, cuts.had, "чтение отсечки отзыва-всех обязано нести СВОЙ предел времени")
	require.LessOrEqual(t, time.Until(cuts.deadline), cfg.PeerTimeout)
}

const (
	deadlineClientID = "uoc_01abcdefghjkmnpqx"
	deadlineOwnerID  = "usr_01abcdefghjkmnpqx"
)

// keyedResolver — строка реестра с настоящим открытым ключом: запрос обязан
// пройти проверку подписи, чтобы дойти до выдачи. Срок вызова запоминается.
type keyedResolver struct {
	client   domain.AssertionClient
	called   bool
	deadline time.Time
	had      bool
}

func (r *keyedResolver) ResolveAssertionClient(ctx context.Context, clientID string) (domain.AssertionClient, error) {
	r.called = true
	r.deadline, r.had = ctx.Deadline()
	if clientID != r.client.ID {
		return domain.AssertionClient{}, domain.ErrAssertionClientUnknown
	}
	return r.client, nil
}

// personClaims — состав, разрешающий принципала-ЧЕЛОВЕКА по ключу: только для
// него выдача читает отсечку отзыва-всех.
type personClaims struct{}

func (personClaims) ClaimsForAssertionClient(_ context.Context, c domain.AssertionClient, _ service.TokenHookContext) (
	map[string]any, service.ResolvedPrincipal, error,
) {
	issued := time.Now().Add(-time.Hour)
	return map[string]any{}, service.ResolvedPrincipal{
		Kind: service.PrincipalUser, UserID: c.OwnerID, StandingCredentialIssuedAt: &issued,
	}, nil
}

func newClientKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// assertionRequest — запрос выдачи по утверждению клиента, подписанному его
// ключом: издатель и субъект — наш идентификатор строки реестра.
func assertionRequest(t *testing.T, key *ecdsa.PrivateKey, clientID, audience string) *http.Request {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": clientID, "sub": clientID, "aud": audience,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": "jti-deadline",
	})
	tok.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	raw, err := tok.SignedString(key)
	require.NoError(t, err)
	form := url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {raw},
	}
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}
