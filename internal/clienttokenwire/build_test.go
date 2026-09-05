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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/clienttokenwire"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho-iam/internal/tokensigner"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
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
	deadline time.Time
	had      bool
}

func (r *recordingReplay) Redeem(ctx context.Context, _, _ string, _ time.Time) error {
	r.deadline, r.had = ctx.Deadline()
	return nil
}

type stubClaims struct{}

func (stubClaims) ClaimsForAssertionClient(context.Context, domain.AssertionClient, service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	return map[string]any{}, service.ResolvedPrincipal{}, nil
}

type stubSigner struct{}

func (stubSigner) Sign(context.Context, tokensigner.Request) (tokensigner.Token, error) {
	return tokensigner.Token{}, nil
}
func (stubSigner) Issuer() string { return "https://iam.kacho.local" }

func full() clienttokenwire.BuildConfig {
	return clienttokenwire.BuildConfig{
		ExpectedAudience:         "https://iam.kacho.local",
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
	_, err := clienttokenwire.New(cfg, res, &recordingIssuers{}, rep, stubSigner{}, stubClaims{})
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
			_, err := clienttokenwire.New(full(), nil, &recordingIssuers{}, &recordingReplay{}, stubSigner{}, stubClaims{})
			return err
		},
		"без перечня доверенных издателей": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, nil, &recordingReplay{}, stubSigner{}, stubClaims{})
			return err
		},
		"без однократности": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, nil, stubSigner{}, stubClaims{})
			return err
		},
		"без подписанта": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, &recordingReplay{}, nil, stubClaims{})
			return err
		},
		"без источника состава": func() error {
			_, err := clienttokenwire.New(full(), &recordingResolver{}, &recordingIssuers{}, &recordingReplay{}, stubSigner{}, nil)
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
func TestEveryExternalCallOfTheNewPathCarriesItsOwnDeadline(t *testing.T) {
	cfg := full()
	res, rep, err := build(cfg)
	require.NoError(t, err)

	// Контекст БЕЗ срока: если бы предел приезжал от вызывающего, здесь его
	// не было бы вовсе, и проба это увидит.
	ctx := context.Background()

	_, _ = res, rep
	require.NoError(t, resolveThrough(ctx, cfg, res))
	require.True(t, res.had, "чтение реестра обязано нести СВОЙ предел времени")
	require.LessOrEqual(t, time.Until(res.deadline), cfg.PeerTimeout)

	require.NoError(t, redeemThrough(ctx, cfg, rep))
	require.True(t, rep.had, "допуск однократности обязан нести СВОЙ предел времени")
	require.LessOrEqual(t, time.Until(rep.deadline), cfg.PeerTimeout)
}

// resolveThrough / redeemThrough зовут порт ЧЕРЕЗ обёртку, которую ставит
// сборка, а не напрямую: предмет пробы — обёртка, и вызов в обход неё измерял
// бы дублёра.
func resolveThrough(ctx context.Context, cfg clienttokenwire.BuildConfig, res clientassertion.ClientResolver) error {
	_, err := clienttokenwire.WithDeadlineResolver(res, cfg.PeerTimeout).ResolveAssertionClient(ctx, "uoc_x")
	if domain.IsAssertionClientUnknown(err) {
		return nil
	}
	return err
}

func redeemThrough(ctx context.Context, cfg clienttokenwire.BuildConfig, rep clientassertion.ReplayGuard) error {
	return clienttokenwire.WithDeadlineReplay(rep, cfg.PeerTimeout).Redeem(ctx, "uoc_x", "jti", time.Now().Add(time.Minute))
}

var _ = client_token.Input{}
