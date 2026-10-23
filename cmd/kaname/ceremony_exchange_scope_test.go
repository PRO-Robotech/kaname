// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_exchange_scope_test.go — обмен, собранный корнем, ждёт места
// вычисления проверяющего до срока ОПЕРАЦИИ, а не до срока одного вызова порта
// (kaname#892).
//
// Проба обёртки (`internal/ceremonyport`) держит саму обёртку, но не то, что
// корень через неё ведёт обмен: обмен мимо обёртки оставлял её пробу
// зелёной, а пробы корня на одном процессоре ловили это лишь по случаю
// расписания. Здесь обмен идёт через ту сборку, что зовёт buildCeremonySurface
// (`ceremonyExchange`): настоящий мост фундамента, настоящий адаптер сверки
// секрета и вариант использования обмена, на управляемых часах (synctest).
//
// Срок вызова порта P, срок операции O > P. Проверяющий подставлен: его место
// вычисления освобождается через w, вердикт — «секрет неверен», и обмен
// отказывает `invalid_client`, не доходя до кода. Хранилища кода и токенов в
// путь не входят.
//
//   - близнец: w < P — вердикт к w;
//   - P < w < O — вердикт к w; обмен мимо обёртки отказывал бы по сроку к P;
//   - w > O — отказ `port_deadline` ровно к O.
package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	scopeProbePort      = time.Second
	scopeProbeOperation = 4 * time.Second
	scopeProbeClient    = "scope-probe-client"
	scopeProbeRedirect  = "https://app.kacho.local/callback"
)

// scopeProbeClients — справочник с одним конфиденциальным клиентом.
type scopeProbeClients struct{}

func (scopeProbeClients) LookupClient(_ context.Context, clientID string) (oauthceremony.ClientRegistration, error) {
	if clientID != scopeProbeClient {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	return oauthceremony.ClientRegistration{
		ClientID:      scopeProbeClient,
		RedirectURIs:  []string{scopeProbeRedirect},
		GrantKinds:    []oauthceremony.GrantKind{oauthceremony.GrantAuthorizationCode, oauthceremony.GrantRefreshToken},
		ResponseKinds: []string{"code"},
		Scopes:        []string{"openid", "offline"},
	}, nil
}

// scopeProbeMaterial — справочник проверочных значений: значения нет, и
// сверка вычисляется против выравнивающего (контракт адаптера).
type scopeProbeMaterial struct{}

func (scopeProbeMaterial) ClientSecretVerifier(context.Context, string) (domain.LoginVerifier, bool, error) {
	return domain.LoginVerifier{}, false, nil
}

// scopeProbeChecker — проверяющий, место вычисления которого освобождается
// через wait; вызов, кончившийся раньше, получает ошибку контекста без
// вердикта — контракт `passwordverify` для ожидания места.
type scopeProbeChecker struct{ wait time.Duration }

func (c *scopeProbeChecker) VerifyPresented(ctx context.Context, _ domain.LoginVerifier, _ passwordverify.Presented) (passwordverify.Result, error) {
	place := time.NewTimer(c.wait)
	defer place.Stop()
	select {
	case <-place.C:
		return passwordverify.Result{Outcome: passwordverify.OutcomeMismatched}, nil
	case <-ctx.Done():
		return passwordverify.Result{}, ctx.Err()
	}
}

func (*scopeProbeChecker) Aligned() bool { return true }

func (*scopeProbeChecker) Capacity() int { return 2 }

type scopeProbeShare struct{}

func (scopeProbeShare) CeremonyShareExhaustedObserved() {}

// scopeProbeUnits — единица запроса без транзакции: урегулирование мгновенно.
type scopeProbeUnits struct{}

func (scopeProbeUnits) OpenRequest(ctx context.Context) (context.Context, func(context.Context) error) {
	return ctx, func(context.Context) error { return nil }
}

// Порты вне пути пробы: вызов любого из них — паника на нулевом интерфейсе,
// то есть красное с координатой, а не молчаливый ответ дублёра.
type scopeProbeCodes struct {
	oauthceremony.AuthorizationCodeVault
}

type scopeProbeAccess struct{ oauthceremony.AccessTokenVault }

type scopeProbeRefresh struct {
	oauthceremony.RefreshTokenVault
}

type scopeProbeGrants struct{ oauthceremony.GrantRevoker }

type scopeProbeIssuer struct {
	oauthceremony.AccessTokenIssuer
}

func TestCeremonyExchange_SecretCheckWaitsForAPlaceUnderTheOperationDeadline(t *testing.T) {
	cases := []struct {
		name string
		wait time.Duration
		// verdict — сверка дала вердикт «секрет неверен», и обмен отказал
		// invalid_client; иначе — отказ по сроку. Ответ — ровно к elapsed.
		verdict bool
		elapsed time.Duration
	}{
		{name: "близнец: ожидание короче срока порта", wait: scopeProbePort / 2,
			verdict: true, elapsed: scopeProbePort / 2},
		{name: "ожидание дольше срока порта, короче срока операции", wait: 2*scopeProbePort + scopeProbePort/2,
			verdict: true, elapsed: 2*scopeProbePort + scopeProbePort/2},
		{name: "ожидание дольше срока операции", wait: scopeProbeOperation + scopeProbePort,
			elapsed: scopeProbeOperation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				checker := &scopeProbeChecker{wait: tc.wait}
				secrets, err := ceremonyport.NewClientSecrets(scopeProbeMaterial{}, checker, scopeProbeShare{})
				require.NoError(t, err)
				_, exchange, err := ceremonyExchange(oauthceremony.Config{
					AuthorizationEndpoint:     "https://iam.kacho.local/iam/v1/authorize",
					TokenEndpoint:             "https://iam.kacho.local/iam/v1/token",
					AccessTokenLifespan:       10 * time.Minute,
					RefreshTokenLifespan:      time.Hour,
					AuthorizationCodeLifespan: tokenpolicy.MaxAuthorizationCodeTTL,
					ScopeMatching:             oauthceremony.ScopeMatchingExact,
					RefreshTokenIssuance:      oauthceremony.RefreshTokenIssuanceAlways,
					MinParameterEntropy:       8,
					PortTimeout:               scopeProbePort,
					OperationTimeout:          scopeProbeOperation,
					NewGrantID:                ceremonyport.NewGrantID,
				}, oauthceremony.Ports{
					Clients:            scopeProbeClients{},
					AuthorizationCodes: scopeProbeCodes{},
					AccessTokens:       scopeProbeAccess{},
					RefreshTokens:      scopeProbeRefresh{},
					Grants:             scopeProbeGrants{},
					AccessTokenIssuer:  scopeProbeIssuer{},
					ClientSecrets:      secrets,
				}, scopeProbeUnits{}, scopeProbePort)
				require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: обмен корня не собран")

				start := time.Now()
				_, err = exchange.Execute(t.Context(), oauthceremony.TokenRequest{
					Grant: oauthceremony.GrantAuthorizationCode, ClientID: scopeProbeClient,
					ClientSecret: "scope-probe-secret", AuthMethod: oauthceremony.ClientAuthBasic,
					Code: "scope-probe-code", RedirectURI: scopeProbeRedirect,
					CodeVerifier: "scope-probe-verifier-0123456789-0123456789-0123456789",
				})
				elapsed := time.Since(start)

				require.Error(t, err, "обмен с неверным секретом выдал токены")
				if tc.verdict {
					require.ErrorIs(t, err, oauthceremony.ErrInvalidClient,
						"сверка, дождавшаяся места в сроке операции, не стала вердиктом: %v", err)
					require.False(t, errors.Is(err, oauthceremony.ErrPortDeadline),
						"вердикт сверки выдан за конец срока: %v", err)
				} else {
					require.ErrorIs(t, err, oauthceremony.ErrPortDeadline, "отказ не по сроку: %v", err)
				}
				require.Equal(t, tc.elapsed, elapsed, "обмен ответил не в своё время")
			})
		})
	}
}
