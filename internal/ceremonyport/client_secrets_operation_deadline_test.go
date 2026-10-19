// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport_test

// client_secrets_operation_deadline_test.go — сверка секрета клиента ждёт
// места вычисления до срока ОПЕРАЦИИ, а не до срока одного вызова порта
// (kaname#892).
//
// Сквозь настоящий мост фундамента (`oauthceremony.New`): срок вызова порта P,
// срок операции O > P. Проверяющий подставлен: его место вычисления
// освобождается через заданное время, а вызов, кончившийся раньше,
// получает ошибку контекста — контракт `passwordverify` для ожидания места.
//
//   - ожидание дольше P, но короче O — вердикт, обмен выдаёт токены;
//   - ожидание дольше O — отказ `port_deadline` ровно в срок операции, а не
//     после него;
//   - близнец: ожидание короче P — вердикт;
//   - обмен мимо обёртки срока операции ждёт под сроком порта: отказ к сроку
//     P, ответа после срока нет и там.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	deadlinePort      = time.Second
	deadlineOperation = 4 * time.Second
)

// placeAfterChecker — проверяющий, место вычисления которого освобождается
// через wait: до того сверка ждёт, и вызов, кончившийся раньше, получает
// ошибку контекста без вердикта.
type placeAfterChecker struct{ wait time.Duration }

func (c *placeAfterChecker) VerifyPresented(ctx context.Context, _ domain.LoginVerifier, _ passwordverify.Presented) (passwordverify.Result, error) {
	place := time.NewTimer(c.wait)
	defer place.Stop()
	select {
	case <-place.C:
		return passwordverify.Result{Outcome: passwordverify.OutcomeMatched}, nil
	case <-ctx.Done():
		return passwordverify.Result{}, ctx.Err()
	}
}

func (*placeAfterChecker) Aligned() bool { return true }

func (*placeAfterChecker) Capacity() int { return 2 }

// deadlineRig — церемония фундамента на хранилищах пробы и порте сверки над
// проверяющим с очередью.
type deadlineRig struct {
	ceremony *oauthceremony.Ceremony
	checker  *placeAfterChecker
}

func newDeadlineRig(t *testing.T) *deadlineRig {
	t.Helper()
	ring := newKeyRing(t, testKID)
	families := newMemFamilies()
	tokens := newRecordingAccessTokens(t, ring, time.Now, families)
	grants, err := ceremonyport.NewGrants(families)
	require.NoError(t, err)
	vaults := newMemVaults(families)
	stored, err := floorHasher(t).Hash(flowSecret)
	require.NoError(t, err)
	vaults.secrets.verifiers[testClientID] = stored
	vaults.clients[testClientID] = oauthceremony.ClientRegistration{
		ClientID:      testClientID,
		RedirectURIs:  []string{flowRedirect},
		GrantKinds:    []oauthceremony.GrantKind{oauthceremony.GrantAuthorizationCode, oauthceremony.GrantRefreshToken},
		ResponseKinds: []string{"code"},
		Scopes:        []string{"openid", "offline"},
		Audiences:     []string{testAudience},
	}
	checker := &placeAfterChecker{}
	secrets, err := ceremonyport.NewClientSecrets(vaults.secrets, checker, &shareCounter{})
	require.NoError(t, err)

	ceremony, err := oauthceremony.New(oauthceremony.Config{
		AuthorizationEndpoint:     "https://iam.kacho.local/iam/v1/authorize",
		TokenEndpoint:             "https://iam.kacho.local/iam/v1/token",
		AccessTokenLifespan:       10 * time.Minute,
		RefreshTokenLifespan:      time.Hour,
		AuthorizationCodeLifespan: tokenpolicy.MaxAuthorizationCodeTTL,
		ScopeMatching:             oauthceremony.ScopeMatchingExact,
		RefreshTokenIssuance:      oauthceremony.RefreshTokenIssuanceOnScope,
		RefreshTokenScopes:        []string{"offline"},
		MinParameterEntropy:       8,
		PortTimeout:               deadlinePort,
		OperationTimeout:          deadlineOperation,
		NewGrantID:                ceremonyport.NewGrantID,
	}, oauthceremony.Ports{
		Clients:            vaults,
		AuthorizationCodes: vaults,
		AccessTokens:       vaults,
		RefreshTokens:      vaults,
		Grants:             grants,
		AccessTokenIssuer:  tokens,
		ClientSecrets:      secrets,
	})
	require.NoError(t, err, "церемония не собрана на адаптерах службы")
	return &deadlineRig{ceremony: ceremony, checker: checker}
}

// code — код авторизации клиента пробы.
func (r *deadlineRig) code(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(flowVerifier))
	intent, err := r.ceremony.Authorize(t.Context(), oauthceremony.AuthorizationRequest{
		ClientID:      testClientID,
		RedirectURI:   flowRedirect,
		ResponseKinds: []oauthceremony.ResponseKind{oauthceremony.ResponseKindCode},
		Scopes:        []string{"openid", "offline"},
		Audiences:     []string{testAudience},
		State:         flowState,
		Additional: map[string][]string{
			"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
			"code_challenge_method": {"S256"},
		},
	})
	require.NoError(t, err, "Authorize отказал")
	result, err := r.ceremony.CompleteAuthorization(t.Context(), intent, loginGrant())
	require.NoError(t, err, "CompleteAuthorization отказал")
	require.Len(t, result.Parameters["code"], 1, "НЕ ВЫПОЛНИЛОСЬ: кода нет")
	return result.Parameters["code"][0]
}

// exchange — обмен кода через ex с ожиданием места wait; время ответа.
func (r *deadlineRig) exchange(t *testing.T, ex ceremonyport.Exchanger, wait time.Duration) (oauthceremony.TokenResult, time.Duration, error) {
	t.Helper()
	code := r.code(t)
	r.checker.wait = wait
	start := time.Now()
	res, err := ex.Exchange(t.Context(), oauthceremony.TokenRequest{
		Grant: oauthceremony.GrantAuthorizationCode, ClientID: testClientID, ClientSecret: flowSecret,
		AuthMethod: oauthceremony.ClientAuthBasic, Code: code, RedirectURI: flowRedirect, CodeVerifier: flowVerifier,
	})
	return res, time.Since(start), err
}

func TestClientSecrets_WaitForAPlaceIsBoundedByTheOperationNotThePort(t *testing.T) {
	cases := []struct {
		name string
		wait time.Duration
		// verdict — сверка дала вердикт и обмен выдал токены; иначе —
		// отказ по сроку ровно в elapsed.
		verdict bool
		elapsed time.Duration
	}{
		{name: "близнец: ожидание короче срока порта", wait: deadlinePort / 2, verdict: true, elapsed: deadlinePort / 2},
		{name: "ожидание дольше срока порта, короче срока операции", wait: 2*deadlinePort + deadlinePort/2,
			verdict: true, elapsed: 2*deadlinePort + deadlinePort/2},
		{name: "ожидание дольше срока операции", wait: deadlineOperation + deadlinePort, elapsed: deadlineOperation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rig := newDeadlineRig(t)
				scope, err := ceremonyport.NewOperationScope(rig.ceremony, deadlineOperation)
				require.NoError(t, err)

				res, elapsed, err := rig.exchange(t, scope, tc.wait)
				if tc.verdict {
					require.NoError(t, err, "сверка, дождавшаяся места в сроке операции, не стала вердиктом")
					require.NotEmpty(t, res.AccessToken, "обмен не выдал токена доступа")
				} else {
					require.Error(t, err, "сверка, не дождавшаяся места в сроке операции, стала вердиктом")
					require.ErrorIs(t, err, oauthceremony.ErrPortDeadline, "отказ не по сроку: %v", err)
				}
				require.Equal(t, tc.elapsed, elapsed, "обмен ответил не в своё время")
			})
		})
	}
}

// Обмен мимо обёртки: срока операции порт не видит и ждёт под сроком
// вызова порта — отказ к нему, а не позже.
func TestClientSecrets_ExchangeOutsideTheScopeWaitsUnderThePortDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rig := newDeadlineRig(t)
		_, elapsed, err := rig.exchange(t, rig.ceremony, 2*deadlinePort)
		require.Error(t, err)
		require.ErrorIs(t, err, oauthceremony.ErrPortDeadline, "отказ не по сроку: %v", err)
		require.False(t, errors.Is(err, domain.ErrVerifierAtCapacity), "конец срока выдан за исчерпание: %v", err)
		require.Equal(t, deadlinePort, elapsed, "обмен ответил не к сроку порта")
	})
}

func TestNewOperationScope_RefusesAnIncompleteWiring(t *testing.T) {
	_, err := ceremonyport.NewOperationScope(nil, time.Second)
	require.Error(t, err, "обёртка без церемонии собрана")
	_, err = ceremonyport.NewOperationScope(&oauthceremony.Ceremony{}, 0)
	require.Error(t, err, "обёртка без срока операции собрана")
}
