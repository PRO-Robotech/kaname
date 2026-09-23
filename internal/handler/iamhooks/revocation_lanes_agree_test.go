// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_lanes_agree_test.go — отсечка отзыва-всех утверждается
// СРАВНЕНИЕМ полос выдачи, а не пробой каждой по отдельности (задача
// kaname#379).
//
// # Почему сравнением
//
// Токен по ключу человека выдают две полосы: этот хук на выпуске и наш
// собственный токен-эндпоинт. Проба каждой полосы по отдельности требует знать,
// каким свойство ДОЛЖНО быть, — и каждая полоса по отдельности выглядела бы
// исправной со своими зелёными пробами. Неверной была бы их РАЗНИЦА. Сравнение
// спрашивает другое: один принципал, одна отсечка — один вердикт на обеих.
//
// # Что здесь ОДНО на обе полосы
//
// Служба состава, её порты, строка ключа, отсечка и её читатель — один
// экземпляр на обе полосы. Два экземпляра сверяли бы два разных принципала и
// были бы зелены при любом расхождении полос.
//
// # Перепись печатает ОБЕ величины
//
// «Полос N · сверяют отсечку M». Одно число скрыло бы полосу, которую забыли
// завести в перечень.
package iamhooks_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Оба порта — одна форма: один и тот же читатель подаётся обеим полосам, и
// сборка это требует, а не предполагает.
var _ client_token.RevocationLookup = iamhooks.UserRevocationLookup(nil)
var _ iamhooks.UserRevocationLookup = client_token.RevocationLookup(nil)

const (
	laneUserMirror = "cap-machine"
	laneSAMirror   = "cap-machine-sa"
	laneOurUserKey = "uoc_01abcdefghjkmnpqx"
	laneOurSAKey   = "soc_01abcdefghjkmnpqx"
	laneSAID       = "sva_01abcdefghjkmnpqx"
)

// laneOwnClients — чтение строки реестра по НАШЕМУ идентификатору. Отдаёт ТЕ ЖЕ
// строки, что порты прежнего пути отдают по зеркальному значению.
type laneOwnClients struct {
	uoc domain.UserOAuthClient
	soc domain.ServiceAccountOAuthClient
}

func (l laneOwnClients) GetUserToken(_ context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	if id != l.uoc.ID {
		return domain.UserOAuthClient{}, errors.New("lane own clients: unknown user-token client")
	}
	return l.uoc, nil
}

func (l laneOwnClients) GetSAKey(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != l.soc.ID {
		return domain.ServiceAccountOAuthClient{}, errors.New("lane own clients: unknown sa-key client")
	}
	return l.soc, nil
}

// laneSigner — подписант нашей полосы. Предмет пробы — вердикт выдачи, а не
// подпись; подпись закреплена своими пробами подписанта.
type laneSigner struct{}

func (laneSigner) Sign(_ context.Context, req tokensigner.Request) (tokensigner.Token, error) {
	return tokensigner.Token{Token: "signed-for-" + req.Subject}, nil
}
func (laneSigner) Issuer() string { return "https://kaname.kacho.local" }

// revocationLane — полоса выдачи глазами этой пробы: выдала ли она токен по
// ключу названного вида.
type revocationLane struct {
	name  string
	issue func(t *testing.T, kind domain.AssertionClientKind) bool
}

// TestRevokeAllCutoff_BothIssuanceLanesAgree — один принципал, одна отсечка,
// один вердикт на полосе хука и на нашем эндпоинте.
func TestRevokeAllCutoff_BothIssuanceLanesAgree(t *testing.T) {
	keyIssued := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	unavailable := errors.New("user_token_revocations: backend unavailable")

	type input struct {
		name      string
		kind      domain.AssertionClientKind
		cutoff    *time.Time
		lookupErr error
		wantIssue bool
	}
	at := func(t time.Time) *time.Time { return &t }
	cases := []input{
		{"ключ человека, отсечки нет", domain.AssertionClientUser, nil, nil, true},
		{"ключ человека выдан до отсечки", domain.AssertionClientUser, at(keyIssued.Add(time.Hour)), nil, false},
		{"ключ человека выдан ровно в момент отсечки", domain.AssertionClientUser, at(keyIssued), nil, false},
		{"ключ человека выдан после отсечки", domain.AssertionClientUser, at(keyIssued.Add(-time.Hour)), nil, true},
		{"хранилище отсечек не ответило", domain.AssertionClientUser, nil, unavailable, false},
		{"ключ служебной учётки при отсечке человека", domain.AssertionClientServiceAccount,
			at(keyIssued.Add(365 * 24 * time.Hour)), nil, true},
	}

	users := cutoffUser()
	uoc := domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             laneOurUserKey,
		UserID:         cutoffUserID,
		OAuthClientID:  laneUserMirror,
		CreatedAt:      keyIssued,
	}
	soc := domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindKeypair,
		ID:             laneOurSAKey,
		SvaID:          laneSAID,
		OAuthClientID:  laneSAMirror,
	}
	sa := domain.ServiceAccount{ID: laneSAID, AccountID: cutoffAccountID, Enabled: true}

	// Один экземпляр службы состава на обе полосы.
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		users,
	).
		WithUserTokenPort(&fakeUserTokenPort{client: uoc, user: users.users[0]}).
		WithSAPort(&fakeIssuanceSAPort{clientID: laneSAMirror, mapping: soc, sa: sa}).
		WithOwnClientPort(laneOwnClients{uoc: uoc, soc: soc})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Одна отсечка, один читатель — обеим полосам.
			revs := newFakeRevocations()
			revs.userBeforeErr = c.lookupErr
			if c.cutoff != nil {
				revs.MarkUserRevokedBefore(cutoffUserID, *c.cutoff)
			}

			lanes := []revocationLane{
				{name: "хук выпуска", issue: func(t *testing.T, kind domain.AssertionClientKind) bool {
					t.Helper()
					mirror := laneUserMirror
					if kind == domain.AssertionClientServiceAccount {
						mirror = laneSAMirror
					}
					body := capturedBody(t, "provider-token-hook-client-credentials.json")
					machineShaped(t, body, mirror)
					h := iamhooks.NewTokenHookHandler(
						iamhooks.TokenHookConfig{
							HookSharedSecret: issuanceHookSecret,
							Domain:           "api.test.cloud",
							HydraIssuer:      "https://hydra.test.cloud",
						},
						enricher, revs, &fakeAudit{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
					)
					w := postCaptured(t, h, "/iam/v1/hooks/token", body)
					_, minted := mintedClaims(t, w)
					issued := w.Code == http.StatusOK && minted
					require.Truef(t, issued || w.Code == http.StatusForbidden,
						"хук ответил не выдачей и не отказом: %d %s", w.Code, w.Body.String())
					return issued
				}},
				{name: "наш токен-эндпоинт", issue: func(t *testing.T, kind domain.AssertionClientKind) bool {
					t.Helper()
					uc, err := client_token.New(client_token.Config{
						AllowedAudiences: []string{"https://api.test.cloud"},
						DefaultAudience:  "https://api.test.cloud",
						TokenTTL:         15 * time.Minute,
						Clock:            func() time.Time { return keyIssued.Add(48 * time.Hour) },
					}, laneSigner{}, enricher, revs)
					require.NoError(t, err)
					cl := domain.AssertionClient{ID: laneOurUserKey, Kind: kind, OwnerID: cutoffUserID, OwnerActive: true}
					if kind == domain.AssertionClientServiceAccount {
						cl.ID, cl.OwnerID = laneOurSAKey, laneSAID
					}
					out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: cl})
					if err != nil {
						return false
					}
					require.Equal(t, clientassertion.OutcomeAccepted, outcome)
					require.NotEmpty(t, out.AccessToken)
					return true
				}},
			}

			verdicts := make(map[string]bool, len(lanes))
			for _, l := range lanes {
				verdicts[l.name] = l.issue(t, c.kind)
				require.Equalf(t, c.wantIssue, verdicts[l.name], "полоса %q: выдача=%v", l.name, verdicts[l.name])
			}
			first := verdicts[lanes[0].name]
			for _, l := range lanes[1:] {
				require.Equalf(t, first, verdicts[l.name],
					"полосы разошлись на входе %q: %q сказала %v, %q сказала %v — расхождение полос "+
						"одного механизма обязано быть решением, а не побочным эффектом",
					c.name, lanes[0].name, first, l.name, verdicts[l.name])
			}
		})
	}
	t.Logf("перепись: полос выдачи по ключу человека 2 · сверяют отсечку 2 · входов сличено %d", len(cases))
}
