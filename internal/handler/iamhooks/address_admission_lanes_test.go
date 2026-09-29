// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_admission_lanes_test.go — EV-65 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р5): владелец-
// человек с неподтверждённым адресом не получает токена ни на одной из полос
// выдачи, предъявляющих его полномочие, — ни на нашем токен-эндпоинте, ни на
// хуке выпуска, ни на хуке обновления. Одно правило, три двери, один вердикт.
//
// Читатель отметки — один на все полосы входа (тот же двойник, что читатель
// отсечки): у полос нет своего чтения отметки (§8 инв. 4, 5).
package iamhooks_test

import (
	"context"
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
)

// TestEV65_UnverifiedOwnerGetsNoTokenOnAnyIssuanceLane — EV-65.
func TestEV65_UnverifiedOwnerGetsNoTokenOnAnyIssuanceLane(t *testing.T) {
	keyIssued := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	sessionAt := capturedAuthTime(t, capturedBody(t, "provider-token-hook-authorization-code.json"))
	users := cutoffUser()
	uoc := domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindKeypair, ID: laneOurUserKey, UserID: cutoffUserID,
		CreatedAt: keyIssued,
	}
	soc := domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindKeypair, ID: laneOurSAKey, SvaID: laneSAID,
	}
	sa := domain.ServiceAccount{ID: laneSAID, AccountID: cutoffAccountID, Enabled: true}
	enricher := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud"}, users,
	).
		WithUserTokenPort(&fakeUserTokenPort{user: users.users[0]}).
		WithSAPort(&fakeIssuanceSAPort{clientID: laneOurSAKey, mapping: soc, sa: sa}).
		WithOwnClientPort(laneOwnClients{uoc: uoc, soc: soc})
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, verified := range []bool{false, true} {
		revs := newFakeRevocations()
		revs.setVerified(cutoffUserID, verified)

		// Токен-эндпоинт: ключ человека.
		uc, err := client_token.New(client_token.Config{
			AllowedAudiences: []string{"https://api.test.cloud"}, DefaultAudience: "https://api.test.cloud",
			TokenTTL: 15 * time.Minute, Clock: func() time.Time { return keyIssued.Add(48 * time.Hour) },
		}, laneSigner{}, enricher, revs)
		require.NoError(t, err)
		out, outcome, err := uc.Issue(context.Background(), client_token.Input{Client: domain.AssertionClient{
			ID: laneOurUserKey, Kind: domain.AssertionClientUser, OwnerID: cutoffUserID, OwnerActive: true,
		}})
		if verified {
			require.NoError(t, err, "EV-65 (б): токен-эндпоинт выдаёт")
			require.NotEmpty(t, out.AccessToken)
		} else {
			require.Error(t, err, "EV-65 (а): токен-эндпоинт токена не выдаёт")
			require.Equal(t, clientassertion.Outcome("owner-unverified"), outcome, "EV-65 (а): своя клетка словаря исходов полосы")
			require.Empty(t, out.AccessToken)
		}
		// Контроль вида владельца: ключ служебной учётки при неподтверждённом
		// человеке выдаётся (Р4 — машинный принципал).
		_, saOutcome, err := uc.Issue(context.Background(), client_token.Input{Client: domain.AssertionClient{
			ID: laneOurSAKey, Kind: domain.AssertionClientServiceAccount, OwnerID: laneSAID, OwnerActive: true,
		}})
		require.NoError(t, err, "EV-65: ключ служебной учётки отметкой человека не затронут")
		require.Equal(t, clientassertion.OutcomeAccepted, saOutcome)

		// Хук выпуска: сессия человека.
		audit := &fakeAudit{}
		hook := iamhooks.NewTokenHookHandler(iamhooks.TokenHookConfig{
			HookSharedSecret: issuanceHookSecret, Domain: "api.test.cloud",
		}, enricher, revs, audit, discard)
		body := capturedBody(t, "provider-token-hook-authorization-code.json")
		sessionClaims(t, body)["auth_time"] = sessionAt.Format(time.RFC3339)
		w := postCaptured(t, hook, "/iam/v1/hooks/token", body)
		_, minted := mintedClaims(t, w)
		if verified {
			require.Equal(t, http.StatusOK, w.Code, "EV-65 (б): хук выпуска выдаёт: %s", w.Body.String())
			require.True(t, minted)
		} else {
			require.Equal(t, http.StatusForbidden, w.Code, "EV-65 (а): хук выпуска — 403: %s", w.Body.String())
			require.JSONEq(t, `{"error":"invalid_grant"}`, w.Body.String(), "EV-65 (а): то же слово, что на отсечке владельца")
			require.Equal(t, "user_unverified", deniedReason(audit), "EV-65 (а): причина в аудите — своя")
		}

		// Хук обновления.
		rbody := capturedBody(t, "provider-refresh-hook.json")
		sessionClaims(t, rbody)["auth_time"] = sessionAt.Format(time.RFC3339)
		raudit := &fakeAudit{}
		rh := iamhooks.NewRefreshHookHandler(iamhooks.RefreshHookConfig{
			HookSharedSecret: "secret", Domain: "api.test.cloud",
		}, users, enricher, revs, raudit, discard)
		rw := postCapturedRefresh(t, rh, rbody)
		if verified {
			require.Equal(t, http.StatusOK, rw.Code, "EV-65 (б): хук обновления выдаёт: %s", rw.Body.String())
			continue
		}
		require.Equal(t, http.StatusForbidden, rw.Code, "EV-65 (а): хук обновления — 403: %s", rw.Body.String())
		require.Equal(t, "user_unverified", deniedReason(raudit), "EV-65 (а): причина обновления в аудите — своя")
	}
}

// deniedReason — причина отказа, записанная полосой в аудит.
func deniedReason(a *fakeAudit) string {
	for _, e := range a.Events() {
		if r, ok := e.Payload["reason"].(string); ok && r != "" {
			return r
		}
	}
	return ""
}
