// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_credential_revocation_test.go — отзыв удостоверения служебной учётки
// снимает токен, выданный ПО НЕМУ, сразу, а не по сроку (kaname#947).
//
// # Почему проба собрана из настоящих частей, а не из отчеканенного состава
//
// Правило отзыва (`tokenrevocation`) уже закреплено пробой авторитета на
// токене, чей состав фикстура чеканит САМА. Такая проба зелена и тогда, когда
// полоса выдачи перестала класть ключ отсечки в токен: фикстура кладёт его за
// неё. Разрыв живёт ровно посередине — между составом, который действительно
// выпускает полоса, и ключами, которые читает правило.
//
// Поэтому здесь токен выпускает НАСТОЯЩАЯ полоса выдачи с НАСТОЯЩИМ
// объявлением состава (`service.TokenEnrichmentService`) и настоящим
// подписантом, а судит его то правило, которое спрашивают обе принимающие
// поверхности: читатель предъявленного на публичном слушателе (API) и
// авторитет отзыва на внутреннем (его спрашивает прокси доступа перед
// реестром). Отсечку по снятой строке удостоверения пишет триггер схемы
// `sa_oauth_client_removal_cuts_minted_tokens` идентификатором строки; здесь
// она подаётся тем же ключом.
package client_token_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// errCredRowAbsent — строки с таким идентификатором в реестре нет.
var errCredRowAbsent = errors.New("row is absent")

// credOwnClients — строка реестра ключей, как её читает объявление состава.
type credOwnClients struct {
	row domain.ServiceAccountOAuthClient
}

func (c credOwnClients) GetUserToken(context.Context, domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return domain.UserOAuthClient{}, errCredRowAbsent
}

func (c credOwnClients) GetSAKey(_ context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if id != c.row.ID {
		return domain.ServiceAccountOAuthClient{}, errCredRowAbsent
	}
	return c.row, nil
}

// credServiceAccounts — владелец строки: действующая служебная учётка.
type credServiceAccounts struct{ sa domain.ServiceAccount }

func (c credServiceAccounts) GetServiceAccount(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if id != c.sa.ID {
		return domain.ServiceAccount{}, errCredRowAbsent
	}
	return c.sa, nil
}

// credCutoffs — хранилище отсечек правила: ключ отсечки → момент.
type credCutoffs struct{ before map[string]time.Time }

func (c credCutoffs) RevokedBefore(_ context.Context, key string) (time.Time, bool, error) {
	t, ok := c.before[key]
	return t, ok, nil
}

func (credCutoffs) FamilyRevoked(context.Context, string) (bool, error) { return false, nil }

func (credCutoffs) PersonMarks(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

// TestCredentialRevocationCutsTheTokenIssuedByItAndOnlyIt — выдан токен по
// удостоверению → удостоверение снято → правило, которое спрашивают API и
// прокси реестра, токен отвергает; снятие ДРУГОГО удостоверения той же учётки
// его не трогает.
func TestCredentialRevocationCutsTheTokenIssuedByItAndOnlyIt(t *testing.T) {
	const (
		svaID    = "sva_0123456789abcdefg"
		keyID    = "soc_0123456789abcdefg"
		otherKey = "soc_zzzzzzzzzzzzzzzzz"
	)
	enrich := service.NewTokenEnrichmentService(service.TokenEnrichmentConfig{Domain: audResource}).
		WithClock(func() time.Time { return now }).
		WithOwnClientPort(credOwnClients{row: domain.ServiceAccountOAuthClient{
			ID: domain.SAOAuthClientID(keyID), SvaID: domain.ServiceAccountID(svaID), CreatedAt: now.Add(-time.Hour),
		}}).
		WithSAPort(credServiceAccounts{sa: domain.ServiceAccount{
			ID: domain.ServiceAccountID(svaID), AccountID: "acc_0123456789abcdefg", Enabled: true,
		}})
	uc, err := client_token.New(client_token.Config{
		AllowedAudiences: []string{audResource, audRegistry},
		DefaultAudience:  audResource,
		TokenTTL:         15 * time.Minute,
		Clock:            momentclock.Func(func() time.Time { return now }),
	}, newSigner(t), enrich, &stubCutoffs{at: map[string]time.Time{}})
	require.NoError(t, err)

	out, _, err := uc.Issue(context.Background(), client_token.Input{
		Client:            client(ofKind(domain.AssertionClientServiceAccount)),
		RequestedAudience: []string{audRegistry},
	})
	require.NoError(t, err, "положительный путь выдачи обязан выпускать токен")
	claims, _ := parse(t, out.AccessToken)

	// Отсечка ПОЗЖЕ выпуска — так её пишет снятие строки в момент отзыва.
	revokedAt := now.Add(time.Second)

	// (1) Положительный контроль: отсечек нет — токен действует. Без него проба
	// зелена на правиле, отвергающем всё.
	revoked, err := tokenrevocation.Revoked(context.Background(), credCutoffs{before: map[string]time.Time{}}, claims)
	require.NoError(t, err)
	require.False(t, revoked, "токен без единой отсечки отвергнут — правило отвергает всё, проба ничего не меряет")

	// (2) Предмет: снято удостоверение, по которому токен выдан.
	revoked, err = tokenrevocation.Revoked(context.Background(),
		credCutoffs{before: map[string]time.Time{keyID: revokedAt}}, claims)
	require.NoError(t, err)
	require.True(t, revoked,
		"удостоверение %s снято, а выданный по нему токен действует до срока: состав токена не несёт ключа "+
			"отсечки, которым снятие строки его отзывает", keyID)

	// (3) Законный близнец: снято ДРУГОЕ удостоверение той же учётки.
	revoked, err = tokenrevocation.Revoked(context.Background(),
		credCutoffs{before: map[string]time.Time{otherKey: revokedAt}}, claims)
	require.NoError(t, err)
	require.False(t, revoked, "отзыв чужого удостоверения той же учётки снял токен — отзыв блокирует учётку целиком")
}
