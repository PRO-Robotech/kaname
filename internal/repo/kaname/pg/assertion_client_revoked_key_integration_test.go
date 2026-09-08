// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assertion_client_revoked_key_integration_test.go — F2-31: клиент, чей
// зарегистрированный ключ ОТОЗВАН, токена не получает.
//
// # Чем в этой схеме выражен отзыв ключа
//
// Колонки отзыва у обеих таблиц реестра НЕТ: отзыв выражен СНЯТИЕМ СТРОКИ
// (`domain/client_assertion.go`). Поэтому проба ставит вопрос против настоящей
// базы, а не против подставного реестра: предмет — состояние схемы, и дублёр,
// у которого поля отзыва нет вовсе, отвечал бы правильно по причине, к схеме
// отношения не имеющей.
//
// # Что делает пробу способной упасть
//
// Положительный контроль снят В ТОЙ ЖЕ пробе и на ТОМ ЖЕ клиенте: до отзыва он
// токен получает. Без него проба зелена на разрешении, не находящем никого, и
// на выдаче, не выдающей ничего.
package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestF2_31_RevokedRegisteredKeyGetsNoToken — оба вида клиента отдельными
// входами: реестра два, и снятие строки в одном ничего не говорит о другом.
func TestF2_31_RevokedRegisteredKeyGetsNoToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	kinds := domain.AssertionClientKinds()
	require.Len(t, kinds, 2, "видов клиента ДВА; перечень выведен из закрытого словаря домена")

	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			f := newAssertionFixture(t)
			rig := newIssuanceRig(t)

			var clientID string
			switch kind {
			case domain.AssertionClientUser:
				clientID = "uoc_kkkkkkkkkkkkkkkkk"
				f.seedUserClient(t, clientID, "kacho-usr-revoked-key", testPublicKeyPEM, "ES256", nil)
			case domain.AssertionClientServiceAccount:
				clientID = "soc_kkkkkkkkkkkkkkkkk"
				f.seedSAClient(t, clientID, "kacho-sak-revoked-key", testPublicKeyPEM, "ES256")
			}

			// ── Положительный контроль: ДО отзыва тот же клиент токен получает.
			row, err := f.repo.ResolveAssertionClient(ctx, clientID)
			require.NoError(t, err, "до отзыва клиент обязан резолвиться")
			require.True(t, row.CanPresentAssertion(), "ключ зарегистрирован — клиент способен к утверждению")

			out, outcome, err := rig.uc.Issue(ctx, client_token.Input{Client: row})
			require.NoError(t, err, "до отзыва токен обязан выдаваться")
			require.Equal(t, clientassertion.OutcomeAccepted, outcome)
			require.NotEmpty(t, out.AccessToken, "выданный токен непуст")

			// ── Отзыв зарегистрированного ключа: строка снимается.
			revokeRegisteredKey(t, f, kind, clientID)

			// ── Токен НЕ выдаётся: клиент не резолвится, и отказ наступает тем
			// же признаком, что для несуществующего, — различимость исходов
			// была бы оракулом существования.
			_, err = f.repo.ResolveAssertionClient(ctx, clientID)
			require.True(t, domain.IsAssertionClientUnknown(err),
				"после отзыва ключа клиент обязан не резолвиться, получено: %v", err)

			// Выдача до этого места не доходит by construction: строки, которую
			// можно было бы подать на вход, больше нет. Утверждается это
			// отсутствием второй половины, а не вызовом выдачи с выдуманной
			// строкой: подать сюда пустого клиента значило бы измерить
			// поведение выдачи на входе, которого продукт не производит.
			_, err = f.repo.ResolveAssertionClient(ctx, clientID)
			require.Error(t, err)
		})
	}
}

// revokeRegisteredKey отзывает зарегистрированный ключ ТЕМ ЖЕ способом, каким
// это делает продукт: снятием строки реестра.
func revokeRegisteredKey(t *testing.T, f assertionFixture, kind domain.AssertionClientKind, clientID string) {
	t.Helper()
	var table string
	switch kind {
	case domain.AssertionClientUser:
		table = "kaname.user_oauth_clients"
	case domain.AssertionClientServiceAccount:
		table = "kaname.service_account_oauth_clients"
	default:
		t.Fatalf("вид клиента вне закрытого словаря: %q", kind)
	}
	tag, err := f.pool.Exec(context.Background(), "DELETE FROM "+table+" WHERE id = $1", clientID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(),
		"отзыв обязан снять РОВНО одну строку: ноль означал бы, что проба отзывает не то")
}
