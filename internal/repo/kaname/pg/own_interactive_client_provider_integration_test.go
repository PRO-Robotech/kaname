// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// own_interactive_client_provider_integration_test.go — ИСПОЛНИТЕЛЬ заведения и
// снятия интерактивного клиента на собственной посадке, судимый ПО БАЗЕ
// (задача PRO-Robotech/kaname#313).
//
// Композиционный корень судится отдельно — он выбирает исполнителя по посадке
// (`cmd/kaname/own_interactive_client_wiring_test.go`). Здесь судится то, чего
// выбор не доказывает: что снятие действительно снимает и что повтор снятия
// не превращается в отказ.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// ownClientVerifier — проверочное значение, вычеканенное ТЕМ ЖЕ производителем,
// каким пишутся пароли. Переписанной строки здесь нет намеренно: переписанная
// разошлась бы с производителем молча, и проба судила бы свою копию формы.
func ownClientVerifier(t *testing.T) domain.LoginVerifier {
	t.Helper()
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatArgon2id))
	require.True(t, ok, "формат argon2id обязан стоять в перечне")
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: record.Floor,
	})
	require.NoError(t, err, "хешер объявленного формата")
	v, err := hasher.Hash("s3cret-of-the-interactive-client")
	require.NoError(t, err)
	return v
}

// TestIntegration_OwnInteractiveClientDeregistrationLeavesNoSecretBehind —
// снятие уносит проверочное значение секрета клиента.
func TestIntegration_OwnInteractiveClientDeregistrationLeavesNoSecretBehind(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)
	provider := kanamepg.NewOwnInteractiveClientProvider(ceremony)

	// Заведение чеканит имя клиента; строку реестра кладёт вызывающий — здесь
	// его роль исполняет посев, тем же оператором, что и адаптер ресурса.
	pc, err := provider.Register(ctx, interactiveclient.ProviderClientSpec{
		Name:                   "console",
		RedirectURIs:           []string{"https://console.example.test/cb"},
		PostLogoutRedirectURIs: []string{"https://console.example.test/"},
		Audiences:              []string{"https://api.example.test"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
	})
	require.NoError(t, err, "заведение")
	require.NotEmpty(t, pc.ClientID, "имя клиента не отчеканено")
	require.Equal(t, "none", pc.TokenEndpointAuthMethod,
		"клиент интерактивного входа обязан быть ПУБЛИЧНЫМ: владение доказывает "+
			"PKCE, и секрета у него нет — та же форма, что у прежней дороги")

	// Строка объявлена способом СЕКРЕТОМ, а не способом производителя (`none`):
	// материал лежит только у клиента, который секрет предъявляет
	// (`interactive_clients_secret_verifier_method_ck`, kaname#317), и
	// положительный близнец иначе не положил бы материала вовсе.
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id, token_endpoint_auth_method)
		VALUES ($1, $2, ARRAY['https://console.example.test/cb'], $3, 'client_secret_basic')`,
		"ic-00000000000000001", "own-console", pc.ClientID)
	require.NoError(t, err, "посев строки реестра")

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: значение, положенное в реестр, читается.
	require.NoError(t, ceremony.SetClientSecretVerifier(ctx, pc.ClientID, ownClientVerifier(t)))

	_, hasSecret, err := ceremony.ClientSecretVerifier(ctx, pc.ClientID)
	require.NoError(t, err)
	require.True(t, hasSecret,
		"фикстура не положила материала — отрицание ниже зеленело бы на пустом месте")

	// ПРЕДМЕТ: снятие уносит материал.
	require.NoError(t, provider.Deregister(ctx, pc.ClientID), "снятие")

	_, hasSecret, err = ceremony.ClientSecretVerifier(ctx, pc.ClientID)
	require.NoError(t, err)
	require.False(t, hasSecret,
		"снятие клиента оставило за собой годное проверочное значение секрета")
}

// TestIntegration_OwnInteractiveClientDeregistrationIsIdempotent — снятие
// клиента, которого в реестре уже нет, — УСПЕХ.
//
// Не придирка: глагол `Delete` удаляет строку ПЕРВОЙ и зовёт снятие следом,
// поэтому «строки нет» — обычное состояние этого вызова, а не неполадка.
// Отказ здесь пометил бы операцию ошибкой на каждом снятии подряд.
func TestIntegration_OwnInteractiveClientDeregistrationIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)
	provider := kanamepg.NewOwnInteractiveClientProvider(ceremony)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ формы отказа: сам реестр об отсутствующем клиенте
	// отвечает ПРИЗНАКОМ, а не прозой. На этом признаке стоит идемпотентность.
	err = ceremony.ClearClientSecretVerifier(ctx, "oic-nosuchclient00000")
	require.Error(t, err)
	require.True(t, errors.Is(err, iamerr.ErrNotFound),
		"реестр отвечает об отсутствии клиента неразличимо машинно: %v", err)

	require.NoError(t, provider.Deregister(ctx, "oic-nosuchclient00000"),
		"снятие отсутствующего клиента обязано быть успехом: строку уносит "+
			"глагол ресурса, а вместе с ней схема уносит семейства выданного, "+
			"коды и обновляющие токены")
}
