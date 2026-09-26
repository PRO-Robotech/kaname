// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// own_interactive_client_provider_test.go — СПОСОБ аутентификации клиента,
// которого заводит собственный реестр посадки без внешнего поставщика, судится
// решением Р3 одобренной приёмки LINE-A-1 (kacho-workspace,
// docs/specs/sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md,
// строка 3 таблицы решений; сценарии LINE-A-1-10 и LINE-A-1-12): интерактивный
// клиент КОНФИДЕНЦИАЛЬНЫЙ и аутентифицируется на обмене секретом (задача
// PRO-Robotech/kaname#405).
//
// Судится выход исполнителя заведения, а не строка базы: способ выбирает он, а
// схема только принимает любой способ своего закрытого словаря
// (`interactive_clients_auth_method_ck`, kaname#317). Поэтому проба не
// поднимает базы — хранилище заведению не нужно.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// confidentialAuthMethods — способы словаря схемы, у которых клиент предъявляет
// секрет. Способ `none` (публичный клиент) в перечень не входит, и это предмет
// пробы, а не умолчание.
var confidentialAuthMethods = []string{"client_secret_basic", "client_secret_post"}

// TestOwnInteractiveClientRegistrationDeclaresAConfidentialClient — собственный
// реестр заводит клиента, который аутентифицируется на обмене (Р3).
func TestOwnInteractiveClientRegistrationDeclaresAConfidentialClient(t *testing.T) {
	provider := kanamepg.NewOwnInteractiveClientProvider(nil)
	spec := interactiveclient.ProviderClientSpec{
		Name:                   "console",
		RedirectURIs:           []string{"https://console.example.test/cb"},
		PostLogoutRedirectURIs: []string{"https://console.example.test/"},
		Audiences:              []string{"https://api.example.test"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
	}

	pc, err := provider.Register(context.Background(), spec)
	require.NoError(t, err, "заведение на годном входе")

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же вызов, та же форма ответа — имя клиента
	// отчеканено своей приставкой, виды выдачи и получатели возвращены дословно.
	// Без него красное ниже читалось бы и как «заведение не состоялось вовсе».
	require.True(t, strings.HasPrefix(pc.ClientID, "oic-"),
		"имя клиента не отчеканено собственной приставкой: %q", pc.ClientID)
	require.Equal(t, spec.GrantTypes, pc.GrantTypes, "виды выдачи решает вызывающий")
	require.Equal(t, spec.Audiences, pc.Audiences, "получателей решает вызывающий")

	// ПРЕДМЕТ: способ — секретом. Отличие от близнеца ровно в одном факте.
	require.Contains(t, confidentialAuthMethods, pc.TokenEndpointAuthMethod,
		"собственный реестр завёл клиента со способом %q, а Р3 одобренной приёмки "+
			"LINE-A-1 требует конфиденциального клиента, аутентифицируемого на обмене",
		pc.TokenEndpointAuthMethod)
}
