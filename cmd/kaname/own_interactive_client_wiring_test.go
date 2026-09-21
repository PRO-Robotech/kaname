// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_interactive_client_wiring_test.go — У ЗАВЕДЕНИЯ И СНЯТИЯ ИНТЕРАКТИВНОГО
// КЛИЕНТА ПОД СОБСТВЕННОЙ ПОСАДКОЙ ЕСТЬ ИСПОЛНИТЕЛЬ (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// `InternalInteractiveClientService.Create` и `.Delete` исполняются портом
// `providerClients`. Композиционный корень наполнял этот порт ОДНИМ адаптером —
// к внешнему поставщику, — и делал это БЕЗУСЛОВНО. На посадке `own` внешнего
// поставщика не существует вовсе: строитель дороги отдаёт отставленного клиента
// без адреса, и всякий вызов порта получает терминальный отказ
// `ErrNoExternalIdentityProvider`. То есть оба глагола ресурса на собственной
// посадке не исполнялись НИ ПРИ КАКОМ входе.
//
// Здесь судится наблюдаемое: вызов порта под `own` не имеет права отказать
// за отсутствием чужого поставщика. ЧЕМ он будет исполнен — предмет
// композиционного корня, а не этой пробы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТРИЦАНИЕ СТОИТ В ПАРЕ С ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ
//
// Без близнеца «под own отказа нет» зеленело бы на корне, который не строит
// дорогу НИКОГДА, — то есть на сломанной посадке `external`, где чужой
// поставщик и есть исполнитель. Поэтому рядом стоит контроль: под `external`
// исполнителем остаётся прежняя дорога, и она построена.
package main

import (
	"context"
	"errors"
	"testing"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/clients"
)

// ownInteractiveSpec — то, что use-case просит у порта на заведении: имя,
// адреса возврата и РЕШЁННАЯ им форма выдачи. Значения взяты из того же
// выражения, которым корень зовёт порт, а не придуманы здесь.
func ownInteractiveSpec() interactiveclient.ProviderClientSpec {
	return interactiveclient.ProviderClientSpec{
		Name:                   "console",
		RedirectURIs:           []string{"https://console.kaname.test/callback"},
		PostLogoutRedirectURIs: []string{"https://console.kaname.test/"},
		Audiences:              []string{"https://kaname.test"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
	}
}

// TestCompositionRoot_InteractiveClientCreateHasAnExecutorUnderOwnPosture —
// ЗАВЕДЕНИЕ под `own` исполняется.
func TestCompositionRoot_InteractiveClientCreateHasAnExecutorUnderOwnPosture(t *testing.T) {
	ctx := context.Background()
	cfg := roadCfg(config.IdentityProviderOwn, "9097")

	// ТАК КОРЕНЬ СТРОИТ ПОРТ СЕГОДНЯ — выражение скопировано из `buildServices`,
	// а не сочинено здесь: проба обязана спрашивать о том, что процесс делает.
	prov := clients.NewInteractiveClientProvider(mustProviderAdminClient(cfg, nil))

	_, err := prov.Register(ctx, ownInteractiveSpec())
	if errors.Is(err, clients.ErrNoExternalIdentityProvider) {
		t.Fatalf("под собственной посадкой заведение интерактивного клиента "+
			"исполнять НЕЧЕМ — порт отказывает за отсутствием чужого поставщика: %v", err)
	}
}

// TestCompositionRoot_InteractiveClientDeleteHasAnExecutorUnderOwnPosture —
// СНЯТИЕ под `own` исполняется.
//
// Снятие идёт ПОСЛЕ удаления строки реестра, поэтому отсутствие клиента —
// ожидаемое состояние, а не отказ (та же идемпотентность, с какой прежняя
// дорога принимает 404 поставщика).
func TestCompositionRoot_InteractiveClientDeleteHasAnExecutorUnderOwnPosture(t *testing.T) {
	ctx := context.Background()
	cfg := roadCfg(config.IdentityProviderOwn, "9097")

	// ТО ЖЕ выражение корня, что и на заведении: порт у обоих глаголов один.
	prov := clients.NewInteractiveClientProvider(mustProviderAdminClient(cfg, nil))

	err := prov.Deregister(ctx, "oic-00000000000000000")
	if errors.Is(err, clients.ErrNoExternalIdentityProvider) {
		t.Fatalf("под собственной посадкой снятие интерактивного клиента "+
			"исполнять НЕЧЕМ — порт отказывает за отсутствием чужого поставщика: %v", err)
	}
}

// TestCompositionRoot_InteractiveClientKeepsTheForeignRoadUnderExternalPosture —
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под `external` исполнителем остаётся прежняя дорога.
//
// Без него отрицания выше зеленели бы на корне, который чужого поставщика не
// зовёт никогда, — то есть на сломанной прежней посадке.
func TestCompositionRoot_InteractiveClientKeepsTheForeignRoadUnderExternalPosture(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderExternal, "9097")

	road := mustProviderAdminClient(cfg, nil)
	if road == nil || road.BaseURL == "" {
		t.Fatal("под external дорога к чужому поставщику НЕ построена — отрицания " +
			"выше зеленели бы на корне, который его не зовёт никогда")
	}

	// Порт строится ТЕМ ЖЕ выражением и получает построенную дорогу. Вызова
	// здесь нет намеренно: он ушёл бы в сеть за адресом, которого на машине
	// прогона не существует, и проба судила бы разрешение имён, а не полосу.
	// Признак построенности взят у продукта (`roadIsBuilt` судит по адресу).
	if prov := clients.NewInteractiveClientProvider(road); prov == nil {
		t.Fatal("под external исполнителя нет вовсе")
	}
}
