// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_interactive_client_wiring_test.go — У ЗАВЕДЕНИЯ И СНЯТИЯ ИНТЕРАКТИВНОГО
// КЛИЕНТА ЕСТЬ ИСПОЛНИТЕЛЬ, И ЭТО НАШ РЕЕСТР (задачи kaname#313, #363).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// `InternalInteractiveClientService.Create` и `.Delete` исполняются портом
// `ProviderClients`. Прежде корень наполнял этот порт адаптером к внешнему
// поставщику безусловно, и на своей посадке оба глагола не исполнялись ни при
// каком входе (kaname#313); затем выбор стал развилкой посадки. Поставщика
// больше нет (kaname#363), и исполнитель один — наш реестр с хешером секрета.
//
// Здесь судится наблюдаемое: заведение отдаёт имя клиента и проверочное
// значение секрета объявленного класса, снятие доходит до нашего реестра.
//
// ─────────────────────────────────────────────────────────────────────────────
// БЛИЗНЕЦ — ДРУГОЙ ФАКТ, А НЕ ДРУГАЯ ПОСАДКА
//
// Прежний положительный контроль стоял на посадке внешнего поставщика: «там
// исполнителем остаётся чужая дорога». Той посадки нет, и близнец — отказ
// сборки исполнителя без объявленного класса хешера: он доказывает, что проба
// видит исполнителя, которого СОБРАЛ корень, а не любой объект порта.
package main

import (
	"context"
	"strings"
	"testing"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ownClientRegistryDouble — собственный реестр клиентов, отвечающий контрактом
// настоящего: снятие проверочного значения записывается и возвращает тот же
// исход. Поведение хранилища здесь не воспроизводится — его судит
// интеграционная проба слоя доступа; здесь судится ВЫБОР исполнителя корнем.
type ownClientRegistryDouble struct{ cleared []string }

func (d *ownClientRegistryDouble) ClearClientSecretVerifier(_ context.Context, clientID string) error {
	d.cleared = append(d.cleared, clientID)
	return nil
}

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

// TestCompositionRoot_InteractiveClientCreateHasAnExecutor — ЗАВЕДЕНИЕ
// исполняется.
func TestCompositionRoot_InteractiveClientCreateHasAnExecutor(t *testing.T) {
	ctx := context.Background()
	cfg := loginLaneCfg()

	prov := mustOwnExecutor(t, cfg, &ownClientRegistryDouble{})
	if _, ok := prov.(*kanamepg.OwnInteractiveClientProvider); !ok {
		t.Fatalf("исполнителем заведения корень собрал %T, а не наш реестр", prov)
	}

	pc, err := prov.Register(ctx, ownInteractiveSpec())
	if err != nil {
		t.Fatalf("заведение отказало: %v", err)
	}
	if pc.ClientID == "" {
		t.Fatal("исполнитель не назвал имени клиента — строке реестра нечем " +
			"быть ключённой, и церемония не найдёт клиента ни по чему")
	}
	// Форма выдачи — РЕШЕНИЕ use-case, и она возвращается дословно.
	if len(pc.GrantTypes) != 2 || pc.GrantTypes[0] != "authorization_code" {
		t.Errorf("форма выдачи подменена исполнителем: %v", pc.GrantTypes)
	}
}

// TestCompositionRoot_InteractiveClientDeleteHasAnExecutor — СНЯТИЕ
// исполняется.
//
// Снятие идёт ПОСЛЕ удаления строки реестра, поэтому отсутствие клиента —
// ожидаемое состояние, а не отказ.
func TestCompositionRoot_InteractiveClientDeleteHasAnExecutor(t *testing.T) {
	ctx := context.Background()
	cfg := loginLaneCfg()

	registry := &ownClientRegistryDouble{}
	prov := mustOwnExecutor(t, cfg, registry)

	if err := prov.Deregister(ctx, "oic-00000000000000000"); err != nil {
		t.Fatalf("снятие отказало: %v", err)
	}
	if len(registry.cleared) != 1 || registry.cleared[0] != "oic-00000000000000000" {
		t.Errorf("снятие не дошло до собственного реестра: %v — проверочное "+
			"значение секрета обязано уйти вместе с клиентом, чем бы оно туда "+
			"ни попало", registry.cleared)
	}
}

// mustOwnExecutor — исполнитель ТЕМ ЖЕ вызовом, что корень.
func mustOwnExecutor(t *testing.T, cfg config.Config, registry kanamepg.ClientSecretStore) interactiveclient.ProviderClients {
	t.Helper()
	prov, err := interactiveClientProvider(cfg, registry)
	if err != nil {
		t.Fatalf("исполнитель заведения не собран: %v", err)
	}
	return prov
}

// TestCompositionRoot_OwnInteractiveClientExecutorRefusesToStartWithoutHasher —
// условие поверхности п.9 (ban #16): исполнитель заведения без объявленного
// класса хешера — отказ в пуске с названием недостающего, а не клиент без
// материала и не откат к публичному.
func TestCompositionRoot_OwnInteractiveClientExecutorRefusesToStartWithoutHasher(t *testing.T) {
	cfg := loginLaneCfg()
	cfg.AuthN.Login.HasherFormat = ""

	prov, err := interactiveClientProvider(cfg, &ownClientRegistryDouble{})
	if err == nil {
		t.Fatalf("исполнитель заведения собран БЕЗ объявленного класса хешера (%T): клиент со способом "+
			"секретом получил бы строку без проверочного значения либо откат к публичному", prov)
	}
	if !strings.Contains(err.Error(), "hasher") {
		t.Errorf("отказ сборки не называет недостающего: %v", err)
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же корень с объявленным классом собирается —
	// отличие ровно одно, формат хешера.
	_ = mustOwnExecutor(t, loginLaneCfg(), &ownClientRegistryDouble{})
}

// TestCompositionRoot_OwnClientSecretIsHashedInTheSignInLaneClass — условие
// поверхности п.6: проверочное значение секрета клиента пишет хешер ТОГО
// объявленного класса, которым корень пишет приманку проверяющего
// (`cfg.AuthN.Login.Declared()`); иначе отказ незаведённому клиенту стоил бы
// иначе, чем заведённому, и время ответа перечисляло бы клиентов.
func TestCompositionRoot_OwnClientSecretIsHashedInTheSignInLaneClass(t *testing.T) {
	cfg := loginLaneCfg()
	declared := cfg.AuthN.Login.Declared()

	pc, err := mustOwnExecutor(t, cfg, &ownClientRegistryDouble{}).Register(context.Background(), ownInteractiveSpec())
	if err != nil {
		t.Fatalf("заведение отказало: %v", err)
	}
	if pc.SecretVerifier.IsZero() {
		t.Fatal("исполнитель корня не отдал проверочного значения — клиенту нечего будет предъявить")
	}
	checker, err := passwordverify.New(1, rootNopObserver{})
	if err != nil {
		t.Fatal(err)
	}
	meets, err := checker.MeetsDeclared(pc.SecretVerifier, declared)
	if err != nil || !meets {
		t.Fatalf("проверочное значение не отвечает объявленному классу полосы входа: отвечает=%t, %v", meets, err)
	}
	got := checker.Verify(pc.SecretVerifier, "x")
	for param, want := range declared.Params {
		if got.Params[param] != want {
			t.Errorf("параметр %s проверочного значения = %d, у объявленного класса приманки — %d",
				param, got.Params[param], want)
		}
	}
	if got.Format != declared.Format {
		t.Errorf("формат проверочного значения %q, у объявленного класса — %q", got.Format, declared.Format)
	}
}

type rootNopObserver struct{}

func (rootNopObserver) VerificationObserved(passwordverify.Outcome) {}
