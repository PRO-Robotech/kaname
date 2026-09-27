// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_interactive_client_wiring_test.go — У ЗАВЕДЕНИЯ И СНЯТИЯ ИНТЕРАКТИВНОГО
// КЛИЕНТА ПОД СОБСТВЕННОЙ ПОСАДКОЙ ЕСТЬ ИСПОЛНИТЕЛЬ (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// `InternalInteractiveClientService.Create` и `.Delete` исполняются портом
// `ProviderClients`. Композиционный корень наполнял этот порт ОДНИМ адаптером —
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
	"strings"
	"testing"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/clients"
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

// TestCompositionRoot_InteractiveClientCreateHasAnExecutorUnderOwnPosture —
// ЗАВЕДЕНИЕ под `own` исполняется.
func TestCompositionRoot_InteractiveClientCreateHasAnExecutorUnderOwnPosture(t *testing.T) {
	ctx := context.Background()
	cfg := loginLaneCfg(config.IdentityProviderOwn)

	prov := mustOwnExecutor(t, cfg, &ownClientRegistryDouble{})

	pc, err := prov.Register(ctx, ownInteractiveSpec())
	if errors.Is(err, clients.ErrNoExternalIdentityProvider) {
		t.Fatalf("под собственной посадкой заведение интерактивного клиента "+
			"исполнять НЕЧЕМ — порт отказывает за отсутствием чужого поставщика: %v", err)
	}
	if err != nil {
		t.Fatalf("заведение под собственной посадкой отказало: %v", err)
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

// TestCompositionRoot_InteractiveClientDeleteHasAnExecutorUnderOwnPosture —
// СНЯТИЕ под `own` исполняется.
//
// Снятие идёт ПОСЛЕ удаления строки реестра, поэтому отсутствие клиента —
// ожидаемое состояние, а не отказ (та же идемпотентность, с какой прежняя
// дорога принимает 404 поставщика).
func TestCompositionRoot_InteractiveClientDeleteHasAnExecutorUnderOwnPosture(t *testing.T) {
	ctx := context.Background()
	cfg := loginLaneCfg(config.IdentityProviderOwn)

	registry := &ownClientRegistryDouble{}
	prov := mustOwnExecutor(t, cfg, registry)

	err := prov.Deregister(ctx, "oic-00000000000000000")
	if errors.Is(err, clients.ErrNoExternalIdentityProvider) {
		t.Fatalf("под собственной посадкой снятие интерактивного клиента "+
			"исполнять НЕЧЕМ — порт отказывает за отсутствием чужого поставщика: %v", err)
	}
	if err != nil {
		t.Fatalf("снятие под собственной посадкой отказало: %v", err)
	}
	if len(registry.cleared) != 1 || registry.cleared[0] != "oic-00000000000000000" {
		t.Errorf("снятие не дошло до собственного реестра: %v — проверочное "+
			"значение секрета обязано уйти вместе с клиентом, чем бы оно туда "+
			"ни попало", registry.cleared)
	}
}

// TestCompositionRoot_InteractiveClientKeepsTheForeignRoadUnderExternalPosture —
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: под `external` исполнителем остаётся прежняя дорога.
//
// Без него отрицания выше зеленели бы на корне, который чужого поставщика не
// зовёт никогда, — то есть на сломанной прежней посадке.
func TestCompositionRoot_InteractiveClientKeepsTheForeignRoadUnderExternalPosture(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderExternal, "9097")

	registry := &ownClientRegistryDouble{}
	hasher, err := ownClientSecretHasher(cfg)
	if err != nil {
		t.Fatalf("под external хешер секрета клиента не нужен, а его сборка отказала: %v", err)
	}
	if hasher != nil {
		t.Errorf("под external собран хешер секрета клиента (%T) — исполнителя, которому он нужен, "+
			"на этой посадке нет", hasher)
	}
	prov, err := interactiveClientProvider(cfg, registry, hasher, nil)
	if err != nil {
		t.Fatalf("под external исполнитель не собран: %v", err)
	}

	if _, ok := prov.(*clients.InteractiveClientProvider); !ok {
		t.Fatalf("под external исполнителем стал %T — прежняя посадка обязана "+
			"ходить к чужому поставщику, и её поведение эта задача не меняет", prov)
	}
	// Дорога построена — иначе отрицания выше зеленели бы на корне, который
	// чужого поставщика не зовёт никогда. Вызова здесь нет намеренно: он ушёл
	// бы в сеть за адресом, которого на машине прогона не существует, и проба
	// судила бы разрешение имён. Признак построенности взят у продукта
	// (`roadIsBuilt` судит по адресу).
	if road, built := mustProviderAdminClient(cfg, nil); !built || road == nil || road.BaseURL == "" {
		t.Fatal("под external дорога к чужому поставщику НЕ построена")
	}
	if len(registry.cleared) != 0 {
		t.Errorf("под external собственный реестр тронут: %v — прежняя посадка "+
			"о нём знать не должна", registry.cleared)
	}
}

// mustOwnExecutor — исполнитель посадки `own` ТЕМИ ЖЕ вызовами, что корень:
// хешер от его же производителя, исполнитель от выбора по посадке.
func mustOwnExecutor(t *testing.T, cfg config.Config, registry kanamepg.ClientSecretStore) interactiveclient.ProviderClients {
	t.Helper()
	hasher, err := ownClientSecretHasher(cfg)
	if err != nil {
		t.Fatalf("хешер секрета клиента под own не собран: %v", err)
	}
	prov, err := interactiveClientProvider(cfg, registry, hasher, nil)
	if err != nil {
		t.Fatalf("исполнитель заведения под own не собран: %v", err)
	}
	return prov
}

// TestCompositionRoot_OwnInteractiveClientExecutorRefusesToStartWithoutHasher —
// условие поверхности п.9 (ban #16): на посадке `own` исполнитель заведения без
// хешера — отказ в пуске с названием недостающего, а не клиент без материала и
// не откат к публичному.
func TestCompositionRoot_OwnInteractiveClientExecutorRefusesToStartWithoutHasher(t *testing.T) {
	cfg := loginLaneCfg(config.IdentityProviderOwn)

	prov, err := interactiveClientProvider(cfg, &ownClientRegistryDouble{}, nil, nil)
	if err == nil {
		t.Fatalf("под own исполнитель заведения собран БЕЗ хешера (%T): клиент со способом секретом "+
			"получил бы строку без проверочного значения либо откат к публичному", prov)
	}
	if !strings.Contains(err.Error(), "hasher") {
		t.Errorf("отказ сборки не называет недостающего: %v", err)
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же корень с хешером своего производителя собирается.
	_ = mustOwnExecutor(t, cfg, &ownClientRegistryDouble{})
}

// TestCompositionRoot_OwnClientSecretIsHashedInTheSignInLaneClass — условие
// поверхности п.6: проверочное значение секрета клиента пишет хешер ТОГО
// объявленного класса, которым корень пишет приманку проверяющего
// (`cfg.AuthN.Login.Declared()`); иначе отказ незаведённому клиенту стоил бы
// иначе, чем заведённому, и время ответа перечисляло бы клиентов.
func TestCompositionRoot_OwnClientSecretIsHashedInTheSignInLaneClass(t *testing.T) {
	cfg := loginLaneCfg(config.IdentityProviderOwn)
	declared := cfg.AuthN.Login.Declared()

	pc, err := mustOwnExecutor(t, cfg, &ownClientRegistryDouble{}).Register(context.Background(), ownInteractiveSpec())
	if err != nil {
		t.Fatalf("заведение под own отказало: %v", err)
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
