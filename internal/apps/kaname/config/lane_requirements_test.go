// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_requirements_test.go — сценарии F4d-04, F4d-05, F4d-07, F4d-08, F4d-09 и
// F4d-12 приёмки Ф4д, плюс ТАБЛИЧНАЯ проба отказа старта (F4d-10).
//
// Проба отказа старта ходит по config.LaneRequirements и порождает по случаю на
// строку. Непокрытой клетки произведения «значение поля × обязательный элемент»
// не бывает by construction: чтобы завести требование, его придётся вписать в ту
// же таблицу, по которой ходит эта проба. Второй рукописный перечень клеток
// здесь НЕ заводится — он и был бы тем самым вторым местом об одном предмете.
package config_test

import (
	"errors"
	"strings"
	"testing"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// ПРИЗНАК задачи #1125, закрытый: боевая посадка, своя чеканка, НИ ОДНОГО адреса
// внешнего поставщика — старт проходит.
//
// До полосности этот же вход давал ТРИ отказа сразу (административный адрес,
// адрес набора ключей и адрес обмена), и отдельный клон в боевой посадке не
// поднимался, сколько бы кода ни переехало. Адрес набора ключей снят вместе с
// зеркалом (kaname#361); два оставшихся судятся ниже.
func TestF4d_OwnPostureBootsWithoutASingleProviderAddress(t *testing.T) {
	cfg := postureWithoutProviderAddresses(t, config.IdentityProviderOwn)

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; посадка own обязана подниматься без адресов поставщика", err)
	}
}

// Положительный контроль того же входа: строки полосы `external` те же пустые
// адреса НЕ пропускают, и отказов ровно два — по одному на адрес. Без него
// зелёное выше означало бы «стражи сняты», а не «стражи полосные».
//
// Строки судятся напрямую, а не проверкой старта: посадка снята фундаментом
// (PRO-Robotech/corelib#30), и старт отвергает её раньше требований полосы
// (#424). Строки живут до снятия полосы целиком (#363).
func TestF4d_ExternalLaneRowsStillRefuseTheSameEmptyAddresses(t *testing.T) {
	cfg := postureWithoutProviderAddresses(t, config.IdentityProviderExternal)

	err := externalLaneRefusal(cfg)
	if err == nil {
		t.Fatal("строки полосы external = nil; адреса поставщика обязаны требоваться")
	}
	msg := err.Error()
	for _, setting := range []string{
		"authn.hydra-admin-url", "authn.hydra-token-url",
	} {
		if !strings.Contains(msg, setting) {
			t.Fatalf("отказ обязан называть %s, получено: %q", setting, msg)
		}
	}
	// F4d-04/F4d-05: тексты отказов сохранены ДОСЛОВНО и несут ОДНУ добавленную
	// строку о том, каким значением поля требование снимается.
	if !strings.Contains(msg, "is not declared (env override KANAME_HYDRA_ADMIN_URL)") {
		t.Fatalf("текст провайдерского отказа обязан быть сохранён дословно, получено: %q", msg)
	}
	if n := strings.Count(msg, "declare authn.identity-provider=own and this requirement is lifted"); n != 2 {
		t.Fatalf("каждый полосный отказ обязан назвать снимающее значение; таких строк %d, ожидалось 2", n)
	}
	// Адрес набора ключей поставщика не требуется НИ ОДНОЙ строкой: верхнего
	// хопа зеркала больше нет (kaname#361), и отказ о нём был бы требованием
	// ручки, которую никто не читает.
	if strings.Contains(msg, "hydra-jwks") {
		t.Fatalf("строки полосы external требуют адрес набора ключей поставщика, а его читателя нет: %q", msg)
	}
}

// externalLaneRefusal — отказ строк стадии «настройка» полосы снятой посадки
// `external`, взятых из той же таблицы, по которой ходит проверка старта.
//
// Проверка старта до этих строк не доходит (#424): посадку вне словаря она
// отвергает первой и в одиночку. Строки живут в таблице до снятия полосы
// целиком (#363), и пробы их содержимого зовут их здесь — иначе положительные
// случаи зеленели бы на полосе `own`, где эти стражи не предъявляются вовсе.
func externalLaneRefusal(c config.Config) error {
	var errs error
	rows := 0
	for _, r := range config.LaneRequirements {
		if r.Stage != config.LaneStageConfig || !r.AppliesTo(config.IdentityProviderExternal) {
			continue
		}
		rows++
		errs = multierr.Append(errs, r.Check(c, config.LaneWiring{}))
	}
	if rows == 0 {
		// Строк не осталось — судить нечего, и молчание не должно читаться как
		// «стражи пропустили вход».
		return errors.New("в таблице полос нет ни одной строки полосы external — пробам, которые их судят, судить нечего")
	}
	return errs
}

// postureWithoutProviderAddresses — боевая настройка со СВОЕЙ чеканкой и без
// единого адреса внешнего поставщика (ни в настройке, ни в окружении).
func postureWithoutProviderAddresses(t *testing.T, p config.IdentityProvider) config.Config {
	t.Helper()
	t.Setenv("KANAME_HYDRA_ADMIN_URL", "")
	t.Setenv("KANAME_HYDRA_TOKEN_URL", "")

	cfg := laneCfg(p)
	cfg.AuthN.HydraAdminURL = ""
	cfg.AuthN.HydraAdminCAFile = ""
	cfg.AuthN.HydraTokenURL = ""
	return cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-10 — ТАБЛИЧНАЯ проба отказа старта: по случаю на строку таблицы.
//
// Для каждой строки: на своей полосе невыполненное требование ОТВЕРГАЕТ старт и
// текст называет элемент; на ЧУЖОЙ полосе то же самое требование не
// предъявляется вовсе (полосность), и выполненное требование старт проходит
// (положительный контроль).
func TestF4d10_EveryLaneRequirementRefusesTheStartOnItsOwnLane(t *testing.T) {
	if len(config.LaneRequirements) == 0 {
		t.Fatal("таблица требований полос пуста — обходить нечего")
	}
	for _, r := range config.LaneRequirements {
		for _, lane := range config.IdentityProviderValues() {
			name := lane.String() + "/" + strings.ReplaceAll(r.Element, " ", "_")
			t.Run(name, func(t *testing.T) {
				cfg := laneCfg(lane)
				broken, wiring := breakRequirement(t, cfg, r)

				var err error
				switch r.Stage {
				case config.LaneStageConfig:
					err = broken.Validate()
				case config.LaneStageWiring:
					err = config.ValidateLaneWiring(broken, wiring)
				default:
					t.Fatalf("неизвестная стадия %v", r.Stage)
				}

				if !r.AppliesTo(lane) {
					// Полосность: на чужой полосе требование не предъявляется.
					// Признак производителя — имя поля посадки: оно стоит в
					// КАЖДОМ полосном отказе и ни в одном чужом.
					if err != nil && strings.Contains(err.Error(), config.IdentityProviderSetting) {
						t.Fatalf("требование %q предъявлено на чужой полосе %s: %v", r.Element, lane, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("требование %q на полосе %s не отвергло старт", r.Element, lane)
				}
				if !strings.Contains(err.Error(), config.IdentityProviderSetting) {
					t.Fatalf("отказ обязан называть поле посадки, получено: %q", err.Error())
				}

				// Положительный контроль: выполненное требование проходит.
				okWiring := wiredLane()
				var okErr error
				switch r.Stage {
				case config.LaneStageConfig:
					okErr = cfg.Validate()
				case config.LaneStageWiring:
					okErr = config.ValidateLaneWiring(cfg, okWiring)
				}
				if okErr != nil {
					t.Fatalf("положительный контроль: выполненное требование %q обязано проходить, получено %v",
						r.Element, okErr)
				}
			})
		}
	}
}

// breakRequirement возвращает вход, на котором названное требование НЕ
// выполнено. Ломается ровно один элемент — остальные остаются выполненными,
// иначе случай перестал бы отличать своё требование от соседского.
func breakRequirement(t *testing.T, cfg config.Config, r config.LaneRequirement) (config.Config, config.LaneWiring) {
	t.Helper()
	broken := cfg
	w := wiredLane()

	switch r.Element {
	case "административная дорога к внешнему поставщику":
		t.Setenv("KANAME_HYDRA_ADMIN_URL", "")
		broken.AuthN.HydraAdminURL = ""
		broken.AuthN.HydraAdminCAFile = ""
	case "адрес обмена утверждения у внешнего поставщика":
		t.Setenv("KANAME_HYDRA_TOKEN_URL", "")
		broken.AuthN.HydraTokenURL = ""
	case "своя чеканка токенов включена":
		broken.AuthN.TokenSigning.Enabled = false
	case "контур выдачи ключей служебных учёток переведён на свою чеканку":
		broken.AuthN.ClientToken.Enabled = false
	case "приём предъявленного удостоверения включён":
		broken.AuthN.PresentedCredential.Enabled = false
	case "подписант своей чеканки провязан":
		w.OwnMintSignerWired = false
	case "свои способы входа человека провязаны":
		w.HumanCredentialsWired = false
	case "своя сессия человека провязана":
		w.HumanSessionsWired = false
	case "срок сессии и домен печенья объявлены":
		broken.AuthN.Login.SessionTTL = 0
	case "предел частоты неверных предъявлений объявлен по обеим осям":
		broken.AuthN.Login.SourceWindow = 0
	case "правило пароля объявлено: длина, состояние и адрес проверки утечек":
		broken.AuthN.Login.BreachCheck = ""
	case "ручка «что писать» объявлена и в перечне записываемых":
		broken.AuthN.Login.HasherFormat = ""
	case "ёмкость проверяющего и резерв памяти объявлены":
		broken.AuthN.Login.VerifierCapacity = 0
	case "величина темпа заведения объявлена: предел и окно":
		broken.AuthN.Registration.AdmissionsPerWindow = nil
	case "срок кода восстановления доступа объявлен":
		broken.AuthN.Login.RecoveryCodeTTL = 0
	case "пять величин подтверждения адреса объявлены: срок и предел попыток кода, промежуток, число и окно писем":
		broken.AuthN.Login.VerificationCodeTTL = 0
	case "сроки церемонии объявлены в пределах потолков фундамента: срок кода и срок семейства":
		broken.AuthN.Ceremony.CodeTTL = 0
	case "перечень ключей обёртки секретов второго фактора объявлен":
		t.Setenv("KANAME_SECOND_FACTOR_ENC_KEY", "")
		broken.AuthN.SecondFactorEncryptionKeyHex = ""
	case "окно свежести правки своих данных объявлено":
		broken.AuthN.SelfServiceFreshness = 0
	case "привязка ключей доступа объявлена: имя доверяющей стороны, перечень происхождений, перечень алгоритмов":
		broken.AuthN.AccessKeys.Origins = nil
	case "каждый уровень доверия каталога предъявим":
		w.PresentableACRs = nil
	// Строка ниже требует ОТСУТСТВИЯ, поэтому ломается наличием.
	case "дорога к внешнему поставщику не строится":
		w.ProviderAdminHopBuilt = true
	default:
		// Новая строка таблицы без способа её сломать — НАХОДКА, а не пропуск:
		// иначе клетка была бы «покрыта» случаем, который ничего не проверяет.
		t.Fatalf("в таблице появилось требование %q, которое эта проба не умеет ломать — "+
			"допишите способ, иначе клетка покрыта пустым случаем", r.Element)
	}
	return broken, w
}

// wiredLane — полностью провязанная полоса: все объекты собраны, каталог
// прочитан и его требования полосе предъявимы.
func wiredLane() config.LaneWiring {
	return config.LaneWiring{
		OwnMintSignerWired:    true,
		HumanCredentialsWired: true,
		HumanSessionsWired:    true,
		// Полностью провязанная полоса `own` — это в том числе полоса, у
		// которой дороги к внешнему поставщику НЕТ: поле ниже требуется
		// отсутствующим, поэтому «всё выполнено» для него означает false.
		ProviderAdminHopBuilt: false,
		PresentableACRs:       []string{"1", "2"},
		CatalogFloors: config.CatalogFloors{
			Readable: true,
			ByLevel:  map[string]int{"1": 285, "2": 32},
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-09 — величина берётся ИЗ КАТАЛОГА, а не из константы.

// Отказ называет ЧИСЛО записей, которые остались бы недостижимыми.
func TestF4d09_UnreachableFloorRefusalNamesTheCatalogCount(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	w := wiredLane()
	w.PresentableACRs = []string{"1"} // второй фактор не провязан

	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil; каталог требует уровня 2, полоса его не предъявляет")
	}
	if !strings.Contains(err.Error(), "32 catalog entr") {
		t.Fatalf("отказ обязан называть число записей каталога, получено: %q", err.Error())
	}
}

// Подмена каталога на набор БЕЗ записей уровня «2» отказ снимает — то есть
// величина действительно берётся из каталога.
func TestF4d09_CatalogWithoutRaisedFloorsLiftsTheRefusal(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	w := wiredLane()
	w.PresentableACRs = []string{"1"}
	w.CatalogFloors.ByLevel = map[string]int{"1": 285}

	if err := config.ValidateLaneWiring(cfg, w); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; каталог без поднятых полов противоречия не создаёт", err)
	}
}

// Нечитаемый каталог — ОТДЕЛЬНЫЙ исход, а не ноль.
func TestF4d09_UnreadableCatalogIsNotAnEmptyOne(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	w := wiredLane()
	w.CatalogFloors = config.CatalogFloors{Readable: false}

	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("ValidateLaneWiring() = nil; нечитаемый каталог обязан отвергать старт")
	}
	if !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("отказ обязан отличать нечитаемый каталог от пустого, получено: %q", err.Error())
	}
}

// Уровень, которого платформа не знает, требованием НЕ является — ровно как в
// точке решения. Иначе страж отказал бы в старте из-за записи, которая ни
// одного запроса не отвергла бы.
func TestF4d09_UnknownAssuranceLevelIsNotADemand(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	w := wiredLane()
	w.PresentableACRs = []string{"1"}
	w.CatalogFloors.ByLevel = map[string]int{"1": 285, "totally-unknown": 7}

	if err := config.ValidateLaneWiring(cfg, w); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; неизвестный платформе уровень требованием не является", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-08 — половина ПОЛНОТЫ ПРОВЯЗКИ не заменяется посадочной и наоборот.

func TestF4d08_WiringHalfIsNotReplacedByTheConfigHalf(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn) // настройка полная и валидная
	if err := cfg.Validate(); err != nil {
		t.Fatalf("посадочная половина обязана проходить на полной настройке: %v", err)
	}

	w := wiredLane()
	w.OwnMintSignerWired = false
	err := config.ValidateLaneWiring(cfg, w)
	if err == nil {
		t.Fatal("непровязанный подписант обязан отвергать старт в СБОРКЕ")
	}
	if !strings.Contains(err.Error(), "not wired in the composition root") {
		t.Fatalf("отказ сборки обязан быть ОТДЕЛЬНЫМ текстом, получено: %q", err.Error())
	}
}

// Обе точки читают ОДИН аксессор включённости своей чеканки — разойтись во
// мнении о ней они не могут.
func TestF4d08_BothHalvesReadOneEnabledAccessor(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	cfg.AuthN.TokenSigning.Enabled = false

	if err := cfg.Validate(); err == nil {
		t.Fatal("посадочная половина обязана отвергать выключенную чеканку")
	}
	// Тот же аксессор читает сборка: провязанный подписант при выключенной
	// настройке остаётся отказом посадочной половины, а не тихим успехом.
	if cfg.AuthN.TokenSigning.Enabled {
		t.Fatal("аксессор включённости прочитан не тот")
	}
}

// В непроизводственном режиме требований полосы нет — та же граница, что у
// соседних провайдерских стражей (in-process фикстура стендом не является).
func TestF4d_DevModeCarriesNoLaneRequirements(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderOwn)
	cfg.AuthN.Mode = config.ModeDev
	if err := config.ValidateLaneWiring(cfg, config.LaneWiring{}); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; в dev требований полосы нет", err)
	}
	// Положительный контроль: в боевом режиме тот же вход отвергается.
	cfg.AuthN.Mode = config.ModeProduction
	if err := config.ValidateLaneWiring(cfg, config.LaneWiring{}); err == nil {
		t.Fatal("в боевом режиме непровязанная полоса обязана отвергать старт")
	}
}
