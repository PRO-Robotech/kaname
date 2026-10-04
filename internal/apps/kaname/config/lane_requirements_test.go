// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_requirements_test.go — сценарии F4d-04, F4d-05, F4d-07, F4d-08, F4d-09 и
// F4d-12 приёмки Ф4д, плюс ТАБЛИЧНАЯ проба отказа старта (F4d-10).
//
// Проба отказа старта ходит по config.LaneRequirements и порождает по случаю на
// строку. Непокрытой строки не бывает by construction: чтобы завести требование,
// его придётся вписать в ту же таблицу, по которой ходит эта проба. Второй
// рукописный перечень строк здесь НЕ заводится — он и был бы тем самым вторым
// местом об одном предмете.
//
// Прежде случаи порождались произведением «строка × полоса посадки», и на
// «чужой» полосе требование проверялось непредъявленным. Посадка у службы одна
// (kaname#363): случай на строку один, и каждая строка предъявляется всякому
// боевому старту.
package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ─────────────────────────────────────────────────────────────────────────────
// ПРИЗНАК задачи #1125, закрытый: боевой старт своей чеканкой проходит, и ни одного
// адреса внешнего поставщика у него нет — ручек таких адресов у процесса больше
// нет вовсе.
//
// До полосности этот же вход давал ТРИ отказа сразу (административный адрес,
// адрес набора ключей и адрес обмена). Адрес набора ключей снят вместе с
// зеркалом (kaname#361), административный — вместе с посадкой поставщика
// (kaname#363), адрес обмена — вместе с дорогой обмена (kaname#494).
func TestF4d_ProductionBootsOnOwnMinting(t *testing.T) {
	cfg := laneCfg()

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v; боевой старт своей чеканкой обязан подниматься", err)
	}
}

// Законный близнец: тот же вход без своей чеканки старт НЕ проходит — то есть
// зелёное выше означает «своей чеканки достаточно», а не «проверка старта не
// отказывает ни на чём». Меняется ровно один факт — чеканка.
func TestF4d_ProductionWithoutOwnMintingRefusesTheSameInput(t *testing.T) {
	cfg := laneCfg()
	cfg.AuthN.TokenSigning.Enabled = false

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; без своей чеканки боевой старт обязан отказывать")
	}
	if !strings.Contains(err.Error(), "authn.token-signing.enabled is false") {
		t.Fatalf("отказ обязан называть выключенную чеканку, получено: %q", err.Error())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-10 — ТАБЛИЧНАЯ проба отказа старта: по случаю на строку таблицы.
//
// Для каждой строки: невыполненное требование ОТВЕРГАЕТ боевой старт, и текст
// называет элемент своим отказом; выполненное требование старт проходит
// (положительный контроль). Ни один отказ не называет снятого ключа посадки:
// совет объявить ключ, которого нет, послал бы оператора за вторым отказом.
func TestF4d10_EveryLaneRequirementRefusesTheProductionStart(t *testing.T) {
	if len(config.LaneRequirements) == 0 {
		t.Fatal("таблица требований пуста — обходить нечего")
	}
	cases := 0
	for _, r := range config.LaneRequirements {
		name := strings.ReplaceAll(r.Element, " ", "_")
		cases++
		t.Run(name, func(t *testing.T) {
			cfg := laneCfg()
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
			if err == nil {
				t.Fatalf("требование %q не отвергло боевой старт", r.Element)
			}
			own := r.Check(broken, wiring)
			if own == nil {
				t.Fatalf("строка %q на сломанном входе сама отказа не производит — случай ломает не её предмет", r.Element)
			}
			if !strings.Contains(err.Error(), own.Error()) {
				t.Fatalf("отказ старта не несёт отказа строки %q:\n  строка: %v\n  старт: %v", r.Element, own, err)
			}
			if strings.Contains(err.Error(), "identity-provider") {
				t.Fatalf("отказ называет снятый ключ посадки: %q", err.Error())
			}

			// Положительный контроль: выполненное требование проходит.
			var okErr error
			switch r.Stage {
			case config.LaneStageConfig:
				okErr = cfg.Validate()
			case config.LaneStageWiring:
				okErr = config.ValidateLaneWiring(cfg, wiredLane())
			}
			if okErr != nil {
				t.Fatalf("положительный контроль: выполненное требование %q обязано проходить, получено %v",
					r.Element, okErr)
			}
		})
	}
	t.Logf("перепись: строк таблицы %d · порождено случаев %d", len(config.LaneRequirements), cases)
}

// breakRequirement возвращает вход, на котором названное требование НЕ
// выполнено. Ломается ровно один элемент — остальные остаются выполненными,
// иначе случай перестал бы отличать своё требование от соседского.
func breakRequirement(t *testing.T, cfg config.Config, r config.LaneRequirement) (config.Config, config.LaneWiring) {
	t.Helper()
	broken := cfg
	w := wiredLane()

	switch r.Element {
	case "своя чеканка токенов включена":
		broken.AuthN.TokenSigning.Enabled = false
	case "контур выдачи ключей служебных учёток переведён на свою чеканку":
		broken.AuthN.ClientToken.Enabled = false
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
	case "почтовый узел объявлен: адрес узла и адрес отправителя":
		broken.InviteMail = config.InviteMailConfig{}
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
	cfg := laneCfg()
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
	cfg := laneCfg()
	w := wiredLane()
	w.PresentableACRs = []string{"1"}
	w.CatalogFloors.ByLevel = map[string]int{"1": 285}

	if err := config.ValidateLaneWiring(cfg, w); err != nil {
		t.Fatalf("ValidateLaneWiring() = %v; каталог без поднятых полов противоречия не создаёт", err)
	}
}

// Нечитаемый каталог — ОТДЕЛЬНЫЙ исход, а не ноль.
func TestF4d09_UnreadableCatalogIsNotAnEmptyOne(t *testing.T) {
	cfg := laneCfg()
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
	cfg := laneCfg()
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
	cfg := laneCfg() // настройка полная и валидная
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
	cfg := laneCfg()
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
// соседних стражей старта (in-process фикстура стендом не является).
func TestF4d_DevModeCarriesNoLaneRequirements(t *testing.T) {
	cfg := laneCfg()
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
