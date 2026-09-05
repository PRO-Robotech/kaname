// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_provider_test.go — сценарии F4d-01 и F4d-02 приёмки Ф4д: поле
// посадки личности есть ЗАКРЫТЫЙ словарь без умолчания в коде.
//
// Отказ старта здесь утверждается ТЕКСТОМ, а не только исходом: тон отказа при
// старте — часть контракта оператора и одно из трёх мест, выведенных из-под
// запрета на публичный разбор (`security.md`).
package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// laneCfg — боевая настройка, удовлетворяющая всем прочим требованиям старта
// НА ЛЮБОЙ полосе, чтобы предметом случая осталось РОВНО поле посадки.
//
// Требования обеих полос выполнены одновременно намеренно: иначе
// положительный контроль «законное значение проходит» падал бы не на предмете
// случая, а на содержимом полосы, и отрицание рядом с ним зеленело бы по
// неверной причине.
func laneCfg(p config.IdentityProvider) config.Config {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "hook-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.AuthN.IdentityProvider = p
	cfg.AuthN.TokenSigning = ownMintingSettings()
	return cfg
}

// ownMintingSettings — валидная настройка своей чеканки. Своя чеканка
// проверяется собственным стражем в любом режиме, поэтому её значения обязаны
// быть настоящими, а не заглушкой.
func ownMintingSettings() config.TokenSigningConfig {
	return config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://iam.kacho.cloud",
		Algorithm:         "RS256",
		AllowedAlgorithms: "RS256",
		KeySetPath:        "/.well-known/kacho/jwks.json",
		KeyLifetime:       90 * 24 * time.Hour,
	}
}

// F4d-01 — профиль, не объявивший поле, старт не проходит; текст называет поле
// и ОБА законных значения.
func TestF4d01_UnsetIdentityProviderRefusesTheStart(t *testing.T) {
	cfg := laneCfg(config.IdentityProviderUnset)

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil; посадка личности не выбрана — старт обязан быть отвергнут")
	}
	msg := err.Error()
	if !strings.Contains(msg, "authn.identity-provider") {
		t.Fatalf("отказ обязан называть поле, получено: %q", msg)
	}
	for _, name := range config.IdentityProviderNames() {
		if !strings.Contains(msg, name) {
			t.Fatalf("отказ обязан называть законное значение %q, получено: %q", name, msg)
		}
	}
}

// F4d-01 — парный ПОЛОЖИТЕЛЬНЫЙ контроль: тот же вход с любым из двух законных
// значений старт проходит. Без него отрицание выше зеленело бы на проверке,
// отвергающей всё.
func TestF4d01_EitherLegalValuePassesTheStart(t *testing.T) {
	for _, v := range config.IdentityProviderValues() {
		t.Run(v.String(), func(t *testing.T) {
			cfg := laneCfg(v)
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v; законное значение %q обязано проходить", err, v)
			}
		})
	}
}

// F4d-01 — отказ производится ДО любых полосных требований: посадка неизвестна,
// и требовать по ней нечего. Проверяется наблюдаемым: при незаданном поле в
// тексте нет НИ ОДНОГО полосного требования.
func TestF4d01_UnsetLaneDemandsNothingLaneScoped(t *testing.T) {
	t.Setenv("KACHO_IAM_HYDRA_ADMIN_URL", "")
	t.Setenv("KACHO_IAM_HYDRA_JWKS_URL", "")
	t.Setenv("KACHO_IAM_HYDRA_TOKEN_URL", "")

	cfg := laneCfg(config.IdentityProviderUnset)
	cfg.AuthN.HydraAdminURL = ""
	cfg.AuthN.HydraAdminCAFile = ""
	cfg.AuthN.HydraJWKSURL = ""
	cfg.AuthN.HydraTokenURL = ""

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, ожидался отказ по незаданной посадке")
	}
	msg := err.Error()
	for _, lanescoped := range []string{"hydra-admin-url", "hydra-jwks-url", "hydra-token-url"} {
		if strings.Contains(msg, lanescoped) {
			t.Fatalf("при незаданной посадке полосное требование %q предъявляться не должно: %q",
				lanescoped, msg)
		}
	}

	// Положительный контроль той же оси: объявленная посадка external те же
	// требования предъявляет — то есть отсутствие их выше не оттого, что их
	// вообще нет.
	ext := cfg
	ext.AuthN.IdentityProvider = config.IdentityProviderExternal
	extErr := ext.Validate()
	if extErr == nil || !strings.Contains(extErr.Error(), "hydra-admin-url") {
		t.Fatalf("контроль: при external требование адреса обязано предъявляться, получено: %v", extErr)
	}
}

// F4d-02 — значение вне словаря старт не проходит, и отката к «безопасному» не
// происходит: негодное значение не читается ни как own, ни как external.
func TestF4d02_ValueOutsideTheDictionaryRefusesTheStart(t *testing.T) {
	// Соседняя раскладка регистра · лишний символ · пустая строка · омоглиф
	// кириллицы (`о` в `own`) — четыре формы одного класса.
	for _, raw := range []string{"External", "OWN", "own ", "externa", "", "оwn"} {
		t.Run(strings.ReplaceAll(raw, " ", "_"), func(t *testing.T) {
			got, err := config.ParseIdentityProvider(raw)
			if err == nil {
				t.Fatalf("ParseIdentityProvider(%q) = %v, nil; значение вне словаря обязано быть отвергнуто", raw, got)
			}
			if got == config.IdentityProviderOwn || got == config.IdentityProviderExternal {
				t.Fatalf("ParseIdentityProvider(%q) откатилось к законному значению %v — отката быть не должно", raw, got)
			}
			if !strings.Contains(err.Error(), "authn.identity-provider") {
				t.Fatalf("отказ обязан называть поле, получено: %q", err.Error())
			}
		})
	}
}

// F4d-02 — положительный контроль: оба канонических значения принимаются.
func TestF4d02_CanonicalValuesAreAccepted(t *testing.T) {
	for _, name := range config.IdentityProviderNames() {
		got, err := config.ParseIdentityProvider(name)
		if err != nil {
			t.Fatalf("ParseIdentityProvider(%q) = %v; каноническое значение обязано приниматься", name, err)
		}
		if got.String() != name {
			t.Fatalf("ParseIdentityProvider(%q).String() = %q; разбор и печать обязаны быть взаимно обратны", name, got.String())
		}
	}
}

// Документированное ИМЯ переменной окружения обязано иметь читателя — то есть
// доезжать до поля.
//
// Класс, из-за которого проба заведена, реален и был найден в этой же работе:
// viper резолвит переменную только для ключа, который он УЖЕ ЗНАЕТ, а у поля
// посадки умолчания нет намеренно. Без явной привязки документированная
// переменная не доезжала до поля ВООБЩЕ — оператор задавал её, процесс принимал
// старт как «посадка не объявлена», и ручка выглядела настроенной, ничего не
// делая.
//
// Проба фиксирует ИСХОД, а не объявление: ставит переменную ровно под тем
// именем, которое напечатано в документации, и требует, чтобы загруженная
// настройка изменилась. Значение выбрано НЕ-умолчательным намеренно: совпадение
// с умолчанием сделало бы утверждение тождественно истинным (умолчания у поля
// нет, но это свойство может измениться, а проба обязана пережить такое
// изменение осмысленной).
func TestDocumentedEnvName_IdentityProvider(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHN__IDENTITY_PROVIDER", "own")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthN.IdentityProvider != config.IdentityProviderOwn {
		t.Fatalf("документированная переменная не доехала до поля: получено %v", cfg.AuthN.IdentityProvider)
	}
}

// Отрицание идёт В ПАРЕ с положительным контролем: имя БЕЗ двойных
// подчёркиваний (плоская форма, которую легко написать по привычке) на
// настройку влиять НЕ должно. Без этой половины проба зеленела бы на любом
// имени и ничего не сужала.
func TestDocumentedEnvName_IdentityProvider_FlatFormDoesNotApply(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHN_IDENTITY_PROVIDER", "own")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthN.IdentityProvider.IsSet() {
		t.Fatalf("плоская форма имени не должна влиять на настройку, получено %v", cfg.AuthN.IdentityProvider)
	}
}

// Незаданная переменная оставляет поле НЕОБЪЯВЛЕННЫМ: привязка регистрирует
// ключ, но значения ему не даёт — иначе она была бы тем самым умолчанием в
// коде, которого здесь нет намеренно.
func TestIdentityProviderStaysUnsetWithoutAnyDeclaration(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHN__IDENTITY_PROVIDER", "")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuthN.IdentityProvider.IsSet() {
		t.Fatalf("привязка к окружению дала полю значение — это умолчание в коде: %v",
			cfg.AuthN.IdentityProvider)
	}
}
