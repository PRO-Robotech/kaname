// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// second_factor_knobs_test.go — ручки второго фактора (Ф12, kacho#1281):
// перечень ключей обёртки секретов под СВОЕЙ ручкой (Р2, Ф12-35 «а», «б») и
// окно свежести правки своих данных (Р8, Ф12-36). Обе — без умолчания; обе
// требуются полосой `own` строками таблицы требований (их клетки порождает
// `TestF4d10_EveryLaneRequirementRefusesTheStartOnItsOwnLane`).

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// TestF12_35_SecondFactorKeyRingIsItsOwnKnobWithBothHalves — Р2: перечень
// подаётся значением ЛИБО именем переменной окружения; «не задана» — ни одна из
// двух; ключ негодного размера — отказ с позицией, без байта значения; повтор —
// отказ; два ключа — два.
func TestF12_35_SecondFactorKeyRingIsItsOwnKnobWithBothHalves(t *testing.T) {
	keyA := strings.Repeat("01", keywrap.KeySize)
	keyB := strings.Repeat("02", keywrap.KeySize)

	t.Run("не задана ни одна половина — отказ называет ручку", func(t *testing.T) {
		t.Setenv("KANAME_SECOND_FACTOR_ENC_KEY", "")
		var c config.AuthNConfig
		_, err := c.ResolveSecondFactorEncryptionKeys()
		if err == nil || !strings.Contains(err.Error(), "authn.second-factor-encryption-key-hex") {
			t.Fatalf("незаданный перечень обязан отвергаться с именем ручки, получено %v", err)
		}
		if !strings.Contains(err.Error(), "KANAME_SECOND_FACTOR_ENC_KEY") {
			t.Fatalf("отказ обязан назвать переменную окружения второй половины, получено %v", err)
		}
	})
	t.Run("значением — один ключ", func(t *testing.T) {
		t.Setenv("KANAME_SECOND_FACTOR_ENC_KEY", "")
		c := config.AuthNConfig{SecondFactorEncryptionKeyHex: keyA}
		keys, err := c.ResolveSecondFactorEncryptionKeys()
		if err != nil || len(keys) != 1 || len(keys[0]) != keywrap.KeySize {
			t.Fatalf("один годный ключ значением: keys=%d err=%v", len(keys), err)
		}
	})
	t.Run("именем переменной — второй половиной", func(t *testing.T) {
		t.Setenv("SF_KEYS_OF_THE_PROBE", keyB+","+keyA)
		c := config.AuthNConfig{SecondFactorEncryptionKeyHexEnv: "SF_KEYS_OF_THE_PROBE"}
		keys, err := c.ResolveSecondFactorEncryptionKeys()
		if err != nil || len(keys) != 2 {
			t.Fatalf("перечень из переменной: keys=%d err=%v", len(keys), err)
		}
		if keys[0][0] != 0x02 || keys[1][0] != 0x01 {
			t.Fatalf("порядок перечня обязан сохраняться: первый оборачивает")
		}
	})
	t.Run("ключ негодного размера — позиция, без значения", func(t *testing.T) {
		c := config.AuthNConfig{SecondFactorEncryptionKeyHex: keyA + "," + "0a0b"}
		_, err := c.ResolveSecondFactorEncryptionKeys()
		if err == nil || !strings.Contains(err.Error(), "#2 of 2") {
			t.Fatalf("негодный размер обязан называть позицию, получено %v", err)
		}
		if strings.Contains(err.Error(), "0a0b") || strings.Contains(err.Error(), keyA) {
			t.Fatalf("отказ не вправе нести байт значения: %v", err)
		}
	})
	t.Run("повтор ключа — отказ", func(t *testing.T) {
		c := config.AuthNConfig{SecondFactorEncryptionKeyHex: keyA + "," + keyA}
		if _, err := c.ResolveSecondFactorEncryptionKeys(); err == nil {
			t.Fatal("повтор ключа обязан отвергаться: смена, которой не было")
		}
	})
	t.Run("перечень подписного ключа — ДРУГАЯ ручка", func(t *testing.T) {
		t.Setenv("KANAME_SECOND_FACTOR_ENC_KEY", "")
		c := config.AuthNConfig{JWKSEncryptionKeyHex: keyA}
		if _, err := c.ResolveSecondFactorEncryptionKeys(); err == nil {
			t.Fatal("ручка подписного ключа не подменяет перечень второго фактора (Р2)")
		}
	})
}

// TestF12_36_SelfServiceFreshnessIsAKnobWithoutADefault — Р8: окно объявляет
// профиль; незаданное — отказ с именем ручки; заданное — величина читается.
func TestF12_36_SelfServiceFreshnessIsAKnobWithoutADefault(t *testing.T) {
	var c config.AuthNConfig
	err := c.ValidateSelfServiceFreshness()
	if err == nil || !strings.Contains(err.Error(), "authn.self-service-freshness") {
		t.Fatalf("незаданное окно обязано отвергаться с именем ручки, получено %v", err)
	}
	if !strings.Contains(err.Error(), "KANAME_AUTHN__SELF_SERVICE_FRESHNESS") {
		t.Fatalf("отказ обязан назвать переменную окружения, получено %v", err)
	}
	c.SelfServiceFreshness = 15 * time.Minute
	if err := c.ValidateSelfServiceFreshness(); err != nil {
		t.Fatalf("объявленное окно обязано проходить: %v", err)
	}
	c.SelfServiceFreshness = -time.Minute
	if err := c.ValidateSelfServiceFreshness(); err == nil {
		t.Fatal("отрицательное окно — не величина")
	}
}

// TestF12_LaneRequirementsCarryBothKnobsOnOwn — обе ручки стоят строками
// таблицы требований полосы `own` стадии «настройка»; клетки порождает
// табличная проба, здесь — что строки есть.
func TestF12_LaneRequirementsCarryBothKnobsOnOwn(t *testing.T) {
	want := map[string]bool{
		"перечень ключей обёртки секретов второго фактора объявлен": false,
		"окно свежести правки своих данных объявлено":               false,
	}
	for _, r := range config.LaneRequirements {
		if _, ok := want[r.Element]; ok {
			if r.Stage != config.LaneStageConfig || !r.AppliesTo(config.IdentityProviderOwn) || r.AppliesTo(config.IdentityProviderExternal) {
				t.Fatalf("строка %q обязана быть стадии «настройка» и только полосы own", r.Element)
			}
			want[r.Element] = true
		}
	}
	for el, seen := range want {
		if !seen {
			t.Fatalf("в таблице требований нет строки %q", el)
		}
	}
}
