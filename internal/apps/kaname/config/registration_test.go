// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// registration_test.go — величина ТЕМПА заведения объявляется посадкой `own`
// (приёмка Ф4 Р5, Ф4-18, Ф4-19; задача kacho#1270).

// TestRegistration_F4_18_UnsetAdmissionRateRefusesTheStartNamingTheKnob —
// профиль без величины предела темпа не поднимается, и текст называет ручку;
// незаданное окно называется своей ручкой; отрицательный предел отвергается.
func TestRegistration_F4_18_UnsetAdmissionRateRefusesTheStartNamingTheKnob(t *testing.T) {
	var unset config.RegistrationConfig
	err := unset.ValidateAdmissionRate()
	if err == nil {
		t.Fatal("ValidateAdmissionRate() = nil на незаданной величине: она подставлена молча")
	}
	for _, want := range []string{
		"authn.registration.admissions-per-window", "KANAME_AUTHN__REGISTRATION__ADMISSIONS_PER_WINDOW",
		"authn.registration.admission-window", "KANAME_AUTHN__REGISTRATION__ADMISSION_WINDOW",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("отказ обязан называть %s, получено: %q", want, err)
		}
	}

	negative := registrationSettings()
	neg := int64(-1)
	negative.AdmissionsPerWindow = &neg
	if err := negative.ValidateAdmissionRate(); err == nil || !strings.Contains(err.Error(), "-1") {
		t.Fatalf("отрицательный предел обязан отвергаться с величиной в тексте, получено: %v", err)
	}
	noWindow := registrationSettings()
	noWindow.AdmissionWindow = 0
	if err := noWindow.ValidateAdmissionRate(); err == nil || !strings.Contains(err.Error(), "admission-window") {
		t.Fatalf("незаданное окно обязано называть свою ручку, получено: %v", err)
	}
}

// TestRegistration_F4_19_DeclaredAdmissionRatePassesTheGuard — положительный
// контроль: объявленная величина проходит; ноль законен (первое заведение
// безусловно, дальнейшие в окне — ни одного).
func TestRegistration_F4_19_DeclaredAdmissionRatePassesTheGuard(t *testing.T) {
	ok := registrationSettings()
	if err := ok.ValidateAdmissionRate(); err != nil {
		t.Fatalf("объявленная величина обязана проходить: %v", err)
	}
	maxEvents, window := ok.AdmissionRate()
	if maxEvents != 3 || window != time.Hour {
		t.Fatalf("величина не доехала: %d за %v", maxEvents, window)
	}
	zero := registrationSettings()
	z := int64(0)
	zero.AdmissionsPerWindow = &z
	if err := zero.ValidateAdmissionRate(); err != nil {
		t.Fatalf("ноль законен: %v", err)
	}
}

// TestRegistration_EnvVarsArmTheFields — переменные, названные текстом отказа,
// доезжают до полей (умолчания нет, привязка явная — как у трёх потолков).
func TestRegistration_EnvVarsArmTheFields(t *testing.T) {
	t.Setenv("KANAME_AUTHN__REGISTRATION__ADMISSIONS_PER_WINDOW", "0")
	t.Setenv("KANAME_AUTHN__REGISTRATION__ADMISSION_WINDOW", "45m")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	r := cfg.AuthN.Registration
	if r.AdmissionsPerWindow == nil || *r.AdmissionsPerWindow != 0 {
		t.Fatalf("переменная admissions-per-window не доехала (ноль!): %v", r.AdmissionsPerWindow)
	}
	if r.AdmissionWindow != 45*time.Minute {
		t.Fatalf("переменная admission-window не доехала: %v", r.AdmissionWindow)
	}
}

// TestRegistration_KnobsAllHaveARequiredSettingRow — каждая ручка регистрации
// названа документом оператора, и каждая строка документа с этой приставкой
// имеет стража; обе разности множеств.
func TestRegistration_KnobsAllHaveARequiredSettingRow(t *testing.T) {
	const prefix = "authn.registration."
	fromKnobs := map[string]bool{}
	for _, k := range config.RegistrationKnobs {
		fromKnobs[k.Key] = true
		want := "KANAME_" + strings.ToUpper(strings.NewReplacer(".", "__", "-", "_").Replace(k.Key))
		if k.Env != want {
			t.Errorf("ключ %s: переменная объявлена %q, а viper выведет %q", k.Key, k.Env, want)
		}
	}
	fromTable := map[string]bool{}
	for _, s := range config.RequiredSettings {
		if strings.HasPrefix(s.Key, prefix) {
			fromTable[s.Key] = true
			if len(s.Lanes) != 1 || s.Lanes[0] != config.IdentityProviderOwn {
				t.Errorf("строка %s обязана быть полосной (own): %v", s.Key, s.Lanes)
			}
		}
	}
	if len(fromKnobs) == 0 {
		t.Fatal("ручек регистрации ноль — обе разности пусты тривиально")
	}
	for key := range fromKnobs {
		if !fromTable[key] {
			t.Errorf("ручка %s объявлена стражем и не названа документом оператора", key)
		}
	}
	for key := range fromTable {
		if !fromKnobs[key] {
			t.Errorf("документ называет %s, а стража у неё нет", key)
		}
	}
	t.Logf("перепись: ручек регистрации %d, строк документа с приставкой %q %d", len(fromKnobs), prefix, len(fromTable))
}

// registrationSettings — годная настройка регистрации (Ф4).
func registrationSettings() config.RegistrationConfig {
	three := int64(3)
	return config.RegistrationConfig{AdmissionsPerWindow: &three, AdmissionWindow: time.Hour}
}
