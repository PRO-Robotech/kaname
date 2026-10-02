// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_signing_test.go — стражи старта своей чеканки: F1-03 (алгоритм вне
// закрытого словаря), F1-09 (ключ обёртки), F1-20 (незаданный адресат либо
// издатель), F1-21 (пустой перечень допустимых алгоритмов).
package config

import (
	"strings"
	"testing"
	"time"
)

// fullSigningConfig — минимально ЗАКОННАЯ настройка своей чеканки.
//
// Пробы мутируют её по одному полю: так отказ, полученный пробой, относится к
// названному полю, а не к тому, что настройка неполна вообще.
func fullSigningConfig() TokenSigningConfig {
	return TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://kaname.kacho.local",
		Algorithm:         "ES256",
		AllowedAlgorithms: "ES256,RS256",
		KeySetPath:        "/.well-known/kaname/jwks.json",
		KeyLifetime:       90 * 24 * time.Hour,
	}
}

func TestF1_03_SigningAlgorithmOutsideTheClosedDictionaryRefusesStart(t *testing.T) {
	for _, bad := range []string{"HS256", "none", "None", "RS512", "rs256", " ES256"} {
		cfg := fullSigningConfig()
		cfg.Algorithm = bad
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("алгоритм %q принят — старт обязан отвергаться", bad)
		}
		if !strings.Contains(err.Error(), "authn.token-signing.algorithm") {
			t.Fatalf("отказ обязан называть НАСТРОЙКУ, получено: %v", err)
		}
		if !strings.Contains(err.Error(), "ES256") {
			t.Fatalf("отказ обязан называть допустимые значения, получено: %v", err)
		}
	}

	// Положительный контроль: алгоритм ИЗ словаря — сервис стартует. Без него
	// проба зелена на страже, не пускающем никого.
	for _, good := range []string{"RS256", "ES256", "EdDSA"} {
		cfg := fullSigningConfig()
		cfg.Algorithm = good
		cfg.AllowedAlgorithms = good
		if err := cfg.Validate(); err != nil {
			t.Fatalf("законный алгоритм %q отвергнут: %v", good, err)
		}
	}
}

func TestF1_20_UnsetIssuerRefusesStart(t *testing.T) {
	// Незаданный издатель означает «не сужаем», а не «по умолчанию».
	for _, bad := range []string{"", "   "} {
		cfg := fullSigningConfig()
		cfg.Issuer = bad
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("издатель %q принят — старт обязан отвергаться", bad)
		}
		if !strings.Contains(err.Error(), "authn.token-signing.issuer") {
			t.Fatalf("отказ обязан называть незаполненную настройку: %v", err)
		}
	}
	// Положительный контроль — с заполненной настройкой процесс стартует.
	if err := fullSigningConfig().Validate(); err != nil {
		t.Fatalf("полная настройка отвергнута: %v", err)
	}
}

func TestF1_21_EmptyAllowedAlgorithmsRefusesStart(t *testing.T) {
	// Проба использует ВЫРОЖДЕННЫЙ вход, а не только отсутствие значения:
	// разделитель без элементов даёт непустую строку и пустой перечень, и
	// страж обязан считать ЭЛЕМЕНТЫ, а не длину строки.
	for _, degenerate := range []string{"", ",", " , ", ",,,", "   ", "\t,\n"} {
		cfg := fullSigningConfig()
		cfg.AllowedAlgorithms = degenerate
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("вырожденный перечень %q принят — пустой перечень означает «принимаем любой»", degenerate)
		}
		if !strings.Contains(err.Error(), "authn.token-signing.allowed-algorithms") {
			t.Fatalf("отказ обязан называть настройку: %v", err)
		}
	}

	// Положительный контроль на ОБЕИХ мощностях — один и два элемента.
	for _, good := range []string{"ES256", "ES256,RS256", " ES256 , RS256 "} {
		cfg := fullSigningConfig()
		cfg.Algorithm = "ES256"
		cfg.AllowedAlgorithms = good
		if err := cfg.Validate(); err != nil {
			t.Fatalf("законный перечень %q отвергнут: %v", good, err)
		}
	}

	// Алгоритм подписи обязан входить в собственный перечень допустимых: иначе
	// мы выпускали бы то, что сами не принимаем.
	cfg := fullSigningConfig()
	cfg.Algorithm = "EdDSA"
	cfg.AllowedAlgorithms = "ES256,RS256"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("алгоритм подписи вне собственного перечня допустимых принят")
	}

	// И элемент перечня обязан быть из закрытого словаря.
	cfg = fullSigningConfig()
	cfg.AllowedAlgorithms = "ES256,HS256"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("алгоритм вне закрытого словаря принят перечнем допустимых")
	}
}

func TestF1_46_KeySetPathMustBeDeclaredAndUsable(t *testing.T) {
	// Издатель объявлен принимаемым, а записи источника у него нет —
	// отказ в старте, а не путь, выведенный из самого издателя.
	for _, degenerate := range []string{"", "   ", "///", "no-leading-slash"} {
		cfg := fullSigningConfig()
		cfg.KeySetPath = degenerate
		if err := cfg.Validate(); err == nil {
			t.Fatalf("вырожденный путь набора %q принят", degenerate)
		}
	}
	if err := fullSigningConfig().Validate(); err != nil {
		t.Fatalf("законный путь отвергнут: %v", err)
	}
}

func TestUnsetSigningKeyLifetimeRefusesStart(t *testing.T) {
	// Срок ключа — политика ротации, решение установки. Незаданный (нулевой)
	// срок отвергается так же, как отрицательный: ключница ниже по стеку
	// отказалась бы строиться, но до неё отказ доезжать не обязан.
	for _, bad := range []time.Duration{0, -time.Second} {
		cfg := fullSigningConfig()
		cfg.KeyLifetime = bad
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("срок ключа %s принят — старт обязан отвергаться", bad)
		}
		if !strings.Contains(err.Error(), "authn.token-signing.key-lifetime") {
			t.Fatalf("отказ обязан называть НАСТРОЙКУ, получено: %v", err)
		}
	}
	// Положительный близнец — тот же вход с заданным сроком стартует.
	if err := fullSigningConfig().Validate(); err != nil {
		t.Fatalf("полная настройка отвергнута: %v", err)
	}
}

// TestSigningKeyLifetimeRefusalNamesItsCause — отказ называет ПРИЧИНУ, а не
// только ключ: нулевой срок — «не объявлен», отрицательный — объявлен негодным.
//
// Оператор, задавший `-1h`, прочитав «is not declared», ищет ключ, который уже
// задал, и не находит ошибки: текст отказа обязан вести к следующему шагу.
func TestSigningKeyLifetimeRefusalNamesItsCause(t *testing.T) {
	const notDeclared = "authn.token-signing.key-lifetime is not declared"
	const mustBePositive = "authn.token-signing.key-lifetime must be positive"

	zero := fullSigningConfig()
	zero.KeyLifetime = 0
	err := zero.Validate()
	if err == nil || !strings.Contains(err.Error(), notDeclared) || strings.Contains(err.Error(), mustBePositive) {
		t.Fatalf("нулевой срок обязан отвергаться как НЕОБЪЯВЛЕННЫЙ, получено: %v", err)
	}

	negative := fullSigningConfig()
	negative.KeyLifetime = -time.Hour
	err = negative.Validate()
	if err == nil || !strings.Contains(err.Error(), mustBePositive) || strings.Contains(err.Error(), notDeclared) {
		t.Fatalf("отрицательный срок объявлен — отказ обязан называть его негодным, а не "+
			"необъявленным; получено: %v", err)
	}
	if !strings.Contains(err.Error(), "-1h0m0s") {
		t.Fatalf("отказ обязан называть объявленную величину, получено: %v", err)
	}
}

func TestTokenSigningDisabledIsNotValidatedIntoOblivion(t *testing.T) {
	// Пока своя чеканка выключена, её настройки не требуются: страж, требующий
	// того, чем не пользуются, — отказ в старте без предмета.
	var cfg TokenSigningConfig
	if err := cfg.Validate(); err != nil {
		t.Fatalf("выключенная чеканка не обязана требовать настроек: %v", err)
	}
	// …но ВКЛЮЧЁННАЯ и пустая — отвергается: это и есть тот случай, ради
	// которого страж существует.
	cfg.Enabled = true
	if err := cfg.Validate(); err == nil {
		t.Fatalf("включённая чеканка без настроек принята")
	}
}

func TestAllowedAlgorithmsCountsElementsNotLength(t *testing.T) {
	// Тот же предикат обязан читаться и вызывающим, и стражем: два места об
	// одном предмете разошлись бы ровно на вырожденном значении.
	if got := ParseAlgorithmList(","); len(got) != 0 {
		t.Fatalf("разделитель без элементов дал %d элементов", len(got))
	}
	if got := ParseAlgorithmList("ES256 , RS256"); len(got) != 2 {
		t.Fatalf("два элемента прочитаны как %d", len(got))
	}
}
