// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sakey_binding_test.go — страж старта: требование связанного с отправителем
// токена и переведённый контур выдачи противоречат друг другу (задача #1137).
//
// # Предмет
//
// `authn.sakey-bind-dpop` — половина ВЫДАЧИ у контроля связанных токенов, и
// читателя у неё ровно один: регистрация клиента у прежнего издателя. На
// переведённом контуре регистрация не заводится вовсе, и величина не читается
// НИЧЕМ: оператор объявляет контроль включённым, а включённым он не становится.
//
// Это тот же класс, что «объявленное ограничение не ограничивает», только с
// другой стороны: там поле принимали и не читали, здесь ручку разрешают
// включить и не исполняют. Обе половины настройки по отдельности защитимы, а
// вместе означают возможность, которой нет ни при каком входе.
//
// # Почему отказ в старте, а не предупреждение
//
// Асимметрия цены, та же, что у соседних стражей этого файла: слишком строгий
// страж даёт отказ в старте — видимый сразу, с именами обеих настроек в тексте.
// Слишком слабый даёт стенд, на котором машинные токены не связаны, при
// операторе, уверенном в обратном, — и не видно этого никогда.
//
// # Почему ручка не снята вовсе
//
// Читатель у неё есть — на НЕпереведённом контуре, где обмен идёт у прежнего
// издателя и связанность решает его регистрация. Снять ручку значило бы снять
// работающий контроль на той посадке, где он работает.
package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// contourTranslated — посадка, на которой выдача ключей переведена на свою
// чеканку: токен-эндпоинт платформы объявлен и настроен полностью.
func contourTranslated(t *testing.T) config.Config {
	t.Helper()
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	cfg.APIServer.RegistryToken = config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096",
		Service:  "registry.kacho.local",
	}
	cfg.AuthN.TokenSigning = config.TokenSigningConfig{
		Enabled:           true,
		Issuer:            "https://iam.kacho.local",
		Algorithm:         tokenpolicy.AlgES256,
		AllowedAlgorithms: tokenpolicy.AlgES256,
		KeySetPath:        "/.well-known/kacho/jwks.json",
	}
	cfg.AuthN.ClientToken = config.ClientTokenConfig{
		Enabled:          true,
		AllowedAudiences: "registry.kacho.local, https://api.kacho.cloud",
		DefaultAudience:  "registry.kacho.local",
		TokenTTL:         15 * time.Minute,
		BodyCeiling:      64 << 10,
	}
	return cfg
}

// contourMirrored — та же посадка, но контур НЕ переведён: токен-эндпоинт не
// объявлен, обмен идёт у прежнего издателя.
func contourMirrored(t *testing.T) config.Config {
	t.Helper()
	cfg := contourTranslated(t)
	cfg.AuthN.ClientToken = config.ClientTokenConfig{}
	return cfg
}

// TestValidate_BindDPoPOnTranslatedContour_RefusesToStart — противоречие
// названо на старте, а не растворено в умолчании.
func TestValidate_BindDPoPOnTranslatedContour_RefusesToStart(t *testing.T) {
	cfg := contourTranslated(t)
	cfg.AuthN.SAKeyBindDPoP = true

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil: требование связанного токена объявлено включённым на контуре, " +
			"где его читателя не существует, — контроль объявлен и не исполняется ни при каком входе")
	}
	for _, want := range []string{"sakey-bind-dpop", "client-token"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %q; текст обязан назвать обе настройки, иначе оператору нечего править (нет %q)",
				err.Error(), want)
		}
	}
}

// TestValidate_BindDPoPOnMirroredContour_Starts — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше зеленело бы на страже, отвергающем ручку ВЕЗДЕ, — то
// есть на снятии работающего контроля вместо починки неработающего.
func TestValidate_BindDPoPOnMirroredContour_Starts(t *testing.T) {
	cfg := contourMirrored(t)
	cfg.AuthN.SAKeyBindDPoP = true

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: на непереведённом контуре у ручки есть читатель — регистрация "+
			"клиента у прежнего издателя, — и отвергать её значит снимать работающий контроль", err)
	}
}

// TestValidate_TranslatedContourWithoutBinding_Starts — второй положительный
// контроль: сам по себе переведённый контур старту не мешает.
//
// Без него проба выше была бы неотличима от «переведённый контур вообще не
// стартует».
func TestValidate_TranslatedContourWithoutBinding_Starts(t *testing.T) {
	cfg := contourTranslated(t)
	cfg.AuthN.SAKeyBindDPoP = false

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v: переведённый контур без требования связанного токена обязан стартовать", err)
	}
}
