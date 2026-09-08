// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_key_material_window_test.go — РУЧКА ОКНА ПЕРЕХОДА #1143.
//
// Утверждается четыре свойства, и ни одно не выводится из остальных:
//  1. умолчание — окно ЗАКРЫТО (незаданное не означает «принимать оба»);
//  2. неразборчивое значение — ОТКАЗ В СТАРТЕ, а не молчаливое закрытие:
//     оператор, написавший значение с опечаткой, обязан узнать об этом от
//     стража, а не от арендатора, которого он думал не сломать;
//  3. бессрочное окно НЕВЫРАЗИМО: ручка принимает мгновение, а не флажок;
//  4. объявленное мгновение доезжает до загруженной настройки.
package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// УМОЛЧАНИЕ — ОКНО ЗАКРЫТО. Fail-closed: незаданная ручка не означает
// «принимать оба вида».
func TestKeyMaterialWindow_UnsetIsClosed(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	until, err := cfg.APIServer.RegistryToken.KeyMaterialWindowUntil()
	require.NoError(t, err, "незаданная ручка — законное состояние, а не отказ")
	require.True(t, until.IsZero(),
		"умолчание обязано быть ЗАКРЫТЫМ окном: незаданное послабление, которое "+
			"по умолчанию открыто, не истекает никогда и не наблюдается ничем")
}

// НЕРАЗБОРЧИВОЕ ЗНАЧЕНИЕ — ОТКАЗ, А НЕ ДОГАДКА. Ни «принимать оба» (это
// открыло бы контроль опечаткой), ни молчаливое закрытие (оператор считал бы,
// что окно есть, и сломал бы арендаторов, которых собирался поберечь).
func TestKeyMaterialWindow_MalformedValueRefusesToStart(t *testing.T) {
	for name, raw := range map[string]string{
		"не мгновение вовсе":  "yes",
		"флажок":              "true",
		"бессрочно":           "never",
		"одна дата без зоны":  "2026-09-01",
		"пустая длительность": "720h",
	} {
		t.Run(name, func(t *testing.T) {
			c := config.RegistryTokenConfig{
				Endpoint:                  "tcp://0.0.0.0:9096",
				Service:                   "registry.kacho.local",
				KeyMaterialWindowUntilRaw: raw,
			}
			_, err := c.KeyMaterialWindowUntil()
			require.Error(t, err,
				"неразборчивое значение обязано отказывать: догадка в любую сторону "+
					"даёт посадку, которой оператор не выбирал")
			require.Contains(t, err.Error(), "key-material-window-until",
				"отказ обязан называть НАСТРОЙКУ — иначе оператор ищет вслепую: %v", err)

			require.Error(t, c.Validate(config.ClientTokenConfig{}),
				"страж старта обязан подхватывать тот же отказ: разобранное только на "+
					"пути запроса означает, что процесс поднялся с настройкой, которой нет")
		})
	}
}

// БЕССРОЧНОЕ ОКНО НЕВЫРАЗИМО — это и есть самоистечение ручки. Положительный
// контроль стоит рядом: годное мгновение обязано приниматься, иначе «всё
// отвергается» зеленело бы на ручке, не принимающей ничего.
func TestKeyMaterialWindow_DeclaredInstantIsParsedAndUnboundedIsUnexpressible(t *testing.T) {
	const declared = "2026-09-30T00:00:00Z"
	c := config.RegistryTokenConfig{
		Endpoint:                  "tcp://0.0.0.0:9096",
		Service:                   "registry.kacho.local",
		KeyMaterialWindowUntilRaw: declared,
	}

	until, err := c.KeyMaterialWindowUntil()
	require.NoError(t, err, "годное мгновение обязано приниматься")
	require.Equal(t, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), until.UTC())
	require.NoError(t, c.Validate(config.ClientTokenConfig{}))
}

// ИМЯ ENV, обещанное оператору, обязано менять исход загрузки — по образцу
// env_names_documented_test.go: имена ENV этого сервиса не встречаются в коде
// литералами, поэтому переименование ключа молча отвязывает документированную
// ручку.
func TestDocumentedEnvName_KeyMaterialWindowUntil(t *testing.T) {
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__KEY_MATERIAL_WINDOW_UNTIL", "2026-09-30T00:00:00Z")

	cfg, err := config.Load("")
	require.NoError(t, err)

	until, err := cfg.APIServer.RegistryToken.KeyMaterialWindowUntil()
	require.NoError(t, err)
	require.False(t, until.IsZero(),
		"ENV KANAME_API_SERVER__REGISTRY_TOKEN__KEY_MATERIAL_WINDOW_UNTIL обязана "+
			"менять исход загрузки — иначе документированной ручки не существует")
}
