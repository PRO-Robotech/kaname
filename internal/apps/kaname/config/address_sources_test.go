// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// ОБЪЯВЛЕН ЛИ АДРЕС БАЗЫ НАСТРОЙКОЙ, А НЕ УМОЛЧАНИЕМ (#532).
//
// Точка наката читает ту же конфигурацию, что служба, и сверх неё — два своих
// источника адреса. Отказ «адрес объявлен дважды» у неё судит, ОБЪЯВИЛ ли
// оператор адрес в конфигурации службы: у ключа есть умолчание, и строка
// подключения из конфигурации непуста ВСЕГДА — по ней объявление не отличить
// от его отсутствия. Отличает его провенанс, который записывает сама загрузка:
// ключ в файле, переменная полного адреса, ручки по полям.
//
// Ответ — ИМЕНА источников, а не значения: значения несут пароль базы.

func clearServiceAddressEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"KANAME_REPOSITORY__POSTGRES__URL",
		"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME",
	} {
		t.Setenv(name, "")
		require.NoError(t, os.Unsetenv(name))
	}
}

func TestAddressSources_DefaultIsNotADeclaration(t *testing.T) {
	clearServiceAddressEnv(t)

	cfg, sources, err := config.LoadWithAddressSources("")
	require.NoError(t, err)
	require.NotEmpty(t, cfg.MigrateDSN(), "предпосылка: умолчание даёт непустую строку подключения")
	require.Empty(t, sources,
		"адрес не объявлен ни одним источником — умолчание объявлением не считается")
}

func TestAddressSources_NamesTheFileKey(t *testing.T) {
	clearServiceAddressEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("repository:\n  postgres:\n    url: \"postgres://iam@pg:5432/kaname\"\n"), 0o600))

	_, sources, err := config.LoadWithAddressSources(path)
	require.NoError(t, err)
	require.Len(t, sources, 1)
	require.Contains(t, sources[0], "repository.postgres.url")
}

func TestAddressSources_FileWithoutTheKeyIsNotADeclaration(t *testing.T) {
	clearServiceAddressEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("repository:\n  postgres:\n    max-conns: 4\n"), 0o600))

	_, sources, err := config.LoadWithAddressSources(path)
	require.NoError(t, err)
	require.Empty(t, sources,
		"файл объявляет соседний ключ секции, а не адрес — объявления адреса нет")
}

func TestAddressSources_NamesTheURLVariable(t *testing.T) {
	clearServiceAddressEnv(t)
	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", "postgres://iam:pw@pg:5432/kaname")

	_, sources, err := config.LoadWithAddressSources("")
	require.NoError(t, err)
	require.Equal(t, []string{"KANAME_REPOSITORY__POSTGRES__URL"}, sources)
}

func TestAddressSources_NamesEverySplitKnobThatIsSet(t *testing.T) {
	clearServiceAddressEnv(t)
	t.Setenv("KANAME_DB_HOST", "pg")
	t.Setenv("KANAME_DB_NAME", "kaname")

	_, sources, err := config.LoadWithAddressSources("")
	require.NoError(t, err)
	require.Equal(t, []string{"KANAME_DB_HOST", "KANAME_DB_NAME"}, sources)
}
