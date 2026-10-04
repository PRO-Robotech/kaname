// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_identity_file_only_test.go — ключ `authn.service-identity` живёт
// ТОЛЬКО в файле (полоса K5; замысел З13 «Форма одна — файл; окружение её не
// перекрывает», CX1-105; приёмка NTF-1 Р2 п.2, NTF1-J05).
//
// Значение — список пар, и поле этой формы само добавило бы в выводимое
// множество законные `KANAME_AUTHN__SERVICE_IDENTITY__METHODS` и
// `…__SERVICES`: таблица SAN служебного субъекта задавалась бы окружением пода
// мимо рендера и гейта J05, и реплики одного рендера несли бы разные таблицы.
//
// Порядок несущий: фикстура (законный файл без ключа стартует) → близнец
// (тот же файл с ключом стартует — ключ известен декодеру) → отрицание
// (переменная, выведенная из ключа, — отказ, называющий её и ключ «только
// файл»). На дереве, где декодер ключа не знает, отрицание зеленело бы
// даром — отказом «неизвестной переменной»; поэтому оно требует текста,
// которого общий отказ не производит, и стоит после близнеца.
package config_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

const (
	serviceIdentityKey      = "authn.service-identity"
	serviceIdentityMethods  = "authn.service-identity.methods"
	serviceIdentityServices = "authn.service-identity.services"
)

// serviceIdentityFile — законный файл близнеца strictTwinConfig плюс
// согласный ключ: ровно один добавленный ключ.
const serviceIdentityFile = strictTwinConfig + `  service-identity:
    methods:
      - kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend
    services:
      - san: spiffe://kacho.cloud/ns/kacho/sa/kacho-notify
        name: notify
`

func TestNTF1K5_ServiceIdentityIsAFileOnlyKey(t *testing.T) {
	t.Run("фикстура: законный файл без ключа стартует", func(t *testing.T) {
		_, err := config.Load(writeConfig(t, strictTwinConfig))
		require.NoError(t, err, "фикстура сломана: близнец без ключа не загрузился")
	})

	t.Run("ключ известен декодеру, а его имена выведены из пространства `__`", func(t *testing.T) {
		keys := config.DecoderKeys()
		for _, k := range []string{serviceIdentityMethods, serviceIdentityServices} {
			require.True(t, slices.Contains(keys, k), "декодер не знает ключа %s (ключей декодера %d)", k, len(keys))
		}
		names := config.NestedEnvNames()
		for _, k := range []string{serviceIdentityMethods, serviceIdentityServices} {
			require.NotContains(t, names, config.EnvNameOfKey(k),
				"ключ «только файл» дал законное имя окружения: переменная перекрыла бы файл")
		}
	})

	t.Run("близнец: тот же файл с ключом стартует", func(t *testing.T) {
		_, err := config.Load(writeConfig(t, serviceIdentityFile))
		require.NoError(t, err)
	})

	for _, key := range []string{serviceIdentityMethods, serviceIdentityServices} {
		name := config.EnvNameOfKey(key)
		t.Run("переменная "+name+" при согласном файле — отказ старта", func(t *testing.T) {
			t.Setenv(name, "kaname.cloud.iam.v1.InternalIAMService/Check")
			_, err := config.Load(writeConfig(t, serviceIdentityFile))
			require.Error(t, err, "переменная принята и перекрыла бы файл")
			require.Contains(t, err.Error(), name, "отказ обязан назвать переменную")
			require.Contains(t, err.Error(), serviceIdentityKey,
				"отказ обязан назвать ключ «только файл», а не сказать «неизвестная переменная»")
		})
	}
}
