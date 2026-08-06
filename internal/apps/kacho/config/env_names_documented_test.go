// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// Имена ENV этого сервиса НЕ ВСТРЕЧАЮТСЯ В КОДЕ КАК ЛИТЕРАЛЫ — они выводятся
// viper'ом из пути ключа конфигурации: префикс `KACHO_IAM`, точка → `__`,
// дефис → `_` (см. load.go, `SetEnvPrefix`+`SetEnvKeyReplacer`+`AutomaticEnv`).
//
// Следствие, ради которого заведён этот файл: **имя, которое документация
// обещает оператору, не имеет в дереве ни одного читателя** — ни одна строка
// кода его не упоминает, поэтому переименование ключа конфигурации молча
// отвязывает документированную ручку, и ни сборка, ни тесты этого не замечают.
// Ровно тот класс, что и «ручка, объявленная и никем не читаемая»: контроль
// на вид есть, а предмета у него нет.
//
// Проба фиксирует ИСХОД, а не объявление: ставит переменную ровно под тем
// именем, которое напечатано в документации, и требует, чтобы загруженная
// конфигурация изменилась. Значения нарочно не-дефолтные — совпадение с
// дефолтом сделало бы утверждение тождественно истинным.
//
// Отрицание идёт В ПАРЕ с положительным контролем: соседний тест требует, чтобы
// имя БЕЗ двойных подчёркиваний (плоская форма, которую легко написать по
// привычке) на конфигурацию НЕ влияло. Без этой половины проба зеленела бы на
// любом имени и ничего не сужала.
func TestDocumentedEnvName_MetricsEndpoint(t *testing.T) {
	t.Setenv("KACHO_IAM_API_SERVER__METRICS_ENDPOINT", "tcp://127.0.0.1:19099")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, "127.0.0.1:19099", cfg.APIServer.MetricsListenAddress(),
		"ENV KACHO_IAM_API_SERVER__METRICS_ENDPOINT напечатан в документации "+
			"установки как ручка адреса /metrics — она обязана менять исход загрузки")
}

// Положительный контроль отрицания: плоская форма имени (без `__`) ручкой НЕ
// является. Если этот тест однажды покраснеет — значит завели второй способ
// задать одно и то же значение, и документация обязана сказать, какой из них
// главный (`code-authoring`: значение выразимо ровно одним способом).
func TestFlatEnvName_MetricsEndpoint_IsNotAKnob(t *testing.T) {
	t.Setenv("KACHO_IAM_METRICS_ENDPOINT", "tcp://127.0.0.1:19098")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, "0.0.0.0:9095", cfg.APIServer.MetricsListenAddress(),
		"плоское имя без `__` ручкой не является: путь ключа api-server.metrics-endpoint "+
			"выводит имя с двойным подчёркиванием, и второго входа у значения нет")
}

// Тот же замок для DSN: документация установки называет полный DSN одной
// строкой именно в выведенной форме.
func TestDocumentedEnvName_PostgresURL(t *testing.T) {
	const dsn = "postgres://u:p@127.0.0.1:5432/db?sslmode=require"
	t.Setenv("KACHO_IAM_REPOSITORY__POSTGRES__URL", dsn)

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, dsn, cfg.Repository.Postgres.URL,
		"ENV KACHO_IAM_REPOSITORY__POSTGRES__URL напечатан в документации установки "+
			"как альтернатива по-полям — она обязана менять исход загрузки")
}
