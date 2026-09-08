// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// Имена ENV этого сервиса НЕ ВСТРЕЧАЮТСЯ В КОДЕ КАК ЛИТЕРАЛЫ — они выводятся
// viper'ом из пути ключа конфигурации: префикс `KANAME`, точка → `__`,
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
	t.Setenv("KANAME_API_SERVER__METRICS_ENDPOINT", "tcp://127.0.0.1:19099")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, "127.0.0.1:19099", cfg.APIServer.MetricsListenAddress(),
		"ENV KANAME_API_SERVER__METRICS_ENDPOINT напечатан в документации "+
			"установки как ручка адреса /metrics — она обязана менять исход загрузки")
}

// Положительный контроль отрицания: плоская форма имени (без `__`) ручкой НЕ
// является. Если этот тест однажды покраснеет — значит завели второй способ
// задать одно и то же значение, и документация обязана сказать, какой из них
// главный (`code-authoring`: значение выразимо ровно одним способом).
func TestFlatEnvName_MetricsEndpoint_IsNotAKnob(t *testing.T) {
	t.Setenv("KANAME_METRICS_ENDPOINT", "tcp://127.0.0.1:19098")

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
	t.Setenv("KANAME_REPOSITORY__POSTGRES__URL", dsn)

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, dsn, cfg.Repository.Postgres.URL,
		"ENV KANAME_REPOSITORY__POSTGRES__URL напечатан в документации установки "+
			"как альтернатива по-полям — она обязана менять исход загрузки")
}

// ─────────────────────────────────────────────────────────────────────────────
// ОПЫТ ПО ТРЁМ ВЕЛИЧИНАМ, КОТОРЫЕ НАЗЫВАЕТ ТЕКСТ ОТКАЗА (задача #2040)
//
// Класс держит гейт `TestRefusalNamedEnvVarReachesItsField`; здесь — три
// поимённых опыта, потому что у каждой величины СВОЙ наблюдаемый исход, и гейт
// класса про исход стража не утверждает: он спрашивает лишь «изменилось ли
// что-нибудь». Того, ради чего оператор задаёт переменную, — «страж пропускает» —
// добивается только опыт по величине.
//
// Двум из трёх опыт ставит таблица обязательных величин
// (`TestRequiredSettings_TableCannotLie`, Т2: полный профиль, собранный
// ОБЪЯВЛЕННЫМИ путями, проходит стража целиком). Третья — опт-ин стенда — в
// таблицу не входит: без неё служба ПУСКАЕТСЯ, и требовать её значило бы
// объявить обязательным то, что обязательным не является. Поэтому её опыт
// стоит здесь.

// Опт-ин стенда доезжает до поля И СНИМАЕТ ОТКАЗ, ради которого объявлен.
//
// Отказ стража круга отправителей называет эту переменную дословно. До задачи
// #2040 у ключа не было ни умолчания, ни привязки: оператор стенда делал ровно
// то, что говорит отказ, и получал тот же отказ.
func TestDevOptInEnvName_TrustAnyForwarder(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	// Отрицательный контроль: на стенде с пустым кругом и без опт-ина страж
	// отказывает. Без него утверждение ниже зеленело бы на профиле, который
	// страж и так пропускает.
	clearOwnEnv()
	t.Setenv("KANAME_AUTHN__MODE", "dev")
	before, err := config.Load("")
	if err != nil {
		t.Fatalf("профиль стенда не загружается: %v", err)
	}
	if !mentions(refusals(before), "trusted-forwarder") {
		t.Fatalf("страж не отказал на пустом круге БЕЗ опт-ина — опыт ниже беспредметен, "+
			"отказы: %v", refusals(before))
	}

	clearOwnEnv()
	t.Setenv("KANAME_AUTHN__MODE", "dev")
	t.Setenv("KANAME_AUTHN__TRUST_ANY_FORWARDER", "true")
	after, err := config.Load("")
	if err != nil {
		t.Fatalf("профиль стенда с опт-ином не загружается: %v", err)
	}
	if !after.AuthN.TrustAnyForwarder {
		t.Fatalf("KANAME_AUTHN__TRUST_ANY_FORWARDER=true до поля не доехала: " +
			"текст отказа называет эту переменную, и оператор стенда, выполнивший названное, " +
			"получит тот же отказ")
	}
	if got := refusals(after); mentions(got, "trusted-forwarder") {
		t.Fatalf("опт-ин доехал до поля, а отказ круга остался — переменная названа отказом "+
			"и его не снимает: %v", got)
	}
}

// Тот же замок для круга отправителей: величина, которую нельзя доставить
// никаким другим объявлением, обязана доезжать именем, названным отказом.
func TestDocumentedEnvName_TrustedForwarderSANs(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	const san = "spiffe://kacho.example/ns/kacho/sa/kacho-api-gateway"
	clearOwnEnv()
	t.Setenv("KANAME_AUTHN__TRUSTED_FORWARDER_SANS", san)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("загрузка: %v", err)
	}
	if len(cfg.AuthN.TrustedForwarderSANs) != 1 || cfg.AuthN.TrustedForwarderSANs[0] != san {
		t.Fatalf("круг отправителей не собрался из переменной, названной текстом отказа: %#v",
			cfg.AuthN.TrustedForwarderSANs)
	}
	if got := refusals(cfg); mentions(got, "trusted-forwarder-sans") {
		t.Fatalf("круг сужен переменной, а страж на него всё ещё отказывает: %v", got)
	}
}

// И для имени чужой службы докерной полосы. Отказ теперь называет переменную
// прямо — прежде он называл только координату ключа и профильное объявление,
// и оператору, ставящему iam отдельно, следующий шаг восстановить было нечем.
func TestDocumentedEnvName_RegistryTokenService(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	clearOwnEnv()
	t.Setenv("KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE", "kacho-registry")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("загрузка: %v", err)
	}
	if got := cfg.APIServer.RegistryToken.TokenService(); got != "kacho-registry" {
		t.Fatalf("имя службы реестра не доехало до поля: %q", got)
	}
	if got := refusals(cfg); mentions(got, "registry-token.service is not declared") {
		t.Fatalf("имя объявлено переменной, а страж на него всё ещё отказывает: %v", got)
	}
}

// ПРИВЯЗКА ОПТ-ИНА НЕ РАСШИРИЛА ПОВЕРХНОСТЬ: в боевом режиме он по-прежнему не
// действует, каким бы путём его ни задали.
//
// Утверждение стоит здесь, а не подразумевается: до #2040 переменная не доезжала
// до поля вовсе, и «в бою не действует» держалось в том числе этим — то есть
// защитой, которой никто не выбирал. Привязка снимает её, и остаётся только та,
// которую выбрали: страж круга отправителей читает опт-ин лишь вне боевого
// режима.
func TestDevOptInIsStillIgnoredInProduction(t *testing.T) {
	saved := snapshotEnv()
	defer restoreEnv(saved)

	clearOwnEnv()
	t.Setenv("KANAME_AUTHN__MODE", "production")
	t.Setenv("KANAME_AUTHN__TRUST_ANY_FORWARDER", "true")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("боевой профиль с опт-ином не загружается: %v", err)
	}
	// Положительный контроль: величина ДОЕХАЛА до поля. Без него отрицание ниже
	// зеленело бы ровно на том дефекте, который задача #2040 и чинила.
	if !cfg.AuthN.TrustAnyForwarder {
		t.Fatalf("опт-ин не доехал до поля — отрицание ниже беспредметно")
	}
	if !mentions(refusals(cfg), "trusted-forwarder-sans") {
		t.Fatalf("боевой режим принял пустой круг отправителей при заданном опт-ине: "+
			"переменной окружения оказалось довольно, чтобы снять защиту на развёрнутом стенде. "+
			"отказы: %v", refusals(cfg))
	}
}
