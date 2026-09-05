// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_starts_test.go — боевой профиль чарта обязан пройти стражей
// СТАРТА, а не только проверку конфигурации.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ, И ПОЧЕМУ ЕГО НЕ ЗАКРЫВАЛА СОСЕДНЯЯ ПРОБА
//
// У чарта уже есть проба боевого профиля — `deploy/prod_profile_test.go`. Она
// зовёт `config.Config.Validate` и потому судит ровно то, что судит `Validate`.
// Но отказ старта производит НЕ ТОЛЬКО он: путь подъёма (`serve`) несёт
// собственные условия боевого режима, и они живут здесь, в пакете `main`, —
// значит для той пробы они недостижимы by construction, и её зелёное о них не
// высказывается вовсе.
//
// Расхождение не гипотетическое. Первая же попытка ПОДНЯТЬ чарт в кластере с
// боевым профилем дала отказ старта, при том что проба профиля была зелёной:
//
//	production mode requires TLS on the docker-token listener 0.0.0.0:9096
//	(set KACHO_IAM_REGISTRYTOKEN_SERVER_MTLS_ENABLE=true with its cert/key)
//
// Профиль поднимает докерную полосу (объявляет её издателя и адресата), адрес
// слушателя приходит умолчанием процесса (`tcp://0.0.0.0:9096`), а TLS этой
// полосы профиль не объявлял. Условие отказа от входа НЕ ЗАВИСИТ: профиль не
// поднимался НИ ПРИ КАКОМ значении — это объявленная и неисполнимая посадка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗДЕСЬ НЕТ ТАБЛИЦЫ УСЛОВИЙ — тот же довод, что у соседней пробы
//
// Соблазн выписать «условие → ручка» списком существует и здесь. Такой список
// есть второе место об одном предмете, и расходится он молча: путь подъёма
// обзаводится новым условием, а список о нём не знает и остаётся зелёным.
// Поэтому проба зовёт САМИ стражи — `requireRegistryTokenTLS` и тот же
// production-блок про оба слушателя, что стоит в `serve`. Появится у подъёма
// новое условие боевого режима — профиль покраснеет, ничего здесь не правя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОБА НЕ ДОКАЗЫВАЕТ — граница названа, чтобы её не выводил читатель
//
// Она НЕ поднимает под и не доказывает, что установка проходит в кластере: это
// третья категория, а не зелёное. Она доказывает ровно одно — что величины,
// объявленные профилем, УДОВЛЕТВОРЯЮТ стражам старта. Страж — первое, обо что
// разбивается боевая установка.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// chartDir — каталог чарта этой службы относительно пакета композиционного корня.
const chartDir = "../../deploy"

// startupProfiles — цепочка `-f`, которой ставится боевая посадка. Тот же
// порядок и те же имена, что у пробы профиля в каталоге чарта.
var startupProfiles = []string{"values.yaml", "values.prod.yaml"}

// mergeInto — наложение профиля поверх накопленного, по правилам helm: карта
// сливается вглубь, скаляр и список замещаются целиком.
func mergeInto(dst, src map[string]any) {
	for key, srcVal := range src {
		srcMap, srcIsMap := srcVal.(map[string]any)
		dstMap, dstIsMap := dst[key].(map[string]any)
		if srcIsMap && dstIsMap {
			mergeInto(dstMap, srcMap)
			continue
		}
		dst[key] = srcVal
	}
}

// dig — значение по пути в дереве значений; второй результат говорит, найдено ли.
func dig(values map[string]any, path ...string) (any, bool) {
	var cur any = values
	for _, seg := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = asMap[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func TestProductionProfileSatisfiesTheStartupGuards(t *testing.T) {
	values := map[string]any{}
	profilesRead := 0

	for _, name := range startupProfiles {
		path := filepath.Join(chartDir, name)
		raw, err := os.ReadFile(path)
		require.NoError(t, err, "профиль чарта не читается: %s", path)

		var profile map[string]any
		require.NoError(t, yaml.Unmarshal(raw, &profile), "профиль чарта не разбирается: %s", path)

		mergeInto(values, profile)
		profilesRead++
	}

	// Пустой обход — находка, а не идеал: «стражи довольны» обязано быть отличимо
	// от «профилей не прочитано ни одного».
	require.Equal(t, len(startupProfiles), profilesRead,
		"обход пуст: прочитано %d профилей из %d — вердикт беспредметен", profilesRead, len(startupProfiles))
	require.NotEmpty(t, values, "обход пуст: значения чарта пусты — вердикт беспредметен")

	// ── ПОСАДКА БЕЗОПАСНОСТИ ────────────────────────────────────────────────
	// Читается тем же ключом, что объявляет чарт (`authMode` в корне значений).
	authModeRaw, ok := dig(values, "authMode")
	require.True(t, ok, "профиль не объявляет посадку безопасности (`authMode`) — судить нечего")
	authMode, ok := authModeRaw.(string)
	require.True(t, ok, "посадка безопасности объявлена не строкой: %T", authModeRaw)
	productionMode := strings.HasPrefix(authMode, "production")
	require.True(t, productionMode,
		"профиль объявляет посадку %q — это не боевая посадка, и стражи боевого режима на ней молчат: проба стала бы вакуумной", authMode)

	// ── ПОСАДКА ТРАНСПОРТА ──────────────────────────────────────────────────
	// Собирается ТЕМ ЖЕ загрузчиком, что зовёт композиционный корень: карта `env`
	// профиля отдаётся поду дословно, поэтому процесс увидит ровно это окружение.
	envRaw, ok := dig(values, "env")
	require.True(t, ok, "профиль не объявляет карты переменных окружения — посадку транспорта собрать не из чего")
	envMap, ok := envRaw.(map[string]any)
	require.True(t, ok, "карта переменных окружения объявлена не картой: %T", envRaw)
	require.NotEmpty(t, envMap, "карта переменных окружения пуста — вердикт беспредметен")

	for name, value := range envMap {
		t.Setenv(name, strings.TrimSpace(strings.Trim(valueAsString(t, name, value), `"`)))
	}

	mtlsCfg, err := config.LoadMTLS()
	require.NoError(t, err, "посадка транспорта, объявленная профилем, не разбирается")

	// ── АДРЕС ДОКЕРНОЙ ПОЛОСЫ ───────────────────────────────────────────────
	// Умолчание берётся у САМОГО процесса (`config.RegisterDefaults`), а не
	// выписывается здесь: выписанное разошлось бы с умолчанием молча, и проба
	// судила бы полосу, которой процесс не поднимает, — либо молчала бы о той,
	// которую поднимает.
	defaults := viper.New()
	config.RegisterDefaults(defaults)
	endpoint := defaults.GetString("api-server.registry-token.endpoint")
	if declared, found := dig(values, "apiServer", "registryToken", "endpoint"); found {
		endpoint = valueAsString(t, "apiServer.registryToken.endpoint", declared)
	}
	registryTokenAddr := config.RegistryTokenConfig{Endpoint: endpoint}.ListenAddress()

	t.Logf(
		"перепись: профилей прочитано %d · переменных окружения объявлено %d · посадка %q · адрес докерной полосы %q",
		profilesRead, len(envMap), authMode, registryTokenAddr,
	)

	// ── СТРАЖИ СТАРТА, ДОСЛОВНО ТЕ ЖЕ, ЧТО В `serve` ────────────────────────
	require.True(t, mtlsCfg.InternalServerMTLS.Enable,
		"боевой режим требует взаимного TLS внутреннего слушателя (:9091): профиль его не объявляет, и процесс откажется стартовать")
	require.True(t, mtlsCfg.PublicServerMTLS.Enable,
		"боевой режим требует TLS публичного слушателя (:9090): профиль его не объявляет, и процесс откажется стартовать")
	require.NoError(t, requireRegistryTokenTLS(productionMode, registryTokenAddr, mtlsCfg),
		"боевой профиль не проходит стража старта докерной полосы: объявленная посадка неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
}

// valueAsString — значение профиля строкой. Числа и булевы в карте `env` чарт
// отдаёт поду в кавычках, поэтому здесь они приводятся так же.
func valueAsString(t *testing.T, key string, value any) string {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		require.Failf(t, "величина профиля не приводится к строке",
			"ключ %s несёт %T", key, value)
		return ""
	}
}
