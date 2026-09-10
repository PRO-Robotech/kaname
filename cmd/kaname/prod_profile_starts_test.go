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
//	(set KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE=true with its cert/key)
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
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
	//
	// Зовутся САМИ стражи, а не повторяются их условия. Здесь стояли два
	// собственных утверждения про gRPC-слушатели — второе место об одном
	// предмете, расходящееся молча: подъём обзавёлся бы новым условием, а
	// утверждения о нём не знали бы (задача #2514).
	require.NoError(t, requireGRPCListenerMTLS(productionMode, mtlsCfg),
		"боевой профиль не проходит стража старта gRPC-слушателей: объявленная посадка "+
			"неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
	require.NoError(t, requireRegistryTokenTLS(productionMode, registryTokenAddr, mtlsCfg),
		"боевой профиль не проходит стража старта докерной полосы: объявленная посадка неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")

	// ── ТРАНСПОРТ ОСТАЛЬНЫХ HTTP-РЁБЕР ──────────────────────────────────────
	//
	// Адреса берутся у САМОГО процесса (`config.RegisterDefaults`), а не
	// выписываются: все три непусты умолчанием, поэтому слушатели поднимаются
	// ВСЕГДА — и профиль, не объявивший их транспорт, ставит службу открытым
	// текстом. Ручки этих рёбер задавал зонтичный чарт монорепо; у отдельно
	// поставленной службы его нет.
	internalRESTAddr := httpEdgeAddr(t, values, defaults, "api-server.internal-rest-endpoint",
		"apiServer", "internalRestEndpoint")
	restAddr := httpEdgeAddr(t, values, defaults, "api-server.rest-endpoint",
		"apiServer", "restEndpoint")
	jwksProxyAddr := httpEdgeAddr(t, values, defaults, "api-server.jwks-proxy.endpoint",
		"apiServer", "jwksProxy", "endpoint")
	publicGRPCAddr := httpEdgeAddr(t, values, defaults, "api-server.endpoint",
		"apiServer", "endpoint")
	internalGRPCAddr := httpEdgeAddr(t, values, defaults, "api-server.internal-endpoint",
		"apiServer", "internalEndpoint")
	httpEdges := iamHTTPEdges(
		httpEdgeAddr(t, values, defaults, "authn.hooks-http-endpoint",
			"authn", "hooksHttpEndpoint"),
		httpEdgeAddr(t, values, defaults, "api-server.metrics-endpoint",
			"apiServer", "metricsEndpoint"),
		jwksProxyAddr,
		// Адрес фронтов профиль объявляет ПОРТОМ, и шаблон выводит эндпоинт из
		// него же. Читать здесь `apiServer.restEndpoint` значило бы судить путь,
		// которым адрес не приходит: у этих рёбер умолчания процесса НЕТ (Р5),
		// поэтому проба получила бы пустое и не судила бы их вовсе — проверка с
		// формой, но без предмета.
		restAddr,
		internalRESTAddr,
		mtlsCfg,
	)
	require.NotEmpty(t, httpEdges, "перечень HTTP-рёбер пуст — вердикт беспредметен")
	// ПРЕДМЕТ КАЖДОГО РЕБРА, а не только непустота перечня. Ребро с пустым
	// адресом страж пропускает by construction («слушателя нет — судить нечего»),
	// поэтому ребро, чей адрес профиль не объявил, проходит проверку МОЛЧА и
	// неотличимо от объявленного верно. Именно так и было с фронтами: их адрес
	// приходит из порта, а не из ключа эндпоинта, и первая редакция читала не тот
	// путь — вердикт был бы о пяти рёбрах из семи.
	judged := 0
	for _, e := range httpEdges {
		if e.addr != "" {
			judged++
		}
	}
	require.Equal(t, len(httpEdges), judged,
		"боевой профиль объявил адрес не у всех HTTP-рёбер: рёбра с пустым адресом "+
			"страж пропускает, то есть о них вердикта НЕТ — «нарушений нет» тут "+
			"неотличимо от «не судили»")
	t.Logf("осмотрено: HTTP-рёбер в перечне %d, из них с объявленным адресом %d",
		len(httpEdges), judged)
	declaredPlaintext, edgeErr := requireHTTPEdgeTLS(productionMode, httpEdges)
	require.NoError(t, edgeErr,
		"боевой профиль не проходит стража транспорта HTTP-рёбер: объявленная посадка неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
	// ОБЪЯВЛЕННЫЕ ИСКЛЮЧЕНИЯ НАЗЫВАЮТСЯ ЧИСЛОМ, а не подразумеваются. Профиль
	// ЭТОГО чарта их не объявляет: у отдельно поставленной службы вызывающий
	// слушателя вебхуков не тот, ради которого исключение заводилось, и молча
	// унаследовать его она не вправе. Пустой перечень здесь — утверждение, а не
	// умолчание: вырастет он — проба скажет, чем именно.
	require.Empty(t, declaredPlaintext,
		"боевой профиль этого чарта объявил исключение открытого текста: %v", declaredPlaintext)
	t.Logf("объявленных исключений открытого текста: %d", len(declaredPlaintext))

	// ── РУБЕЖ ВНУТРЕННЕГО REST-ФРОНТА ───────────────────────────────────────
	//
	// Транспорт у этого ребра проверен выше, и его мало: шифрование и
	// аутентификация СЕРВЕРА не говорят о вызывающем ничего. У этой поверхности
	// рубеж бывает только транспортный — фронт своего не заводит и к собственному
	// слушателю идёт СВОИМ удостоверением, — поэтому режим проверки клиента
	// судится отдельным стражем и здесь исполняется дословно тот же (#2335).
	require.NotEmpty(t, internalRESTAddr,
		"боевой профиль не объявил адреса внутреннего REST-фронта: страж рубежа "+
			"пропускает поверхность с пустым адресом by construction, и вердикта о ней "+
			"не будет вовсе")
	require.NoError(t, requireInternalRESTMutualClientAuth(productionMode, internalRESTAddr, mtlsCfg),
		"боевой профиль не проходит стража рубежа внутреннего REST-фронта: объявленная "+
			"посадка неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
	t.Logf("рубеж внутреннего REST-фронта: режим %q, требует клиентского сертификата: %v",
		mtlsCfg.InternalRESTClientAuthModeValue(), mtlsCfg.InternalRESTRequiresClientCert())

	// ── АВТОРИТЕТ ОТЗЫВА НАШИХ ТОКЕНОВ ──────────────────────────────────────
	//
	// Предмет приносит СВОЯ ЧЕКАНКА, а не выбор посадки: включив её, профиль
	// получает поверхность, которой присылают предъявленный токен, — и она
	// обязана уметь установить, кто спрашивает. Условие жило встроенной ветвью
	// подъёма и потому не судилось здесь ничем: перечисление стражей по именам
	// оставляло дверь открытой ровно для безымянного условия (задача #2476).
	mintingRaw, mintingDeclared := dig(values, "authn", "tokenSigning", "enabled")
	ownMinting := false
	if mintingDeclared {
		ownMinting, ok = mintingRaw.(bool)
		require.True(t, ok, "своя чеканка объявлена не булевым: %T", mintingRaw)
	}
	require.NoError(t,
		requireRevocationAuthorityCallerAuth(ownMinting, jwksProxyAddr, mtlsCfg),
		"боевой профиль не проходит стража авторитета отзыва: объявленная посадка "+
			"неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
	t.Logf("своя чеканка: %v · слушатель зеркала ключей %q, режим проверки клиента %q, устанавливает вызывающего: %v",
		ownMinting, jwksProxyAddr, mtlsCfg.JWKSProxyClientAuthModeValue(),
		mtlsCfg.JWKSProxyVerifiesCaller())

	// ── РАЗЛИЧИМОСТЬ АДРЕСОВ ЧЕТЫРЁХ ПОВЕРХНОСТЕЙ ───────────────────────────
	require.NoError(t,
		requireDistinctSurfaceAddrs(publicGRPCAddr, internalGRPCAddr, restAddr, internalRESTAddr),
		"боевой профиль не проходит стража различимости адресов поверхностей")

	// ── УДОСТОВЕРЕНИЕ ФРОНТА ДЛЯ СОБСТВЕННОГО СЛУШАТЕЛЯ ─────────────────────
	require.NoError(t,
		requireRESTUpstreamCredential(productionMode, restAddr, internalRESTAddr, mtlsCfg),
		"боевой профиль не проходит стража удостоверения фронта: объявленная посадка "+
			"неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")

	// ── ПАРА «АДРЕС + УДОСТОВЕРЕНИЕ» АДМИНИСТРАТИВНОГО КОНТУРА ──────────────
	//
	// Адрес приходит картой `env` профиля (она уже разложена в окружение выше),
	// а ВЫБОР способа — ключом настроек: он уезжает поду файлом, а не
	// переменной, поэтому читается из значений профиля, а не из окружения.
	// Прочитать его отсюда переменной значило бы судить путь, которым величина
	// не приходит (задача #2471).
	adminAuth := ""
	if raw, found := dig(values, "authn", "providerAdminAuth"); found {
		adminAuth = valueAsString(t, "authn.providerAdminAuth", raw)
	}
	adminHop := config.AuthNConfig{ProviderAdminAuth: adminAuth}
	require.NoError(t, requireProviderAdminCredentialPair(adminHop),
		"боевой профиль не проходит стража пары административного контура: объявленная "+
			"посадка неисполнима — процесс не поднимется НИ ПРИ КАКОМ входе")
	t.Logf("административный контур: адрес %q · способ аутентификации %q",
		adminHop.DeclaredHydraAdminURL(), adminHop.ProviderAdminAuthValue())
}

// httpEdgeAddr — адрес слушателя: объявленный профилем либо умолчание процесса.
// Умолчание спрашивается у процесса, а не выписывается здесь: выписанное
// разошлось бы молча, и проба судила бы полосу, которой процесс не поднимает.
func httpEdgeAddr(t *testing.T, values map[string]any, defaults *viper.Viper,
	defaultKey string, chartPath ...string) string {
	t.Helper()
	endpoint := defaults.GetString(defaultKey)
	if declared, found := dig(values, chartPath...); found {
		endpoint = valueAsString(t, strings.Join(chartPath, "."), declared)
	}
	return config.ListenAddressOf(endpoint)
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
