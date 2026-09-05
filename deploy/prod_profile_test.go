// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_test.go — проба боевого профиля ЭТОГО чарта.
//
// # Зачем она есть
//
// Требование «отдельный клон iam поднимается в боевой посадке» до сих пор было
// НЕ С ЧЕМ прогнать: все боевые профили дерева принадлежат зонтичному чарту, а у
// чарта сервиса были только `values.yaml` и `values.dev.yaml`. Профиль есть
// объявление посадки; проба судит объявление.
//
// # Чем она НЕ является — граница названа первой, чтобы её не выводил читатель
//
// Она НЕ поднимает под и НЕ доказывает, что установка проходит в кластере: это
// «не выполнилось», третья категория, а не зелёное. Она доказывает ровно одно —
// что величины, объявленные профилем, УДОВЛЕТВОРЯЮТ стражу старта. Страж —
// первое, обо что разбивается боевая установка, и до этой пробы его вердикт о
// профиле чарта не спрашивал никто.
//
// # Почему тут нет ТАБЛИЦЫ условий стража
//
// Соблазн был: выписать «условие → ручка» списком. Такой список есть второе
// место об одном предмете, и расходится он молча — страж обзаводится новым
// условием, а список о нём не знает и остаётся зелёным. Поэтому проба зовёт САМ
// страж (`config.Config.Validate`), сам предикат шифрования до базы
// (`coredb.SSLModeFromDSN` + `SSLModeSecure` — те же две функции, что зовёт
// композиционный корень) и сам разбор посадки транспорта (`config.LoadMTLS`).
// Появится у стража новое условие — профиль покраснеет, ничего здесь не правя.
//
// # Что всё же приходится повторить, и чем это удержано
//
// Чарт кладёт часть величин в `config.yaml` (шаблон `templates/configmap.yaml`),
// а часть — переменными окружения (карта `env`, шаблон `templates/deployment.yaml`
// отдаёт её пода дословно). Проба обязана собрать ровно тот вход, что увидит
// процесс, поэтому переложение «ключ значений чарта → ключ конфигурации»
// повторяет шаблон. Это ЕДИНСТВЕННОЕ повторение, оно перечислено в
// `configBridge`, и его предпосылка проверяется отдельной пробой: каждый ключ
// переложения обязан встречаться в самом шаблоне. Перестанет шаблон его
// рендерить — переложение краснеет и называет ключ.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// chartProfiles — цепочка `-f`, которой ставится боевая посадка этого чарта.
// Тот же порядок, что у dev-цепочки (`values.yaml` + `values.dev.yaml`).
var chartProfiles = []string{"values.yaml", "values.prod.yaml"}

// configBridge — переложение «путь в значениях чарта → ключ конфигурации», как
// его делает `templates/configmap.yaml`.
//
// ЕДИНИЦА — ключ конфигурации, а не ключ значений: страж читает конфигурацию, и
// именно её надо собрать. Значение либо берётся из значений чарта по пути
// `valuePath`, либо вычисляется `derive` (шаблон кое-где склеивает строку —
// адрес слушателя из порта, строку подключения из полей базы).
type bridged struct {
	configKey string   // точечный путь ключа конфигурации
	valuePath []string // путь в дереве значений чарта; пуст, когда значение выводится
	derive    func(map[string]any) any
	omitEmpty bool // пустое значение шаблон не рендерит вовсе
}

var configBridge = []bridged{
	{configKey: "logger.level", valuePath: []string{"logger", "level"}},
	{configKey: "api-server.endpoint", derive: func(v map[string]any) any {
		return fmt.Sprintf("tcp://0.0.0.0:%v", at(v, "ports", "grpc"))
	}},
	{configKey: "api-server.internal-endpoint", derive: func(v map[string]any) any {
		return fmt.Sprintf("tcp://0.0.0.0:%v", at(v, "ports", "internalGrpc"))
	}},
	{configKey: "api-server.graceful-shutdown", valuePath: []string{"apiServer", "gracefulShutdown"}},
	{configKey: "api-server.registry-token.issuer", valuePath: []string{"apiServer", "registryToken", "issuer"}, omitEmpty: true},
	{configKey: "api-server.registry-token.service", valuePath: []string{"apiServer", "registryToken", "service"}, omitEmpty: true},
	{configKey: "repository.type", derive: func(map[string]any) any { return "POSTGRES" }},
	{configKey: "repository.postgres.url", derive: func(v map[string]any) any {
		return fmt.Sprintf("postgres://%v@%v:%v/%v",
			at(v, "db", "user"), at(v, "db", "host"), at(v, "db", "port"), at(v, "db", "name"))
	}},
	{configKey: "repository.postgres.max-conns", valuePath: []string{"repository", "postgres", "maxConns"}},
	{configKey: "repository.postgres.ssl-mode", valuePath: []string{"repository", "postgres", "sslMode"}},
	{configKey: "repository.postgres.password-from-env", derive: func(map[string]any) any { return "KACHO_IAM_DB_PASSWORD" }},
	{configKey: "authn.mode", valuePath: []string{"authMode"}},
	{configKey: "authn.identity-provider", valuePath: []string{"authn", "identityProvider"}, omitEmpty: true},
	{configKey: "authn.trusted-forwarder-sans", valuePath: []string{"authn", "trustedForwarderSANs"}, omitEmpty: true},
}

// restatedDeliberately — ручки боевого профиля, чьё СНЯТИЕ страж не замечает, и
// причина, по которой они всё равно объявлены.
//
// Перечень утверждается В ОБЕ СТОРОНЫ: запись, чью ручку страж начал читать,
// становится находкой и подлежит удалению. Иначе послабление переживает свой
// предмет и начинает прощать ту ручку, которая в него следующей провалится.
var restatedDeliberately = map[string]string{
	"authMode": "базовые значения чарта уже несут production, поэтому снятие этой строки " +
		"посадку не роняет. Строка стоит затем, чтобы будущая правка умолчания чарта не " +
		"уронила посадку МОЛЧА: профиль называет её сам",
	"apiServer.registryToken.issuer": "встроенное умолчание процесса непусто (локальное имя), " +
		"поэтому страж на снятии молчит. Величина объявлена потому, что это realm, который " +
		"докерный клиент слышит от нас: оставленное умолчание отправило бы его на хост, " +
		"которого у этой установки нет",
	"env.KACHO_IAM_REGISTRYTOKEN_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireRegistryTokenTLS в cmd/kacho-iam), а не в Config.Validate, " +
		"который зовёт эта проба, — то есть недостижим отсюда by construction: пакет main не " +
		"импортируется. Снятие ручки роняет не посадку, а СТАРТ: слушатель докерной полосы " +
		"поднимается умолчанием процесса, и боевой режим отказывается пускать его открытым " +
		"текстом. Держит это TestProductionProfileSatisfiesTheStartupGuards в " +
		"services/iam/cmd/kacho-iam — она зовёт того самого стража. Соседние две ручки этой " +
		"ноги (CERTFILE/KEYFILE) записи не требуют: их снятие ловит разбор посадки транспорта, " +
		"достижимый отсюда",
}

// secretStandIns — ЗАМЕНИТЕЛИ величин, которые живут в объекте Secret и в дерево
// не попадают ни разу.
//
// Профиль объявляет ИМЯ переменной и координату в секрете; ЗНАЧЕНИЕ приезжает в
// под из объекта, которого в git нет. Проба судит объявление, поэтому подставляет
// синтаксически годный заменитель — иначе страж отказывал бы на пустой величине,
// и проба меряла бы отсутствие секрета, а не полноту профиля.
//
// ГРАНИЦА НАЗВАНА ПРЯМО: заменитель годен ВСЕГДА, поэтому проба не может поймать
// негодную настоящую величину. Ловить там нечего — настоящей величины в профиле
// нет by construction; проба утверждает, что объявление о ней СТОИТ.
//
// Перечень утверждается в обе стороны: заменитель без объявленной переменной —
// находка, а не запас.
var secretStandIns = map[string]string{
	"KACHO_IAM_HOOK_TOKEN": "stand-in-not-a-secret",
	// Ключ обёртки разбирается как шестнадцатеричная строка объявленной длины,
	// поэтому заменитель обязан быть годен по форме.
	"KACHO_IAM_JWKS_ENC_KEY": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
}

// ── несущая проба ────────────────────────────────────────────────────────────

func TestProdProfile_SatisfiesTheBootGuard(t *testing.T) {
	merged := mergeChartProfiles(t, chartProfiles)

	envCount, keyCount, posture := evaluatePosture(t, merged)
	require.NoError(t, posture,
		"боевой профиль чарта не удовлетворяет стражу старта: под с этими значениями "+
			"не поднимется — процесс откажет в пуске ещё до первого слушателя")

	t.Logf("перепись: профилей в цепочке %d · ключей конфигурации %d · переменных окружения %d",
		len(chartProfiles), keyCount, envCount)
}

// TestProdProfile_TheGuardIsLiveWithoutIt — отрицательный контроль несущей
// пробы: без боевого профиля страж ОБЯЗАН отказать.
//
// Без этой половины зелёное выше не значит ничего: страж, разучившийся падать,
// на любом профиле выглядит довольным.
func TestProdProfile_TheGuardIsLiveWithoutIt(t *testing.T) {
	merged := mergeChartProfiles(t, []string{"values.yaml"})

	_, _, posture := evaluatePosture(t, merged)
	require.Error(t, posture,
		"одни базовые значения чарта прошли стража боевой посадки — значит зелёное "+
			"боевого профиля не доказывает ничего: падать стражу не на чем")
	t.Logf("отрицательный контроль: без боевого профиля страж отказал — %d упрёк(ов)",
		len(multierr.Errors(posture)))
}

// TestProdProfile_EveryKnobIsLoadBearing — вторая половина предиката: профиль
// падает, КОГДА РУЧКА ПРОПАЛА.
//
// Снимает по одной ручке боевого профиля и требует отказа посадки. Ручка, чьё
// снятие никто не замечает, — либо украшение (профиль обязан быть объявлением
// посадки, а не сборником пожеланий), либо признак того, что страж её не читает
// и она никогда не действовала.
func TestProdProfile_EveryKnobIsLoadBearing(t *testing.T) {
	prod := readChartProfile(t, "values.prod.yaml")
	knobs := leafPaths(prod, nil)
	require.NotEmpty(t, knobs, "боевой профиль не объявляет ни одной ручки — "+
		"перепись прочитала бы ноль и отчиталась успехом при любом содержимом")

	seenRestated := map[string]bool{}
	inSurface, outside := 0, 0
	for _, knob := range knobs {
		joined := strings.Join(knob, ".")
		if !inPostureSurface(knob) {
			outside++
			continue
		}
		inSurface++
		t.Run(joined, func(t *testing.T) {
			merged := mergeChartProfiles(t, chartProfiles)
			removeAt(merged, knob)
			_, _, posture := evaluatePosture(t, merged)

			if _, restated := restatedDeliberately[joined]; restated {
				seenRestated[joined] = true
				require.NoError(t, posture,
					"ручка %q числится восстановленной намеренно (страж её снятия не "+
						"замечает), но посадка без неё отказала — запись перечня лжёт "+
						"о предмете; удалите её", joined)
				return
			}
			require.Error(t, posture,
				"снятие ручки %q не уронило посадку, хотя ручка стоит на поверхности "+
					"посадки — либо страж её не читает вовсе и она не действовала ни "+
					"разу, либо она восстановлена намеренно и это надо СКАЗАТЬ: запись "+
					"в restatedDeliberately с причиной. Молчаливое украшение на этой "+
					"поверхности неотличимо от мёртвой ручки", joined)
		})
	}

	// Послабление живёт, пока у него есть предмет.
	for joined := range restatedDeliberately {
		require.True(t, seenRestated[joined],
			"перечень восстановленных намеренно называет %q, но такой ручки в боевом "+
				"профиле нет — запись пережила свой предмет и начнёт прощать ту ручку, "+
				"которая следующей провалится в неё", joined)
	}

	require.NotZero(t, inSurface,
		"ни одна ручка боевого профиля не попала в поверхность посадки — перепись "+
			"прочитала бы ноль и отчиталась успехом при любом содержимом")
	t.Logf("перепись: ручек боевого профиля %d · на поверхности посадки %d · вне её %d "+
		"(эксплуатационные — число реплик, образ, пределы; предметом этой пробы не являются) "+
		"· восстановленных намеренно %d",
		len(knobs), inSurface, outside, len(restatedDeliberately))
}

// inPostureSurface — принадлежит ли ручка ПОВЕРХНОСТИ ПОСАДКИ.
//
// Поверхность выводится из устройства чарта, а не выписывается перечнем условий
// стража: это карта переменных окружения, карта величин из секрета, материал TLS
// и те ключи значений, которые шаблон кладёт в файл настроек (`configBridge`).
// Всё прочее — эксплуатационные величины (число реплик, образ, пределы): они
// законны в боевом профиле и посадки не несут, поэтому предметом этой пробы не
// являются и в её вердикт не входят.
func inPostureSurface(knob []string) bool {
	switch knob[0] {
	case "env", "secrets", "tls":
		return true
	}
	for _, b := range configBridge {
		if len(b.valuePath) == 0 || len(b.valuePath) > len(knob) {
			continue
		}
		match := true
		for i, seg := range b.valuePath {
			if knob[i] != seg {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestConfigBridge_MirrorsTheChartTemplate — предпосылка переложения.
//
// Переложение верно ровно пока шаблон рендерит те же ключи. Проба судит ТЕКСТ
// шаблона, и это её граница: она отвечает на вопрос «ключ ещё рендерится», а не
// «рендерится тем же значением». Второй вопрос закрыт бы рендером, а рендер
// требует helm и потому пропускается ровно на той машине, где он нужен.
func TestConfigBridge_MirrorsTheChartTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("templates", "configmap.yaml"))
	require.NoError(t, err)
	text := string(raw)

	for _, b := range configBridge {
		segs := strings.Split(b.configKey, ".")
		leaf := segs[len(segs)-1] + ":"
		require.Contains(t, text, leaf,
			"переложение называет ключ конфигурации %q, а шаблон configmap.yaml его "+
				"больше не рендерит — переложение собирает вход, которого процесс не "+
				"увидит, и вердикт пробы относится к чужому дереву", b.configKey)
	}
	t.Logf("перепись: ключей переложения %d, шаблон прочитан (%d байт)", len(configBridge), len(raw))
}

// ── сборка входа и вердикт ───────────────────────────────────────────────────

// evaluatePosture собирает ровно тот вход, что увидит процесс, и возвращает
// сводный вердикт стражей боевой посадки.
//
// Три стража, и каждый зовётся САМ, а не пересказывается:
//   - `config.Config.Validate` — страж старта службы;
//   - `coredb.SSLModeFromDSN` + `SSLModeSecure` — ось шифрования до своей базы
//     (О8 центрального дескриптора посадки; те же две функции зовёт
//     композиционный корень, `cmd/kacho-iam/posture.go`);
//   - `config.LoadMTLS` + `MTLSConfig.Validate` — посадка транспорта обоих
//     слушателей (О8, поля PublicCreds/InternalCreds).
//
// Плюс одно утверждение о ДОСЯГАЕМОСТИ: файл, названный ручкой, обязан лежать
// под каталогом, который чарт монтирует. Путь к материалу, которого под не
// несёт, — объявленная и неисполнимая возможность.
func evaluatePosture(t *testing.T, merged map[string]any) (envCount, keyCount int, verdict error) {
	t.Helper()
	requireCleanEnv(t)

	cfgPath, keys := writeRenderedConfig(t, merged)
	envs := envEntries(merged)
	secretErr := applySecretStandIns(merged, envs)
	for k, v := range envs {
		t.Setenv(k, v)
	}

	cfg, loadErr := config.Load(cfgPath)
	if loadErr != nil {
		return len(envs), keys, fmt.Errorf("конфигурация не загрузилась: %w", loadErr)
	}

	var errs error
	errs = multierr.Append(errs, secretErr)
	errs = multierr.Append(errs, cfg.Validate())

	mode := coredb.SSLModeFromDSN(cfg.DSN())
	if !coredb.SSLModeSecure(mode) {
		errs = multierr.Append(errs, fmt.Errorf(
			"боевая посадка с sslmode=%q; допустимы %s (ось О8 центрального дескриптора)",
			mode, strings.Join(coredb.SecureSSLModes(), ", ")))
	}

	mtls, mtlsErr := config.LoadMTLS()
	switch {
	case mtlsErr != nil:
		errs = multierr.Append(errs, fmt.Errorf("посадка транспорта не разобралась: %w", mtlsErr))
	default:
		if !mtls.PublicServerMTLS.Enable {
			errs = multierr.Append(errs, fmt.Errorf(
				"боевая посадка с непроверенным транспортом публичного слушателя: "+
					"KACHO_IAM_PUBLIC_SERVER_MTLS_ENABLE не объявлен"))
		}
		if !mtls.InternalServerMTLS.Enable {
			errs = multierr.Append(errs, fmt.Errorf(
				"боевая посадка с непроверенным транспортом внутреннего слушателя: "+
					"KACHO_IAM_INTERNAL_SERVER_MTLS_ENABLE не объявлен; внутренний периметр не доверенный"))
		}
		errs = multierr.Append(errs, mtls.Validate())
		errs = multierr.Append(errs, filesAreMountable(merged, envs))
	}
	return len(envs), keys, errs
}

// applySecretStandIns кладёт в карту окружения заменители тех величин, что
// профиль объявил приезжающими из объекта Secret, и заодно судит САМО
// объявление: шаблон развёртывания отказывается рендерить координату без имени
// объекта и без ключа в нём.
func applySecretStandIns(merged map[string]any, envs map[string]string) error {
	declared, _ := merged["secrets"].(map[string]any)

	var errs error
	seen := map[string]bool{}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		coord, ok := declared[name].(map[string]any)
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"secrets.%s объявлен без координаты — шаблон развёртывания рендерить его откажет", name))
			continue
		}
		for _, field := range []string{"secretName", "secretKey"} {
			if v, _ := coord[field].(string); strings.TrimSpace(v) == "" {
				errs = multierr.Append(errs, fmt.Errorf(
					"secrets.%s.%s не задан — шаблон развёртывания рендерить координату "+
						"откажет, и переменная до пода не доедет вовсе", name, field))
			}
		}
		standIn, ok := secretStandIns[name]
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"профиль объявляет переменную %s приезжающей из секрета, а у пробы нет для "+
					"неё заменителя — вердикт о полноте профиля вынести не с чем", name))
			continue
		}
		if _, clash := envs[name]; clash {
			errs = multierr.Append(errs, fmt.Errorf(
				"переменная %s объявлена и в карте env, и в secrets — величина выразима "+
					"двумя способами, и какой из них действует, решает шаблон, а не оператор", name))
			continue
		}
		envs[name] = standIn
		seen[name] = true
	}

	// Заменитель живёт, пока у него есть предмет.
	for name := range secretStandIns {
		if !seen[name] {
			errs = multierr.Append(errs, fmt.Errorf(
				"у пробы есть заменитель для %s, но профиль такой переменной из секрета "+
					"не объявляет — запись пережила свой предмет", name))
		}
	}
	return errs
}

// filesAreMountable — каждый путь к файлу, названный ручкой, лежит под
// каталогом, который чарт монтирует.
//
// Ручка, называющая путь, которого под не несёт, — объявленная и неисполнимая
// возможность: процесс отказывает в пуске на нечитаемом файле, а профиль читается
// как настроенный.
func filesAreMountable(merged map[string]any, envs map[string]string) error {
	mount, _ := at(merged, "tls", "mountPath").(string)
	secret, _ := at(merged, "tls", "secretName").(string)

	var named []string
	for k, v := range envs {
		if !strings.HasSuffix(k, "_CERTFILE") && !strings.HasSuffix(k, "_KEYFILE") &&
			!strings.HasSuffix(k, "_CLIENTCAFILES") && !strings.HasSuffix(k, "_CA_FILE") {
			continue
		}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				named = append(named, k+"="+p)
			}
		}
	}
	if len(named) == 0 {
		return nil
	}
	sort.Strings(named)

	var errs error
	if strings.TrimSpace(secret) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"профиль называет %d путь(ей) к материалу TLS и не объявляет tls.secretName — "+
				"монтировать нечего, и процесс откажет в пуске на нечитаемом файле", len(named)))
	}
	if strings.TrimSpace(mount) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"профиль называет %d путь(ей) к материалу TLS и не объявляет tls.mountPath — "+
				"проверить досягаемость не с чем", len(named)))
		return errs
	}
	for _, n := range named {
		path := n[strings.Index(n, "=")+1:]
		if !strings.HasPrefix(path, strings.TrimSuffix(mount, "/")+"/") {
			errs = multierr.Append(errs, fmt.Errorf(
				"ручка %s называет путь вне каталога, который монтирует чарт (tls.mountPath=%s) — "+
					"файла по этому пути в поде не будет", n, mount))
		}
	}
	return errs
}

// writeRenderedConfig собирает config.yaml так, как его собирает шаблон чарта,
// и возвращает путь к нему плюс число положенных ключей.
func writeRenderedConfig(t *testing.T, merged map[string]any) (string, int) {
	t.Helper()
	tree := map[string]any{}
	keys := 0
	for _, b := range configBridge {
		var val any
		switch {
		case b.derive != nil:
			val = b.derive(merged)
		default:
			val = at(merged, b.valuePath...)
		}
		if b.omitEmpty && isEmptyValue(val) {
			continue
		}
		if val == nil {
			continue
		}
		setAt(tree, strings.Split(b.configKey, "."), val)
		keys++
	}
	raw, err := yaml.Marshal(tree)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path, keys
}

// envEntries — карта `env` профиля, которую шаблон развёртывания отдаёт поду
// дословно.
func envEntries(merged map[string]any) map[string]string {
	out := map[string]string{}
	m, ok := merged["env"].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range m {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// requireCleanEnv — предпосылка пробы: в процессе нет посторонних KACHO_IAM_*.
//
// Оставшаяся переменная сделала бы вердикт свойством машины, а не профиля, и
// зелёное читалось бы как утверждение о дереве.
func requireCleanEnv(t *testing.T) {
	t.Helper()
	var stray []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KACHO_IAM_") {
			stray = append(stray, kv[:strings.Index(kv, "=")])
		}
	}
	require.Empty(t, stray,
		"в окружении прогона уже стоят переменные %v — вердикт стал бы свойством "+
			"машины, а не профиля", stray)
}

// ── чтение профилей чарта ────────────────────────────────────────────────────

func readChartProfile(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(name)
	require.NoErrorf(t, err, "чтение профиля %s", name)
	var tree map[string]any
	require.NoErrorf(t, yaml.Unmarshal(raw, &tree), "разбор профиля %s", name)
	return tree
}

func mergeChartProfiles(t *testing.T, chain []string) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, name := range chain {
		merged = mergeInto(merged, readChartProfile(t, name))
	}
	return merged
}

// at достаёт значение по пути; отсутствующий путь даёт nil.
func at(tree map[string]any, path ...string) any {
	var cur any = tree
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[key]; !ok {
			return nil
		}
	}
	return cur
}

func setAt(tree map[string]any, path []string, val any) {
	cur := tree
	for _, key := range path[:len(path)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[key] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = val
}

// removeAt снимает лист по пути, оставляя опустевшие ветви на месте: снятие
// ветви целиком сняло бы больше одной ручки за раз, и упрёк относился бы не к
// названной.
func removeAt(tree map[string]any, path []string) {
	cur := tree
	for _, key := range path[:len(path)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	delete(cur, path[len(path)-1])
}

// leafPaths перечисляет листья дерева значений. Список — тоже лист: снять из
// него один элемент значило бы менять величину, а не ручку.
func leafPaths(tree map[string]any, prefix []string) [][]string {
	var out [][]string
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := append(append([]string{}, prefix...), k)
		if sub, ok := tree[k].(map[string]any); ok {
			out = append(out, leafPaths(sub, path)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}
