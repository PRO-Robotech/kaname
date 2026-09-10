// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/PRO-Robotech/kacho/pkg/identityposture"
)

// Load reads configuration from a YAML file (if path != "") + applies
// ENV-overrides.
//
// Behaviour:
//  1. Defaults are registered (RegisterDefaults).
//  2. ENV-binding: prefix `KANAME`, key separator `__` →
//     `KANAME_REPOSITORY__POSTGRES__URL` is mapped to
//     `repository.postgres.url`. Dashes in keys (`max-conns`) become
//     underscores (`MAX_CONNS`) via viper's SetEnvKeyReplacer.
//  3. If path != "" — YAML is read and overlays the defaults.
//  4. ENV overrides YAML + defaults.
//  5. Legacy ENV aliases (KANAME_DB_HOST/PORT/USER/NAME/PASSWORD/…) are
//     translated to the new keys by applyLegacyEnv — backward-compat for the
//     already-deployed Helm chart and dev scripts.
//  6. Unmarshal into Config with a custom DecodeHook (Mode-ENUM from string).
//
// Returns Config + error. Validate() is invoked separately by the caller
// (in main).
func Load(path string) (Config, error) {
	v := viper.New()
	RegisterDefaults(v)

	// ENV-binding.
	v.SetEnvPrefix(EnvPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "__", "-", "_"))
	v.AutomaticEnv()

	// ПОСАДКА ЛИЧНОСТИ привязывается к окружению ЯВНО, и это не украшение.
	//
	// AutomaticEnv резолвит переменную только для ключа, который viper уже
	// ЗНАЕТ, — то есть объявленного умолчанием либо привязкой. У этого ключа
	// умолчания нет намеренно (см. defaults.go), поэтому без явной привязки
	// документированная переменная не доезжала бы до поля ВООБЩЕ: оператор
	// задаёт её, процесс принимает старт как «посадка не объявлена», и ручка
	// выглядит настроенной, ничего не делая.
	//
	// Привязка регистрирует ключ, НЕ давая ему значения: незаданная переменная
	// оставляет поле нулевым, то есть «не объявлено», и отказ старта наступает
	// ровно так же. Свойство закреплено пробой documented-env-имени.
	if err := v.BindEnv("authn."+identityposture.FieldName,
		"KANAME_AUTHN__IDENTITY_PROVIDER"); err != nil {
		return Config{}, fmt.Errorf("bind %s env: %w", IdentityProviderSetting, err)
	}

	// ДОСТАВКА МАНИФЕСТОВ привязывается к окружению ЯВНО — по той же причине,
	// что посадка личности выше (задача #1875).
	//
	// Умолчания у обеих ручек нет намеренно: пустой каталог означает «доставка
	// не заведена», и подставленное значение было бы непустым всегда. Но
	// AutomaticEnv резолвит переменную только для ключа, который viper УЖЕ
	// ЗНАЕТ, — без привязки документированная переменная не доехала бы до поля
	// ВООБЩЕ. Оператор задал бы её, процесс принял бы старт как «доставка не
	// объявлена», и ручка выглядела бы настроенной, ничего не делая.
	//
	// Привязка регистрирует ключ, НЕ давая ему значения: незаданная переменная
	// оставляет поле нулевым, и отказ старта при объявленной опоре наступает
	// ровно так же.
	//
	// Ручки СБОРКИ (задача #1971) привязываются здесь же и по той же причине:
	// умолчания у них нет намеренно, а без привязки документированное имя не
	// доехало бы до поля ВООБЩЕ. Секция читается одним словарём — все четыре
	// ключа kebab-case, как вся прочая конфигурация службы, — поэтому имя
	// переменной выводится тем же замены­телем и не требует второго правила.
	// ВЕЛИЧИНЫ, КОТОРЫЕ НАЗЫВАЕТ ТЕКСТ ОТКАЗА, привязываются здесь по той же
	// причине — и это НЕ третий повод, а тот же, доведённый до конца (задача
	// #2040).
	//
	// Отказ стража называет оператору координату и переменную. Оператор задаёт
	// ровно названное — и получает ТОТ ЖЕ отказ, потому что у ключа нет ни
	// умолчания, ни привязки, а `AutomaticEnv` разрешает переменную только для
	// ключа, который випер УЖЕ знает. Отличить свою ошибку от нашей он не может
	// и упирается в цикл. Это самая дорогая форма класса «отказ не
	// восстанавливает следующий шаг»: отказ ВЫГЛЯДИТ исчерпывающим.
	//
	// Умолчания у всех трёх нет НАМЕРЕННО, и привязка его не заводит: она
	// регистрирует ключ, НЕ давая ему значения. Незаданная переменная оставляет
	// поле нулевым — пустой круг отправителей, невыбранный опт-ин стенда,
	// необъявленное имя чужой службы, — и отказ старта наступает ровно так же.
	//
	// Свойство держит гейт класса `TestRefusalNamedEnvVarReachesItsField`:
	// всякая переменная, названная текстом отказа, обязана менять исход.
	//
	// Сканер видит здесь «зашитые учётные данные» (G101) и ошибается на ИМЕНИ:
	// правило матчит подстроку `token` в ключе `api-server.registry-token.service`.
	// Доказано опытом — снятие подстроки из ИМЕНИ ключа и переменной, при нетронутых
	// значениях, даёт 1 → 0 находок. Значений здесь нет вовсе: карта отображает имя
	// ключа конфигурации в ИМЯ переменной окружения, а сама привязка значения НЕ
	// назначает (BindEnv регистрирует ключ, умолчания не заводя, — см. выше). Ключ
	// переименованию не подлежит: это контракт с оператором.
	// #nosec G101 -- ключи и имена переменных окружения, ни одного значения.
	for key, env := range map[string]string{
		"manifests.dir":           "KANAME_MANIFESTS__DIR",
		"manifests.required":      "KANAME_MANIFESTS__REQUIRED",
		"manifests.compose-model": "KANAME_MANIFESTS__COMPOSE_MODEL",
		"manifests.admission":     "KANAME_MANIFESTS__ADMISSION",

		"authn.domain":                      "KANAME_AUTHN__DOMAIN",
		"authn.trusted-forwarder-sans":      "KANAME_AUTHN__TRUSTED_FORWARDER_SANS",
		"authn.trust-domain":                "KANAME_AUTHN__TRUST_DOMAIN",
		"authn.trust-any-forwarder":         "KANAME_AUTHN__TRUST_ANY_FORWARDER",
		"api-server.registry-token.service": "KANAME_API_SERVER__REGISTRY_TOKEN__SERVICE",
	} {
		if err := v.BindEnv(key, env); err != nil {
			return Config{}, fmt.Errorf("bind %s env: %w", key, err)
		}
	}

	// ТРИ СОБСТВЕННЫХ ПОТОЛКА привязываются здесь по той же причине, что три
	// ручки выше, и перечень ВЫВОДИТСЯ из таблицы величин, а не выписывается
	// вторым списком (`own_ceilings.go`): выписанный разошёлся бы с ней молча,
	// и переменная, названная текстом отказа, перестала бы доезжать до поля.
	for _, k := range OwnCeilingKnobs {
		if err := v.BindEnv(k.Key, k.Env); err != nil {
			return Config{}, fmt.Errorf("bind %s env: %w", k.Key, err)
		}
	}

	// YAML file (optional).
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	// Legacy ENV → new keys (backward-compat).
	if err := applyLegacyEnv(v); err != nil {
		return Config{}, err
	}

	// Inject the password from password-from-env (when set) into both the
	// master URL and the slave URL.
	if envName := v.GetString("repository.postgres.password-from-env"); envName != "" {
		if pwd := os.Getenv(envName); pwd != "" {
			urlStr := v.GetString("repository.postgres.url")
			v.Set("repository.postgres.url", injectPasswordIntoDSN(urlStr, pwd))
			if slaveStr := v.GetString("repository.postgres.slave-url"); slaveStr != "" {
				v.Set("repository.postgres.slave-url", injectPasswordIntoDSN(slaveStr, pwd))
			}
		}
	}

	// Unmarshal into Config with a custom hook for Mode-ENUM.
	var cfg Config
	decoderOpts := func(dc *mapstructure.DecoderConfig) {
		dc.DecodeHook = mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			modeDecodeHook(),
			identityProviderDecodeHook(),
		)
	}
	if err := v.Unmarshal(&cfg, decoderOpts); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	return cfg, nil
}

// applyLegacyEnv — bridge from legacy ENV names to new viper keys. Applied
// AFTER AutomaticEnv, and it writes at viper's `override` level, which is
// SENIOR to `env` — so whatever it sets wins over the documented key.
//
// Прежняя редакция этой шапки утверждала обратное — «если задан новый
// KANAME_REPOSITORY__POSTGRES__URL, легаси игнорируется». Код делал ровно
// противоположное: сборка по полям звала `v.Set` безусловно и перебивала
// объявленную оператором строку, отбрасывая из неё всё, кроме четырёх полей,
// — включая параметры запроса. Два места об одном предмете, и верным было НЕ
// написанное (задача #2475).
//
// If at least one of KANAME_DB_HOST/PORT/USER/NAME is set we assemble a
// DSN from them and override repository.postgres.url — но ТОЛЬКО когда
// объявленной строки нет. Обе формы разом — отказ, см. refuseAmbiguousDSN.
//
// KANAME_DB_PASSWORD stays a separate mechanism (see password-from-env).
func applyLegacyEnv(v *viper.Viper) error {
	// ФОРМА ЗНАЧЕНИЯ ПРОВЕРЯЕТСЯ ДО ЛЮБОЙ СБОРКИ.
	//
	// Плоское имя переменной у части этих ручек совпадает с формой, которой
	// Kubernetes сам объявляет поду адреса служб своего пространства имён
	// (`<СЛУЖБА>_PORT` и соседние — см. service_link_collision.go). Подстановка
	// кластера попадает в СВОЁ ЖЕ пространство имён настроек службы и перебивает
	// не умолчание, а то, что задал оператор.
	//
	// Проверка стоит здесь — перед сборкой, — потому что собранное значение
	// доезжает до отказа лишь на ОТКРЫТИИ слушателя: последним шагом старта,
	// после отчёта о всей посадке, отказом от библиотеки, не называющим ни ручки,
	// ни того, откуда взялось значение.
	if err := refuseCollidingFlatEnv(os.LookupEnv); err != nil {
		return err
	}

	// Плоские псевдонимы читаются из ОБЩЕГО объявления (flatEnvKnobs): его же
	// читают проверка формы выше и перепись гейта класса. Второй список
	// разошёлся бы с первым молча.
	for _, k := range flatEnvKnobs {
		if k.Key == "" {
			continue // значение собирается вручную — поля адреса базы ниже
		}
		if val, ok := os.LookupEnv(k.Env); ok {
			v.Set(k.Key, val)
		}
	}

	// DB DSN composition from split-env (KANAME_DB_HOST/PORT/USER/NAME).
	//
	// Имена берутся из ОБЩЕГО объявления (см. splitDSNEnvNames ниже): текст
	// отказа читает то же самое, поэтому «ручку сборка читает, а отказ её не
	// называет» невыразимо by construction.
	host, hasHost := os.LookupEnv(envDBHost)
	port, hasPort := os.LookupEnv(envDBPort)
	user, hasUser := os.LookupEnv(envDBUser)
	db, hasDB := os.LookupEnv(envDBName)
	if hasHost || hasPort || hasUser || hasDB {
		if err := refuseAmbiguousDSN(); err != nil {
			return err
		}
		if host == "" {
			host = "localhost"
		}
		if port == "" {
			port = "5432"
		}
		if user == "" {
			user = "iam"
		}
		if db == "" {
			db = "kaname"
		}
		v.Set("repository.postgres.url", fmt.Sprintf("postgres://%s@%s:%s/%s", user, host, port, db))
	}

	// Legacy port→endpoint composer.
	if p := v.GetString("_legacy.grpc-port"); p != "" {
		v.Set("api-server.endpoint", "tcp://0.0.0.0:"+p)
	}
	if p := v.GetString("_legacy.internal-port"); p != "" {
		v.Set("api-server.internal-endpoint", "tcp://0.0.0.0:"+p)
	}

	return nil
}

// Расщеплённые ручки адреса базы. Объявлены ОДИН раз: их читает и сборка
// строки выше, и текст отказа ниже, поэтому «ручку сборка читает, а отказ её не
// называет» невыразимо by construction.
//
// Это НЕ противоречит соседней пробе documented-env-имён: там речь о ключах,
// чьё имя переменной viper ВЫВОДИТ из пути ключа. У этих четырёх пути ключа
// нет — они легаси-псевдонимы, и вывести их не из чего.
const (
	envDBHost = "KANAME_DB_HOST"
	envDBPort = "KANAME_DB_PORT"
	envDBUser = "KANAME_DB_USER"
	envDBName = "KANAME_DB_NAME"
)

// splitDSNEnvNames — те же четыре ручки в порядке клиентской страницы
// настройки. Выводится из объявлений выше, а не выписывается вторым списком.
var splitDSNEnvNames = []string{envDBHost, envDBPort, envDBUser, envDBName}

// postgresURLKey — путь ключа полного DSN. Имя переменной из него ВЫВОДИТСЯ
// (см. envNameOf), а не пишется вторым литералом: переименуй ключ — и текст
// отказа переедет вместе с ним, вместо того чтобы назвать имя, которого нет.
const postgresURLKey = "repository.postgres.url"

// envNameOf повторяет вывод имени переменной, который делает viper из пути
// ключа: префикс службы, точка → `__`, дефис → `_`, верхний регистр
// (см. SetEnvPrefix + SetEnvKeyReplacer в Load).
func envNameOf(key string) string {
	return EnvPrefix + "_" + strings.ToUpper(strings.NewReplacer(".", "__", "-", "_").Replace(key))
}

// refuseAmbiguousDSN отвергает старт, когда адрес базы объявлен ОБЕИМИ формами
// сразу: строкой целиком и по полям.
//
// Почему отказ, а не старшинство. У величины два документированных входа, и
// главного из них не называл никто. Молчаливое старшинство негодно в ЛЮБУЮ
// сторону: «поля старше строки» отбрасывает у оператора параметры запроса, а
// потом посадочный страж отказывает, называя ровно ту величину, которую
// оператор как раз задал; «строка старше полей» принимает ручки и выбрасывает
// их — отдельно запрещённый класс «принято-и-проигнорировано».
//
// Отказ не выбирает за оператора и восстанавливает следующий шаг: он называет
// ОБЕ спорящие стороны — ручку строки и каждую ЗАДАННУЮ ручку поля. Незаданные
// не называются: иначе оператор пойдёт искать то, чего не задавал.
func refuseAmbiguousDSN() error {
	urlEnv := envNameOf(postgresURLKey)
	if _, ok := os.LookupEnv(urlEnv); !ok {
		return nil
	}

	set := make([]string, 0, len(splitDSNEnvNames))
	for _, name := range splitDSNEnvNames {
		if _, ok := os.LookupEnv(name); ok {
			set = append(set, name)
		}
	}
	if len(set) == 0 {
		return nil
	}

	return fmt.Errorf(
		"адрес базы объявлен дважды, и старшинство форм не решено: %s задаёт "+
			"строку подключения целиком, а %s — её же по полям. Оставьте одну "+
			"форму: либо %s, либо перечисленные ручки полей",
		urlEnv, strings.Join(set, ", "), urlEnv)
}

// injectPasswordIntoDSN adds the password to the DSN (postgres://user@host →
// postgres://user:pwd@host). If the password is already in the URL we leave
// it untouched.
func injectPasswordIntoDSN(dsn, pwd string) string {
	if dsn == "" {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	if u.User == nil {
		return dsn
	}
	if _, has := u.User.Password(); has {
		return dsn
	}
	u.User = url.UserPassword(u.User.Username(), pwd)
	return u.String()
}

// modeDecodeHook — DecodeHook for viper.Unmarshal: parses string → Mode (ENUM).
func modeDecodeHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(Mode(0)) {
			return data, nil
		}
		switch v := data.(type) {
		case string:
			return parseMode(v)
		case int:
			return Mode(v), nil
		case int64:
			return Mode(v), nil
		case float64:
			return Mode(int(v)), nil
		default:
			return data, nil
		}
	}
}

// identityProviderDecodeHook — DecodeHook для viper.Unmarshal: строка →
// IdentityProvider (задача #1125).
//
// Разбор ТОТ ЖЕ, что у всех прочих читателей (ParseIdentityProvider): второй
// разборщик разошёлся бы с первым на вырожденном значении, и разошёлся бы
// молча. Числовая форма НЕ принимается намеренно: у поля есть ровно два
// законных значения и оба именованы, а номер значения — деталь представления,
// которую профиль писать не должен и по которой невозможно отличить «не
// задано» от осознанного выбора.
func identityProviderDecodeHook() mapstructure.DecodeHookFunc {
	return func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if to != reflect.TypeOf(IdentityProvider(0)) {
			return data, nil
		}
		v, ok := data.(string)
		if !ok {
			return data, nil
		}
		if strings.TrimSpace(v) == "" {
			// Пустое значение — «профиль поля не объявил», а не негодный ввод.
			// Отказ производит проверка настройки, называя поле и оба законных
			// значения; отказ здесь назвал бы то же самое вторым текстом.
			return IdentityProviderUnset, nil
		}
		return ParseIdentityProvider(v)
	}
}

// listenAddress normalises an Endpoint string from YAML into `:port` or
// `host:port` — the format net.Listen("tcp", …) expects.
//
// Supported inputs:
//
//	`tcp://0.0.0.0:9090` → `0.0.0.0:9090`
//	`tcp://:9090`        → `:9090`
//	`:9090`              → `:9090`
//	`9090`               → `:9090`
//	`0.0.0.0:9090`       → `0.0.0.0:9090`
func listenAddress(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	endpoint = strings.TrimPrefix(endpoint, "tcp://")
	if strings.HasPrefix(endpoint, "unix://") {
		return endpoint
	}
	if !strings.Contains(endpoint, ":") {
		return ":" + endpoint
	}
	return endpoint
}

// ListenAddress — public wrapper over listenAddress (for cmd/kaname/main.go).
func (c APIServerConfig) ListenAddress() string         { return listenAddress(c.Endpoint) }
func (c APIServerConfig) InternalListenAddress() string { return listenAddress(c.InternalEndpoint) }

// RESTListenAddress / InternalRESTListenAddress — нормализованные адреса
// собственных REST-фронтов. Пустой эндпоинт → пустой адрес, то есть фронт не
// поднимается.
func (c APIServerConfig) RESTListenAddress() string { return listenAddress(c.RESTEndpoint) }
func (c APIServerConfig) InternalRESTListenAddress() string {
	return listenAddress(c.InternalRESTEndpoint)
}

// MetricsListenAddress — normalised listen-addr for the Prometheus /metrics
// HTTP server. Empty endpoint → empty (disabled). Separate internal port from
// the gRPC public/internal listeners (default :9095).
func (c APIServerConfig) MetricsListenAddress() string { return listenAddress(c.MetricsEndpoint) }

// ListenAddressOf — адрес слушателя из объявленной конечной точки.
//
// Экспортируется затем, чтобы страж старта и проба профиля приводили конечную
// точку к адресу ТЕМ ЖЕ разбором, каким это делает процесс: второй разбор
// разошёлся бы с первым молча — на верном входе оба отвечают одинаково.
func ListenAddressOf(endpoint string) string { return listenAddress(endpoint) }
