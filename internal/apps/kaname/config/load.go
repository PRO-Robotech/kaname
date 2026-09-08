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

	// YAML file (optional).
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %q: %w", path, err)
		}
	}

	// Legacy ENV → new keys (backward-compat).
	applyLegacyEnv(v)

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
// AFTER AutomaticEnv: if the new KANAME_REPOSITORY__POSTGRES__URL is set
// it has already been picked up via ENV-binding and legacy is ignored.
//
// If at least one of KANAME_DB_HOST/PORT/USER/NAME is set we assemble a
// DSN from them and override repository.postgres.url. This is required
// because the current values.yaml sets ENV vars exactly that way (parity
// with kacho-vpc).
//
// KANAME_DB_PASSWORD stays a separate mechanism (see password-from-env).
func applyLegacyEnv(v *viper.Viper) {
	type mapping struct {
		env string
		key string
	}
	simple := []mapping{
		{"KANAME_DB_SSLMODE", "repository.postgres.ssl-mode"},
		{"KANAME_DB_MAX_CONNS", "repository.postgres.max-conns"},
		{"KANAME_GRPC_PORT", "_legacy.grpc-port"},
		{"KANAME_INTERNAL_PORT", "_legacy.internal-port"},
		{"KANAME_AUTH_MODE", "authn.mode"},
		// Flat alias for the SA-key redact grace window — the deploy chart sets
		// the short KANAME_SAKEY_REDACT_GRACE rather than the namespaced
		// KANAME_AUTHN__SAKEY_REDACT_GRACE. Value is a Go duration ("120s").
		{"KANAME_SAKEY_REDACT_GRACE", "authn.sakey-redact-grace"},
		// Flat alias for the User-token redact grace window — mirror of the SA-key
		// alias above. Value is a Go duration ("120s").
		{"KANAME_USERTOKEN_REDACT_GRACE", "authn.usertoken-redact-grace"},
		// SA-key lifetime discipline — flat aliases the deploy chart sets.
		// Values are Go durations ("2160h" / "8760h" / "15m").
		{"KANAME_SAKEY_DEFAULT_TTL", "authn.sakey-default-ttl"},
		{"KANAME_SAKEY_MAX_TTL", "authn.sakey-max-ttl"},
		{"KANAME_SAKEY_ACCESS_TOKEN_TTL", "authn.sakey-access-token-ttl"},
		{"KANAME_SAKEY_BIND_DPOP", "authn.sakey-bind-dpop"},
		// Окно отзыва собственной двери. Величина Go-длительности ("5s").
		{"KANAME_AUTHZ_CACHE_TTL", "authz.cache-ttl"},
	}
	for _, m := range simple {
		if val, ok := os.LookupEnv(m.env); ok {
			v.Set(m.key, val)
		}
	}

	// DB DSN composition from split-env (KANAME_DB_HOST/PORT/USER/NAME).
	host, hasHost := os.LookupEnv("KANAME_DB_HOST")
	port, hasPort := os.LookupEnv("KANAME_DB_PORT")
	user, hasUser := os.LookupEnv("KANAME_DB_USER")
	db, hasDB := os.LookupEnv("KANAME_DB_NAME")
	if hasHost || hasPort || hasUser || hasDB {
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
