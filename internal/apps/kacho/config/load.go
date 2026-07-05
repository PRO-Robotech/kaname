// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Load reads configuration from a YAML file (if path != "") + applies
// ENV-overrides.
//
// Behaviour:
//  1. Defaults are registered (RegisterDefaults).
//  2. ENV-binding: prefix `KACHO_IAM`, key separator `__` →
//     `KACHO_IAM_REPOSITORY__POSTGRES__URL` is mapped to
//     `repository.postgres.url`. Dashes in keys (`max-conns`) become
//     underscores (`MAX_CONNS`) via viper's SetEnvKeyReplacer.
//  3. If path != "" — YAML is read and overlays the defaults.
//  4. ENV overrides YAML + defaults.
//  5. Legacy ENV aliases (KACHO_IAM_DB_HOST/PORT/USER/NAME/PASSWORD/…) are
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
	v.SetEnvPrefix("KACHO_IAM")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "__", "-", "_"))
	v.AutomaticEnv()

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
		)
	}
	if err := v.Unmarshal(&cfg, decoderOpts); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}

	return cfg, nil
}

// applyLegacyEnv — bridge from legacy ENV names to new viper keys. Applied
// AFTER AutomaticEnv: if the new KACHO_IAM_REPOSITORY__POSTGRES__URL is set
// it has already been picked up via ENV-binding and legacy is ignored.
//
// If at least one of KACHO_IAM_DB_HOST/PORT/USER/NAME is set we assemble a
// DSN from them and override repository.postgres.url. This is required
// because the current values.yaml sets ENV vars exactly that way (parity
// with kacho-vpc).
//
// KACHO_IAM_DB_PASSWORD stays a separate mechanism (see password-from-env).
func applyLegacyEnv(v *viper.Viper) {
	type mapping struct {
		env string
		key string
	}
	simple := []mapping{
		{"KACHO_IAM_DB_SSLMODE", "repository.postgres.ssl-mode"},
		{"KACHO_IAM_DB_MAX_CONNS", "repository.postgres.max-conns"},
		{"KACHO_IAM_GRPC_PORT", "_legacy.grpc-port"},
		{"KACHO_IAM_INTERNAL_PORT", "_legacy.internal-port"},
		{"KACHO_IAM_AUTH_MODE", "authn.mode"},
		// Flat alias for the SA-key redact grace window — the deploy chart sets
		// the short KACHO_IAM_SAKEY_REDACT_GRACE rather than the namespaced
		// KACHO_IAM_AUTHN__SAKEY_REDACT_GRACE. Value is a Go duration ("120s").
		{"KACHO_IAM_SAKEY_REDACT_GRACE", "authn.sakey-redact-grace"},
		// Flat alias for the User-token redact grace window — mirror of the SA-key
		// alias above. Value is a Go duration ("120s").
		{"KACHO_IAM_USERTOKEN_REDACT_GRACE", "authn.usertoken-redact-grace"},
		// ConditionsService evaluator cache — flat aliases for the documented env
		// knobs (moved out of the service layer's os.Getenv into viper config).
		{"KACHO_IAM_CONDITIONS_CACHE_SIZE", "conditions.cache-size"},
		{"KACHO_IAM_CONDITIONS_CACHE_TTL_SECONDS", "conditions.cache-ttl-seconds"},
		// OpenFGA legacy aliases — extend as the rollout adds them.
	}
	for _, m := range simple {
		if val, ok := os.LookupEnv(m.env); ok {
			v.Set(m.key, val)
		}
	}

	// DB DSN composition from split-env (KACHO_IAM_DB_HOST/PORT/USER/NAME).
	host, hasHost := os.LookupEnv("KACHO_IAM_DB_HOST")
	port, hasPort := os.LookupEnv("KACHO_IAM_DB_PORT")
	user, hasUser := os.LookupEnv("KACHO_IAM_DB_USER")
	db, hasDB := os.LookupEnv("KACHO_IAM_DB_NAME")
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
			db = "kacho_iam"
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

// ListenAddress — public wrapper over listenAddress (for cmd/kacho-iam/main.go).
func (c APIServerConfig) ListenAddress() string         { return listenAddress(c.Endpoint) }
func (c APIServerConfig) InternalListenAddress() string { return listenAddress(c.InternalEndpoint) }

// MetricsListenAddress — normalised listen-addr for the Prometheus /metrics
// HTTP server. Empty endpoint → empty (disabled). Separate internal port from
// the gRPC public/internal listeners (default :9095).
func (c APIServerConfig) MetricsListenAddress() string { return listenAddress(c.MetricsEndpoint) }
