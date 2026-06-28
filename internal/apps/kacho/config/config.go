// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"time"
)

// Config — root configuration struct for kacho-iam.
//
// YAML hierarchy:
//
//	logger:        { level }
//	api-server:    { endpoint, internal-endpoint, graceful-shutdown }
//	repository:    { postgres }
//	authn:         { mode, domain, hydra-issuer, hooks, jwks, dpop }
//
// OpenFGA + the gateway-internal drainer are configured from KACHO_IAM_*
// env vars in the composition root (cmd/kacho-iam), not from this YAML.
//
// Every section is `mapstructure`-tagged (viper uses mapstructure for
// Unmarshal by default). Defaults live in defaults.go.
type Config struct {
	Logger     LoggerConfig     `mapstructure:"logger"`
	APIServer  APIServerConfig  `mapstructure:"api-server"`
	Repository RepositoryConfig `mapstructure:"repository"`
	AuthN      AuthNConfig      `mapstructure:"authn"`
	// OpenFGA is configured from KACHO_IAM_OPENFGA_* env vars in the composition
	// root (cmd/kacho-iam), not from this YAML. The Prometheus /metrics listener
	// is real — see APIServer.MetricsEndpoint.
}

// LoggerConfig — logger section.
type LoggerConfig struct {
	// Level — one of FATAL|ERROR|WARN|INFO|DEBUG.
	Level string `mapstructure:"level"`
}

// APIServerConfig — api-server section.
//
// Endpoint / InternalEndpoint accept two formats:
//   - `tcp://0.0.0.0:9090` (full URL-style, recommended);
//   - `9090` (legacy: bare port; preserved for backward-compat
//     with older values.yaml, see listenAddress in load.go).
type APIServerConfig struct {
	Endpoint         string        `mapstructure:"endpoint"`
	InternalEndpoint string        `mapstructure:"internal-endpoint"`
	GracefulShutdown time.Duration `mapstructure:"graceful-shutdown"`
	// MetricsEndpoint — Prometheus /metrics HTTP listener. A SEPARATE
	// cluster-internal port (default `tcp://0.0.0.0:9095`), never the public
	// tenant gRPC surface — exposing the registry there would leak internal
	// cardinality (security.md). Empty disables the metrics listener.
	MetricsEndpoint string `mapstructure:"metrics-endpoint"`
}

// RepositoryConfig — repository section. Postgres-only (the repository type
// was never branched on; the dead `type` knob was removed).
type RepositoryConfig struct {
	Postgres PostgresConfig `mapstructure:"postgres"`
}

// PostgresConfig — repository.postgres section.
//
//	URL              — standard DSN postgres://user:pass@host:port/db (master).
//	SlaveURL         — DSN of the read-replica (optional).
//	MaxConns         — pgxpool max conns (0 = pgx default).
//	SSLMode          — disable|require|verify-ca|verify-full (validated in Validate).
//	PasswordFromEnv  — name of the ENV var the password is read from and
//	                   substituted into URL and SlaveURL. Default — KACHO_IAM_DB_PASSWORD.
type PostgresConfig struct {
	URL             string `mapstructure:"url"`
	SlaveURL        string `mapstructure:"slave-url"`
	MaxConns        int    `mapstructure:"max-conns"`
	SSLMode         string `mapstructure:"ssl-mode"`
	PasswordFromEnv string `mapstructure:"password-from-env"`
}

// AuthNConfig — authn section.
//
// Mode — overall service mode (see mode.go).
//
// AuthN core fields:
//
//	Domain                — public Kachō domain, default `api.kacho.cloud`.
//	                        Used by token_hook to build issuer/audience.
//	HydraIssuer           — Ory Hydra issuer (default `https://hydra.<Domain>`).
//	HookSharedSecret      — Bearer-token Hydra uses to authenticate calls to
//	                        token_hook/refresh_hook. If empty — accepted
//	                        without auth (dev mode only).
//	JWKSEncryptionKeyHex  — 32-byte AES-GCM key in hex (64 chars) used to
//	                        encrypt private_key_pem_encrypted in the DB.
//	JWKSRotationDays      — key TTL in days (default 90).
//	SessionRevocationsTTLSec — session_revocations cache TTL (default 5s).
//	HooksHTTPEndpoint     — HTTP listener for webhooks from Hydra/Kratos.
//	                        Default `tcp://0.0.0.0:9092` (separate port from
//	                        gRPC public 9090 / internal 9091).
type AuthNConfig struct {
	Mode                     Mode   `mapstructure:"mode"`
	Domain                   string `mapstructure:"domain"`
	HydraIssuer              string `mapstructure:"hydra-issuer"`
	HookSharedSecret         string `mapstructure:"hook-shared-secret"`
	HookSharedSecretEnv      string `mapstructure:"hook-shared-secret-env"`
	JWKSEncryptionKeyHex     string `mapstructure:"jwks-encryption-key-hex"`
	JWKSEncryptionKeyHexEnv  string `mapstructure:"jwks-encryption-key-hex-env"`
	JWKSRotationDays         int    `mapstructure:"jwks-rotation-days"`
	SessionRevocationsTTLSec int    `mapstructure:"session-revocations-cache-ttl-seconds"`
	HooksHTTPEndpoint        string `mapstructure:"hooks-http-endpoint"`
}

// schemaOptionsParam — URL-encoded libpq parameter `options=-c search_path=…`.
// Appended to baseDSN automatically so every connection (pgxpool, dedicated
// pgx.Conn for LISTEN, goose via database/sql) sees kacho-iam tables under
// their unqualified names.
//
// search_path is "kacho_iam, public":
//   - `kacho_iam` first — our tables;
//   - `public` second — Postgres built-ins / extensions.
const schemaOptionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"

// baseDSN — standard postgres DSN without pgxpool parameters; used by both
// pgxpool and database/sql.Open("pgx").
func (c Config) baseDSN() string {
	return c.composeDSN(c.Repository.Postgres.URL)
}

// composeDSN appends missing libpq parameters to raw-DSN: `sslmode=<mode>`
// and `options=-c search_path=kacho_iam,public`. If a parameter is already
// present in raw-URL we do not overwrite it (eases ENV/yaml override).
func (c Config) composeDSN(raw string) string {
	if raw == "" {
		return ""
	}
	mode := c.Repository.Postgres.SSLMode
	if mode == "" {
		mode = "disable"
	}
	if !dsnHas(raw, "sslmode=") {
		sep := "?"
		if dsnHas(raw, "?") {
			sep = "&"
		}
		raw = raw + sep + "sslmode=" + mode
	}
	if !dsnHas(raw, "options=") && !dsnHas(raw, "options%3D") {
		sep := "?"
		if dsnHas(raw, "?") {
			sep = "&"
		}
		raw = raw + sep + schemaOptionsParam
	}
	return raw
}

// DSN — connection string for pgxpool (supports pool_max_conns).
// Do NOT use for database/sql.Open("pgx") — it FATALs on unknown server param.
func (c Config) DSN() string {
	dsn := c.baseDSN()
	if dsn == "" {
		return ""
	}
	if c.Repository.Postgres.MaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.Repository.Postgres.MaxConns)
	}
	return dsn
}

// SlaveDSN — connection string for the slave pool (read-replica). Empty
// string → no replica configured, caller falls back to master.
func (c Config) SlaveDSN() string {
	slaveRaw := c.Repository.Postgres.SlaveURL
	if slaveRaw == "" || slaveRaw == c.Repository.Postgres.URL {
		return ""
	}
	dsn := c.composeDSN(slaveRaw)
	if dsn == "" {
		return ""
	}
	if c.Repository.Postgres.MaxConns > 0 {
		dsn += fmt.Sprintf("&pool_max_conns=%d", c.Repository.Postgres.MaxConns)
	}
	return dsn
}

// MigrateDSN — connection string for goose/database/sql (without
// pool_max_conns). Always points to master — goose must not write to the
// replica.
func (c Config) MigrateDSN() string { return c.baseDSN() }

func dsnHas(dsn, frag string) bool {
	for i := 0; i+len(frag) <= len(dsn); i++ {
		if dsn[i:i+len(frag)] == frag {
			return true
		}
	}
	return false
}
