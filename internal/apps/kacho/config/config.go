// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"os"
	"strings"
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
	// RegistryToken — the Docker Registry v2 `/iam/token` auth-server HTTP
	// listener. A SEPARATE, EXTERNAL-reachable plaintext port (default
	// `tcp://0.0.0.0:9096`; TLS terminated at the ingress, like the hooks /
	// metrics listeners) — docker clients hit `/iam/token` through the edge to
	// exchange an SA-key for a short-lived identity-JWT. Distinct from the
	// cluster-internal hooks (:9092) and metrics (:9095) listeners. Empty
	// endpoint disables it.
	RegistryToken RegistryTokenConfig `mapstructure:"registry-token"`
	// JWKSProxy — the cluster-INTERNAL Hydra-JWKS proxy HTTP listener
	// (`GET /.well-known/jwks.json`; default `tcp://0.0.0.0:9097`). A short-TTL
	// caching reverse-proxy of Hydra's PUBLIC JWKS: the data-plane fetches its
	// verification keys from iam (never dialing Hydra directly) while Hydra stays
	// the issuer/signer. Served ONLY on the cluster-internal `kacho-iam-internal`
	// Service (never external, ban #6) over one-way server-TLS. Empty disables it.
	JWKSProxy JWKSProxyConfig `mapstructure:"jwks-proxy"`
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
//	JWKSEncryptionKeyHex  — 32-byte AES-GCM key in hex (64 chars). It no longer
//	                        encrypts anything (the oidc_jwks_keys store it was
//	                        minted for was dropped in migration 0065), but the
//	                        production boot guard still REQUIRES it — see
//	                        validateProductionAuthNSecrets.
//	HooksHTTPEndpoint     — HTTP listener for webhooks from Hydra/Kratos.
//	                        Default `tcp://0.0.0.0:9092` (separate port from
//	                        gRPC public 9090 / internal 9091).
//	SAKeyRedactGrace      — задержка между Done-ом Issue-Operation и затиранием
//	                        одноразового private_key_pem в её response. Даёт
//	                        поллящему клиенту окно, чтобы забрать ключ до вычистки.
//	                        Default 120s; override KACHO_IAM_SAKEY_REDACT_GRACE.
//	UserTokenRedactGrace  — то же для UserTokenService.Issue (персональные токены
//	                        пользователя). Default 120s; override
//	                        KACHO_IAM_USERTOKEN_REDACT_GRACE.
//	SAKeyDefaultTTL       — срок жизни SA-ключа, когда вызывающий не передал
//	                        ttl_seconds. Машинный принципал освобождён от
//	                        усиленного входа (у машины нет второго фактора) —
//	                        это защитимо лишь пока сам ключ ограничен по времени,
//	                        поэтому умолчание конечно, а не «никогда».
//	                        Default 2160h (90d); override KACHO_IAM_SAKEY_DEFAULT_TTL.
//	SAKeyMaxTTL           — включительный потолок ttl_seconds. Запрос сверх него
//	                        отвергается InvalidArgument ДО регистрации клиента.
//	                        Default 8760h (365d); override KACHO_IAM_SAKEY_MAX_TTL.
//	SAKeyBindDPoP         — регистрировать OAuth2-клиент SA-ключа так, чтобы
//	                        провайдер выпускал ТОЛЬКО sender-constrained токены
//	                        (RFC 9449 `cnf.jkt`). Половина «выпуска» контроля
//	                        привязки; половина «проверки» живёт на api-gateway.
//	                        Default false; override KACHO_IAM_SAKEY_BIND_DPOP.
//	SAKeyAccessTokenTTL   — per-client access_token_lifespan, проставляемый на
//	                        OAuth2-клиенте SA-ключа. 0 → поле не отправляется и
//	                        действует глобальный дефолт провайдера. Задаётся
//	                        профилем деплоя; override KACHO_IAM_SAKEY_ACCESS_TOKEN_TTL.
type AuthNConfig struct {
	Mode          Mode   `mapstructure:"mode"`
	Domain        string `mapstructure:"domain"`
	HydraIssuer   string `mapstructure:"hydra-issuer"`
	HydraAdminURL string `mapstructure:"hydra-admin-url"`
	// HydraAdminCAFile — PEM bundle the provider-admin hop is verified against
	// when it is served over TLS. Empty ⇒ the default transport (system roots),
	// which an internal-CA certificate never chains to. Set ⇒ the bundle becomes
	// the ONLY anchor, and one that cannot be read refuses the start.
	HydraAdminCAFile string `mapstructure:"hydra-admin-ca-file"`
	HydraTokenURL    string `mapstructure:"hydra-token-url"`
	// HydraTokenCAFile / HydraJWKSCAFile — the same anchor discipline for the two
	// hops to the provider's PUBLIC listener: the token exchange (a signed client
	// assertion out, the minted bearer back) and the JWKS upstream (the keyset the
	// data-plane verifies every token against). Empty ⇒ the default transport,
	// which is what a plaintext in-cluster address needs and all it needs. Set ⇒
	// the bundle becomes the ONLY anchor, and one that cannot be read refuses the
	// start rather than falling back to the system roots — that fallback is the
	// state nobody can see, because the operator configured verification against
	// the internal CA and the process is not doing it.
	HydraTokenCAFile        string        `mapstructure:"hydra-token-ca-file"`
	HydraJWKSURL            string        `mapstructure:"hydra-jwks-url"`
	HydraJWKSCAFile         string        `mapstructure:"hydra-jwks-ca-file"`
	HookSharedSecret        string        `mapstructure:"hook-shared-secret"`
	HookSharedSecretEnv     string        `mapstructure:"hook-shared-secret-env"`
	JWKSEncryptionKeyHex    string        `mapstructure:"jwks-encryption-key-hex"`
	JWKSEncryptionKeyHexEnv string        `mapstructure:"jwks-encryption-key-hex-env"`
	HooksHTTPEndpoint       string        `mapstructure:"hooks-http-endpoint"`
	SAKeyRedactGrace        time.Duration `mapstructure:"sakey-redact-grace"`
	UserTokenRedactGrace    time.Duration `mapstructure:"usertoken-redact-grace"`
	SAKeyDefaultTTL         time.Duration `mapstructure:"sakey-default-ttl"`
	SAKeyMaxTTL             time.Duration `mapstructure:"sakey-max-ttl"`
	SAKeyAccessTokenTTL     time.Duration `mapstructure:"sakey-access-token-ttl"`
	SAKeyBindDPoP           bool          `mapstructure:"sakey-bind-dpop"`
	// BootstrapMint — caller gate + key source for
	// InternalBootstrapTokenService.MintBootstrapToken.
	BootstrapMint BootstrapMintConfig `mapstructure:"bootstrap-mint"`
	// TrustedForwarderSANs — EXACT client-certificate SPIFFE SAN URIs allowed to
	// FORWARD an end-user identity (`x-kacho-principal-*` metadata) to iam. Fed
	// into grpcsrv.WithTrustedForwarders on BOTH gRPC listeners
	// (cmd/kacho-iam/serve.go identityUnary/identityStream).
	//
	// Why this is a knob and not a constant: the corelib contract
	// (pkg/grpcsrv principalIsTrusted) narrows the circle of senders ONLY when the
	// list is non-empty; on an empty list it answers "trusted" for ANY peer that
	// passed client-certificate verification. Both gRPC ports are ordinary Services
	// inside the namespace and every neighbour's client certificate is issued by the
	// same internal authority — so an empty list means any pod may send a victim's
	// identity headers and have iam decide in that victim's name (the whole tenant
	// CRUD surface on :9090, including credential issuance). Network position is not
	// a substitute: the only NetworkPolicy selecting the iam pod covers the internal
	// port, and it is off outside production.
	//
	// Format: comma-separated in the env override
	// KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS; a YAML list under
	// authn.trusted-forwarder-sans.
	//
	// Empty is tolerated ONLY in dev (in-process fixtures); in any production mode
	// Validate refuses to start (fail-closed, mirroring geo/compute/nlb/storage/
	// registry).
	TrustedForwarderSANs []string `mapstructure:"trusted-forwarder-sans"`
}

// TrustedForwarders — the certificate identities that REALLY reach
// grpcsrv.WithTrustedForwarders on both listeners.
//
// Single source of this value per process: the wiring
// (cmd/kacho-iam/serve.go), the boot guard (validateProductionTrustedForwarders)
// and the boot self-report (cmd/kacho-iam/bootposture.go) all read this one
// accessor. So "the guard passed" ⟺ "the circle is really narrowed" — by
// construction, not by coincidence.
//
// Blank entries are dropped because corelib drops them too
// (WithTrustedForwarders keeps only s != ""): a list of blank strings
// (`SANS=","`) degenerates there into the empty set, i.e. back to "trust
// anybody". Counting such a list as filled would let the hole through the guard.
//
// Surrounding whitespace is trimmed — deliberately NOT mirroring corelib, which
// compares the SAN byte-for-byte (CertIdentity returns it verbatim), so an entry
// " spiffe://…" would match no certificate there. Without the trim an operator
// who wrote the list as "comma-space" would get a silent denial of service to a
// legitimate sender instead of a boot refusal. The circle is not widened by
// this: exactly the strings the operator listed get in — only the surrounding
// spaces are removed.
func (a AuthNConfig) TrustedForwarders() []string {
	out := make([]string, 0, len(a.TrustedForwarderSANs))
	for _, san := range a.TrustedForwarderSANs {
		if s := strings.TrimSpace(san); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// BootstrapMintConfig — authn.bootstrap-mint section: the non-interactive
// cluster-admin token mint (#58).
//
// The mint hands out a Hydra-signed RS256 Bearer for a cluster `system_admin`
// ServiceAccount. It cannot be gated by a ReBAC relation (it exists to obtain the
// FIRST token, when no relation exists yet) and it must NOT be gated by network
// position, so its credential is the CALLER'S CLIENT CERTIFICATE: only the SPIFFE
// SANs listed here may call it, enforced on :9091 by authzguard.CallerPolicy.
//
// Two fail-closed layers:
//   - runtime — an empty allow-list denies every caller (the mint has no default
//     caller), in dev as well as production;
//   - boot — an ENABLED mint (signing key present) with an empty allow-list
//     REFUSES TO START in production (Validate), so the insecure combination
//     cannot be reached by omission (core rule #16).
type BootstrapMintConfig struct {
	// SigningKeyEnv — name of the env var holding the bootstrap SA private key
	// PEM (supplied from a k8s Secret; never in YAML). An EMPTY value in that
	// var means the mint is DISABLED — the use-case fails closed with
	// UNAVAILABLE and the boot-guard does not apply. Default:
	// KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM.
	SigningKeyEnv string `mapstructure:"signing-key-env"`
	// AllowedClientSANs — EXACT client-certificate SPIFFE SAN URIs allowed to
	// call MintBootstrapToken (e.g.
	// `spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-seeder`). Empty → nobody
	// may mint. Env: comma-separated
	// KACHO_IAM_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS.
	AllowedClientSANs []string `mapstructure:"allowed-client-sans"`
}

// defaultBootstrapSigningKeyEnv — the env var the composition root has always
// read the bootstrap SA key from.
const defaultBootstrapSigningKeyEnv = "KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM"

// ResolveSigningKeyEnv returns the env-var NAME holding the bootstrap signing
// key, falling back to the documented default when unset.
func (b BootstrapMintConfig) ResolveSigningKeyEnv() string {
	if name := strings.TrimSpace(b.SigningKeyEnv); name != "" {
		return name
	}
	return defaultBootstrapSigningKeyEnv
}

// ResolveSigningKeyPEM reads the bootstrap SA private key PEM from its env var.
// Empty → the mint is disabled. Only os.Getenv is read (no other side-effects),
// consistent with the other Resolve* methods; the VALUE is never logged or
// echoed in an error (security.md).
func (b BootstrapMintConfig) ResolveSigningKeyPEM() string {
	return strings.TrimSpace(os.Getenv(b.ResolveSigningKeyEnv()))
}

// Enabled reports whether the mint is provisioned at all (signing key present).
func (b BootstrapMintConfig) Enabled() bool { return b.ResolveSigningKeyPEM() != "" }

// AllowedSANs returns the allow-list with blanks dropped — an empty result means
// "deny everyone", which is exactly what CallerPolicy enforces.
func (b BootstrapMintConfig) AllowedSANs() []string {
	out := make([]string, 0, len(b.AllowedClientSANs))
	for _, san := range b.AllowedClientSANs {
		if s := strings.TrimSpace(san); s != "" {
			out = append(out, s)
		}
	}
	return out
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
