// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
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
// The gateway-internal drainer is configured from KACHO_IAM_* env vars in the
// composition root (cmd/kacho-iam), not from this YAML.
//
// Every section is `mapstructure`-tagged (viper uses mapstructure for
// Unmarshal by default). Defaults live in defaults.go.
type Config struct {
	Logger     LoggerConfig     `mapstructure:"logger"`
	APIServer  APIServerConfig  `mapstructure:"api-server"`
	Repository RepositoryConfig `mapstructure:"repository"`
	AuthN      AuthNConfig      `mapstructure:"authn"`
	// Jobs — фоновые задания сервиса (задача #1264). Секция заведена по
	// прецеденту сметателя целей nlb: интервал работы, удаляющей РЕСУРС
	// АРЕНДАТОРА по времени, живёт в конфигурации со стражем старта, а не
	// константой в композиционном корне.
	Jobs JobsConfig `mapstructure:"jobs"`
	// Retention — величины фоновой уборки таблиц, чей рост задаёт внешний
	// (задача #1292). Порогов в ней нет: они вычисляются из `pkg/tokenpolicy`,
	// см. retention.go.
	Retention RetentionConfig `mapstructure:"retention"`
	// Manifests — ДОСТАВКА манифестов модулей работающей службе (задача #1875):
	// каталог, куда посадка их монтирует, и объявление того, что посадка на них
	// опирается. Секция заведена вперёд своих потребителей: пока каталог не
	// объявлен, служба поднимается ровно как прежде — см. manifests.go.
	Manifests ManifestsConfig `mapstructure:"manifests"`
	// Секции `authz` здесь НЕТ, и это не пропуск. Она держала ровно две ручки —
	// перечень типов, переключённых на реляционную форму, и признак теневой
	// сверки, — и обе снялись вместе с внешним движком отношений: переключать
	// больше нечего, сверять не с чем. Оставленная пустой секция была бы
	// обещанием настройки, которой нет.
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

	// RateLimit — ПОТОЛОК ТЕМПА и ОДНОВРЕМЕННОСТИ на вызывающего, по одному
	// набору на слушатель.
	//
	// У iam он значит больше, чем у соседей: iam стоит на пути запроса ВСЕХ
	// остальных доменов (решение о доступе спрашивают у него на каждом RPC),
	// поэтому неограниченный поток одного вызывающего сюда бьёт не по одному
	// сервису, а по всей платформе.
	//
	// Молчание посадки означает ПОЛ ПЛАТФОРМЫ
	// (`grpcsrv.PlatformPublicAdmission` / `PlatformInternalAdmission`), а не
	// ноль: ноль механизм читает как «не ограничиваем», и слушатель выглядел бы
	// защищённым, ни разу не отказав. Посадка вправе назвать свои величины, но
	// только ВЕСЬ набор из четырёх осей — частичное объявление отвергается
	// стартом с именем слушателя.
	RateLimit RateLimitConfig `mapstructure:"rate-limit"`
}

// RateLimitConfig — величины допуска обоих слушателей в том виде, в каком их
// объявляет файл настроек.
//
// Структура ручек — общая с фундаментом (`grpcsrv.AdmissionKnobs`): те же
// четыре оси читают три семейства настроек платформы, и три копии тегов
// разъехались бы на первой же новой оси — молча, потому что незнакомый ключ
// viper игнорирует.
type RateLimitConfig struct {
	// Public — величины публичного слушателя, на ПРИНЦИПАЛА.
	Public grpcsrv.AdmissionKnobs `mapstructure:"public"`
	// Internal — величины внутреннего слушателя, на ЛИЧНОСТЬ СЕРТИФИКАТА.
	Internal grpcsrv.AdmissionKnobs `mapstructure:"internal"`
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
//	ReplicaBudget    — под сколько реплик рассчитана посадка (см. PostgresConfig).
//	SSLMode          — disable|require|verify-ca|verify-full (validated in Validate).
//	PasswordFromEnv  — name of the ENV var the password is read from and
//	                   substituted into URL and SlaveURL. Default — KACHO_IAM_DB_PASSWORD.
type PostgresConfig struct {
	URL      string `mapstructure:"url"`
	SlaveURL string `mapstructure:"slave-url"`
	MaxConns int    `mapstructure:"max-conns"`

	// ReplicaBudget — сколько реплик этой посадки могут работать ОДНОВРЕМЕННО.
	//
	// Служба не знает этого о себе и знать не обязана: под сколько реплик её
	// раскладывают — свойство раскладки, а не процесса. Поэтому величину
	// СООБЩАЮТ, и сообщает её тот же шаблон, который рендерит число реплик, —
	// одно значение, два места применения, разойтись им негде.
	//
	// Нужна затем, что предел соединений у базы ОБЩИЙ на все реплики, а пул
	// объявлен на ОДНУ. Произведение не записано нигде, и потому расхождение
	// между обещанным и принимаемым не видно ни в одном файле по отдельности
	// (загрузочный страж — `assertConnBudgetFits` в composition root).
	ReplicaBudget   int    `mapstructure:"replica-budget"`
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
//	JWKSEncryptionKeyHex  — 32-байтовый ключ ОБЁРТКИ приватной половины
//	                        подписного ключа, в hex (64 символа). Ею
//	                        оборачивается приватная половина в ключнице
//	                        (задача #897); ручка об этом предмете в дереве
//	                        ОДНА, и её значение меняет исход старта — см.
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
	Mode Mode `mapstructure:"mode"`
	// IdentityProvider — ПОСАДКА ЛИЧНОСТИ: чем стенд проверяет человека,
	// внешним поставщиком удостоверений или своей чеканкой (задача #1125).
	//
	// Разводит требования старта: под `external` обязательны три адреса
	// поставщика, под `own` — не требуется ни одного, зато обязательна своя
	// чеканка и свой вход человека. Умолчания в коде НЕТ намеренно (см.
	// identity_provider.go): незаданное значение — отказ старта, а не молча
	// выбранная полоса. Перечень требований каждой полосы — LaneRequirements.
	IdentityProvider IdentityProvider `mapstructure:"identity-provider"`
	Domain           string           `mapstructure:"domain"`
	HydraIssuer      string           `mapstructure:"hydra-issuer"`
	HydraAdminURL    string           `mapstructure:"hydra-admin-url"`
	// HydraAdminCAFile — PEM bundle the provider-admin hop is verified against
	// when it is served over TLS. Empty ⇒ the default transport (system roots),
	// which an internal-CA certificate never chains to. Set ⇒ the bundle becomes
	// the ONLY anchor, and one that cannot be read refuses the start.
	HydraAdminCAFile string `mapstructure:"hydra-admin-ca-file"`
	// HydraAdminTokenEnv — ИМЯ переменной окружения, из которой берётся
	// административный предъявитель внешнего поставщика.
	//
	// Само значение в YAML не пишется никогда (секрет), поэтому полем настройки
	// объявлено имя переменной — та же косвенность, что у общего секрета хуков
	// и у ключа обёртки.
	//
	// ПОЧЕМУ ЭТО ПОЛЕ ВООБЩЕ ПОЯВИЛОСЬ. Ручка существовала и прежде, но
	// читалась прямым обращением к окружению В КОРНЕ СБОРКИ — то есть была
	// невидима проверке настройки при старте by construction. Проверка читает
	// ПОЛЯ, и только их; значит ручка мимо полей не участвует в полосности
	// посадки и не может быть снята значением поля посадки. Полосность,
	// неполная ровно на ту ручку, которую проверка не видит, — это тот же
	// класс, что чинила подфаза Ф4б-0.
	HydraAdminTokenEnv string `mapstructure:"hydra-admin-token-env"`
	HydraTokenURL      string `mapstructure:"hydra-token-url"`
	// HydraTokenCAFile / HydraJWKSCAFile — the same anchor discipline for the two
	// hops to the provider's PUBLIC listener: the token exchange (a signed client
	// assertion out, the minted bearer back) and the JWKS upstream (the keyset the
	// data-plane verifies every token against). Empty ⇒ the default transport,
	// which is what a plaintext in-cluster address needs and all it needs. Set ⇒
	// the bundle becomes the ONLY anchor, and one that cannot be read refuses the
	// start rather than falling back to the system roots — that fallback is the
	// state nobody can see, because the operator configured verification against
	// the internal CA and the process is not doing it.
	HydraTokenCAFile        string `mapstructure:"hydra-token-ca-file"`
	HydraJWKSURL            string `mapstructure:"hydra-jwks-url"`
	HydraJWKSCAFile         string `mapstructure:"hydra-jwks-ca-file"`
	HookSharedSecret        string `mapstructure:"hook-shared-secret"`
	HookSharedSecretEnv     string `mapstructure:"hook-shared-secret-env"`
	JWKSEncryptionKeyHex    string `mapstructure:"jwks-encryption-key-hex"`
	JWKSEncryptionKeyHexEnv string `mapstructure:"jwks-encryption-key-hex-env"`
	// TokenSigning — СВОЯ чеканка токенов (задача #897): издатель, алгоритм,
	// перечень допустимых алгоритмов приёма, путь нашей записи публикуемого
	// набора и срок ключа. Пока выключена, её настройки не требуются; будучи
	// включённой, требует их все — незаданное здесь означает «не сужаем».
	TokenSigning TokenSigningConfig `mapstructure:"token-signing"`
	// ClientToken — токен-эндпоинт платформы (задача #898): приём вида выдачи
	// «учётные данные клиента» с аутентификацией подписанным утверждением.
	// Пока выключен, его настройки не требуются; будучи включённым, требует их
	// все — и требует включённой своей чеканки, потому что выпускает НАШИМ
	// подписантом и объявляет НАШЕГО издателя ожидаемым адресатом утверждения.
	ClientToken          ClientTokenConfig `mapstructure:"client-token"`
	HooksHTTPEndpoint    string            `mapstructure:"hooks-http-endpoint"`
	SAKeyRedactGrace     time.Duration     `mapstructure:"sakey-redact-grace"`
	UserTokenRedactGrace time.Duration     `mapstructure:"usertoken-redact-grace"`
	SAKeyDefaultTTL      time.Duration     `mapstructure:"sakey-default-ttl"`
	SAKeyMaxTTL          time.Duration     `mapstructure:"sakey-max-ttl"`
	SAKeyAccessTokenTTL  time.Duration     `mapstructure:"sakey-access-token-ttl"`
	SAKeyBindDPoP        bool              `mapstructure:"sakey-bind-dpop"`
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

	// TrustAnyForwarder — ЯВНЫЙ опт-ин «круг не сужаем», действующий ТОЛЬКО вне
	// боевого режима. Нужен для локальных in-process фикстур, где ни сертификатов,
	// ни шлюза нет.
	//
	// Он существует потому, что стража круга срабатывает на ЛЮБОМ старте, а не
	// только в боевом режиме: контроль, чья ветка на локальном стенде не
	// исполняется ни разу, обнаруживает «забыл выставить круг» только на боевом
	// профиле, где цена ошибки максимальна. Оставленный незаданным (false) = отказ
	// старта на пустом круге. В боевом режиме НЕ действует — иначе это была бы
	// ручка, снимающая защиту на развёрнутом стенде.
	TrustAnyForwarder bool `mapstructure:"trust-any-forwarder"`
}

// TrustedForwarders — the circle of senders that REALLY reaches
// grpcsrv.WithTrustedForwarders on both listeners.
//
// Single source of this value per process: the wiring (cmd/kacho-iam/serve.go),
// the boot guard (validateProductionTrustedForwarders) and the boot self-report
// (cmd/kacho-iam/bootposture.go) all read this one object and ask its ONE
// predicate. So "the guard passed" ⟺ "the circle is really narrowed" — by
// construction, not by three separately written bodies happening to agree.
//
// Normalisation of the circle (blank entries, surrounding whitespace,
// duplicates) lives in the type's constructor and is not restated here: two
// places about one subject drift apart silently. See
// grpcsrv.NewTrustedForwarders.
func (a AuthNConfig) TrustedForwarders() grpcsrv.TrustedForwarders {
	return grpcsrv.NewTrustedForwarders(a.TrustedForwarderSANs...)
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
