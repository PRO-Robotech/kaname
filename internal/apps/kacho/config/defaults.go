// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"time"

	"github.com/spf13/viper"
)

// RegisterDefaults sets default values for every config key (defaults are
// kept in one place rather than in struct-tags).
//
// DB / port / SSL values match kacho-vpc so both services deploy uniformly
// through kacho-deploy. ENV-prefix is `KACHO_IAM` (vs `KACHO_VPC`), default
// DB-name is `kacho_iam`.
func RegisterDefaults(v *viper.Viper) {
	// logger
	v.SetDefault("logger.level", "INFO")

	// api-server
	v.SetDefault("api-server.endpoint", "tcp://0.0.0.0:9090")
	v.SetDefault("api-server.internal-endpoint", "tcp://0.0.0.0:9091")
	v.SetDefault("api-server.graceful-shutdown", 10*time.Second)
	// Prometheus /metrics HTTP listener — separate cluster-internal port (never
	// the public tenant gRPC surface). Override via KACHO_IAM_API_SERVER__METRICS_ENDPOINT.
	v.SetDefault("api-server.metrics-endpoint", "tcp://0.0.0.0:9095")
	// Docker Registry v2 `/iam/token` auth-server HTTP listener — a SEPARATE,
	// external-reachable plaintext port (ingress-terminated TLS), distinct from
	// the hooks (:9092) and metrics (:9095) listeners. Issuer/service/TTL shape
	// the minted identity-JWT and must match the data-plane's advertised Bearer
	// realm. Override via KACHO_IAM_API_SERVER__REGISTRY_TOKEN__{ENDPOINT,ISSUER,SERVICE,TTL}.
	v.SetDefault("api-server.registry-token.endpoint", "tcp://0.0.0.0:9096")
	v.SetDefault("api-server.registry-token.issuer", "https://api.kacho.local/iam/token")
	v.SetDefault("api-server.registry-token.service", "registry.kacho.local")
	v.SetDefault("api-server.registry-token.ttl", 5*time.Minute)
	// Cluster-INTERNAL Hydra-JWKS proxy HTTP listener (`GET /.well-known/jwks.json`)
	// — a SEPARATE cluster-internal port (default `tcp://0.0.0.0:9097`), served ONLY
	// on the kacho-iam-internal Service (never external, ban #6) over one-way
	// server-TLS. Short-TTL caching reverse-proxy of Hydra's PUBLIC JWKS so the
	// data-plane fetches verification keys from iam (Hydra stays the signer).
	// Override via KACHO_IAM_API_SERVER__JWKS_PROXY__ENDPOINT.
	v.SetDefault("api-server.jwks-proxy.endpoint", "tcp://0.0.0.0:9097")

	// repository
	v.SetDefault("repository.postgres.url", "postgres://iam@localhost:5432/kacho_iam")
	v.SetDefault("repository.postgres.slave-url", "")
	v.SetDefault("repository.postgres.max-conns", 0)
	// Одна реплика — минимальная посадка, которая вообще работает. Ноль здесь
	// означал бы «не проверять»: произведение обратилось бы в ноль и прошло бы
	// любую проверку.
	v.SetDefault("repository.postgres.replica-budget", 1)
	v.SetDefault("repository.postgres.ssl-mode", "disable")
	v.SetDefault("repository.postgres.password-from-env", "KACHO_IAM_DB_PASSWORD")

	// authz — кто принимает решение о доступе.
	//
	// Умолчания названы ЯВНО, а не оставлены нулевым значением структуры:
	// «источник вердикта — как получится» не является состоянием, в котором
	// служба прав вправе подняться. Пусто = решает движок по каждому типу;
	// сверка включена = «расхождений ноль» отличимо от «сравнений ноль».
	v.SetDefault("authz.verdict-form-types", []string{})
	v.SetDefault("authz.shadow-compare", true)

	// authn
	// Safe-by-default (prod-readiness F14): an un-configured binary fails CLOSED
	// (production = anonymous → PermissionDenied), never dev (anonymous → full
	// access). Local fixtures / the newman stand opt INTO dev explicitly via
	// KACHO_IAM_AUTH_MODE=dev (values.dev.yaml carries mode: dev).
	v.SetDefault("authn.mode", "production")
	// AuthN core — configurable domain + Hydra issuer + hooks. Secrets are
	// resolved from env so they don't sit in YAML/ConfigMap.
	v.SetDefault("authn.domain", "api.kacho.cloud")
	v.SetDefault("authn.hydra-issuer", "")       // resolved via ResolveHydraIssuer() when empty
	v.SetDefault("authn.hydra-jwks-url", "")     // resolved via ResolveHydraJWKSURL() (env KACHO_IAM_HYDRA_JWKS_URL)
	v.SetDefault("authn.hook-shared-secret", "") // no default — security-sensitive
	v.SetDefault("authn.hook-shared-secret-env", "KACHO_IAM_HOOK_TOKEN")
	v.SetDefault("authn.jwks-encryption-key-hex", "")
	v.SetDefault("authn.jwks-encryption-key-hex-env", "KACHO_IAM_JWKS_ENC_KEY")
	v.SetDefault("authn.hooks-http-endpoint", "tcp://0.0.0.0:9092")
	// SA-key одноразовый private_key_pem отдаётся только в op.response; клиент
	// поллит Operation.Get, чтобы его забрать. Затирание выдерживает это окно,
	// иначе клиент проигрывает гонку и получает ПУСТОЕ поле (затирание очищает
	// поле, а не подставляет метку — метки нет). Override —
	// KACHO_IAM_SAKEY_REDACT_GRACE (или KACHO_IAM_AUTHN__SAKEY_REDACT_GRACE).
	v.SetDefault("authn.sakey-redact-grace", 120*time.Second)
	// User-токен: одноразовый private_key_pem отдаётся только в op.response; клиент
	// поллит Operation.Get, чтобы его забрать. Grace-окно выдерживает это окно.
	// Override — KACHO_IAM_USERTOKEN_REDACT_GRACE.
	v.SetDefault("authn.usertoken-redact-grace", 120*time.Second)
	// SA-key lifetime discipline. A service-account key IS the machine's
	// credential, and machine principals are exempt from step-up (a machine has
	// no second factor) — "exempt" is only defensible while the credential is
	// bounded in time. So the omitted-ttl_seconds case resolves to a finite
	// default instead of "never expires", and requests carry an inclusive
	// ceiling. Overrides: KACHO_IAM_SAKEY_DEFAULT_TTL / KACHO_IAM_SAKEY_MAX_TTL.
	v.SetDefault("authn.sakey-default-ttl", 90*24*time.Hour)
	v.SetDefault("authn.sakey-max-ttl", 365*24*time.Hour)
	// Per-client access_token_lifespan for the SA-key OAuth2 client. Default 0 =
	// omit the field and inherit the provider-global TTL, so an existing
	// deployment is unchanged until its profile pins a value (values.prod.yaml
	// does). Override: KACHO_IAM_SAKEY_ACCESS_TOKEN_TTL.
	v.SetDefault("authn.sakey-access-token-ttl", time.Duration(0))
	// Sender-constrained (RFC 9449) tokens for SA keys. Binding is per-client
	// REGISTRATION metadata, so it takes effect only for keys issued after it is
	// enabled — pre-existing keys keep minting plain bearers until rotated.
	// Default false; the edge enforcement knob must be turned on only AFTER this
	// one, otherwise every existing service-account token is rejected.
	// Override: KACHO_IAM_SAKEY_BIND_DPOP.
	v.SetDefault("authn.sakey-bind-dpop", false)
	// bootstrap-mint — the cluster-admin token mint (#58). The signing key lives
	// in a k8s Secret, referenced BY ENV NAME here (never inlined in YAML). The
	// caller allow-list defaults to EMPTY = nobody may mint: the mint has no
	// default caller, so an operator must name the client-certificate SPIFFE SANs
	// explicitly (and an ENABLED mint with an empty list refuses to boot in
	// production — validate.go). Override —
	// KACHO_IAM_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS (comma-separated).
	v.SetDefault("authn.bootstrap-mint.signing-key-env", "KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM")
	v.SetDefault("authn.bootstrap-mint.allowed-client-sans", []string{})

	// OpenFGA, the gateway-internal drainer, Enterprise SSO, Governance,
	// Federation/CAEP/ComplianceReport/Notify and the dead healthcheck
	// placeholder were all removed (dead config) — OpenFGA + the drainer are
	// configured from KACHO_IAM_* env vars in the composition root. The
	// Prometheus metrics listener default is set above (api-server.metrics-endpoint).
}
