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

	// repository
	v.SetDefault("repository.postgres.url", "postgres://iam@localhost:5432/kacho_iam")
	v.SetDefault("repository.postgres.slave-url", "")
	v.SetDefault("repository.postgres.max-conns", 0)
	v.SetDefault("repository.postgres.ssl-mode", "disable")
	v.SetDefault("repository.postgres.password-from-env", "KACHO_IAM_DB_PASSWORD")

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
	v.SetDefault("authn.hook-shared-secret", "") // no default — security-sensitive
	v.SetDefault("authn.hook-shared-secret-env", "KACHO_IAM_HOOK_TOKEN")
	v.SetDefault("authn.jwks-encryption-key-hex", "")
	v.SetDefault("authn.jwks-encryption-key-hex-env", "KACHO_IAM_JWKS_ENC_KEY")
	v.SetDefault("authn.jwks-rotation-days", 90)
	v.SetDefault("authn.session-revocations-cache-ttl-seconds", 5)
	v.SetDefault("authn.hooks-http-endpoint", "tcp://0.0.0.0:9092")

	// OpenFGA, the gateway-internal drainer, Enterprise SSO, Governance,
	// Federation/CAEP/ComplianceReport/Notify and the dead healthcheck
	// placeholder were all removed (dead config) — OpenFGA + the drainer are
	// configured from KACHO_IAM_* env vars in the composition root. The
	// Prometheus metrics listener default is set above (api-server.metrics-endpoint).
}
