// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// goodEndpoints — a Config seeded with the non-secret invariants already
// satisfied (mode-agnostic), so the secret/AuthN checks are the only variable.
//
// The trusted-forwarder allow-list is seeded here for the same reason the
// endpoints are: it is a production invariant that every positive path must
// satisfy, and leaving it empty would make unrelated tests fail on it. Tests
// that are ABOUT the allow-list overwrite the field explicitly
// (trusted_forwarders_test.go).
//
// The provider-admin address is seeded on the same terms and for the same reason
// — production demands it be DECLARED (never derived) and over TLS. Tests that
// are ABOUT that hop overwrite it (validate_provider_admin_hop_test.go).
func goodEndpoints(mode config.Mode, sslMode string) config.Config {
	return config.Config{
		// Величины фоновой уборки посеяны здесь на тех же основаниях, что
		// адреса: страж старта требует их положительными в ЛЮБОМ режиме
		// (задача #1292), поэтому нулевой литерал ронял бы каждую пробу,
		// которая не про уборку. Пробы, которые ПРО неё, значения
		// перезаписывают (retention_test.go).
		Retention: config.RetentionConfig{
			Interval:          5 * time.Minute,
			Batch:             1000,
			MaxBatchesPerPass: 20,
		},
		// Период обновления снимка каталога — на тех же основаниях, что и
		// величины уборки выше: страж старта требует его положительным в ЛЮБОМ
		// режиме (задача #1816), потому что выключенного обновления у снимка не
		// бывает — снимок без обновления отстаёт бессрочно и при этом продолжает
		// отвечать. Пробы, которые ПРО него, значение перезаписывают
		// (jobs_test.go).
		Jobs: config.JobsConfig{
			CatalogSnapshot: config.CatalogSnapshotConfig{RefreshInterval: time.Minute},
		},
		APIServer: config.APIServerConfig{
			Endpoint:         "tcp://0.0.0.0:9090",
			InternalEndpoint: "tcp://0.0.0.0:9091",
		},
		Repository: config.RepositoryConfig{
			Postgres: config.PostgresConfig{
				URL:     "postgres://u:p@db:5432/kaname",
				SSLMode: sslMode,
			},
		},
		AuthN: config.AuthNConfig{
			Mode: mode,
			// Доменное имя посадки объявлено ЯВНО: умолчания у поля нет by
			// construction (задача #2127) — из него выводится клеймо адресата,
			// уезжающее в каждом выпущенном токене, поэтому подставить его за
			// оператора нельзя. Фикстура обязана его назвать, как обязан
			// профиль. Значение нарочно НЕ платформенное: подставленное имя
			// чужого продукта — ровно тот дефект, ради которого умолчание снято.
			Domain: "access.example.invalid",
			// Посадка личности объявлена ЯВНО и равна той, в которой сегодня
			// работает всякий развёрнутый профиль: личность проверяет внешний
			// поставщик. Умолчания у поля нет by construction (задача #1125),
			// поэтому фикстура обязана его назвать — как обязан профиль.
			IdentityProvider:     config.IdentityProviderExternal,
			TrustedForwarderSANs: []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"},
			TrustDomainName:      "kacho.cloud",
			HydraAdminURL:        "https://kacho-umbrella-hydra-admin.kacho.svc:4445",
			HydraAdminCAFile:     "/etc/kaname/tls/server/ca.crt",
			// Both hops to the provider's PUBLIC listener declared, in the plain
			// http the provider actually serves there — the shape the deployed
			// profiles carry. They are part of the fixture, not of any test's
			// subject: production refuses a DERIVED address on either
			// (validateProductionProviderPublicHops), so leaving them empty would
			// make every unrelated production case fail for a reason it is not about.
			HydraJWKSURL:  "http://kacho-umbrella-hydra-public.kacho.svc:4444/.well-known/jwks.json",
			HydraTokenURL: "http://kacho-umbrella-hydra-public.kacho.svc:4444/oauth2/token",
		},
	}
}

// TestValidate_Production_RequiresHookSecret — production mode must reject an
// empty hook-shared-secret (the Bearer Hydra uses to authenticate token/refresh
// hooks). A prod boot without it would accept hook calls without auth.
func TestValidate_Production_RequiresHookSecret(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32) // JWKS key present
	// hook-shared-secret left empty (and no env source configured)
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty hook-shared-secret in production")
	}
	if !strings.Contains(err.Error(), "hook-shared-secret") {
		t.Fatalf("Validate() error = %q, want it to name hook-shared-secret", err.Error())
	}
	// Never leak the secret value (there is none here, but guard the contract).
	if strings.Contains(strings.ToLower(err.Error()), "value") {
		t.Fatalf("Validate() error must not reference a secret value: %q", err.Error())
	}
}

// TestValidate_Production_RequiresJWKSKey — production mode must reject an empty
// JWKS encryption key (used to encrypt private_key_pem in the DB).
func TestValidate_Production_RequiresJWKSKey(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	// jwks-encryption-key-hex left empty
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty jwks-encryption-key-hex in production")
	}
	if !strings.Contains(err.Error(), "jwks-encryption-key-hex") {
		t.Fatalf("Validate() error = %q, want it to name jwks-encryption-key-hex", err.Error())
	}
}

// TestValidate_ProductionStrict_RequiresSecrets — production-strict inherits the
// production AuthN-secret requirements (both missing → an error naming both).
func TestValidate_ProductionStrict_RequiresSecrets(t *testing.T) {
	cfg := goodEndpoints(config.ModeProductionStrict, "require")
	// both secrets empty
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty AuthN secrets in production-strict")
	}
	if !strings.Contains(err.Error(), "hook-shared-secret") {
		t.Fatalf("Validate() error = %q, want it to name hook-shared-secret", err.Error())
	}
	if !strings.Contains(err.Error(), "jwks-encryption-key-hex") {
		t.Fatalf("Validate() error = %q, want it to name jwks-encryption-key-hex", err.Error())
	}
}

// TestValidate_Production_FullyPopulated_OK — a production config with both
// AuthN secrets populated validates cleanly.
func TestValidate_Production_FullyPopulated_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a fully-populated production config", err)
	}
}

// TestValidate_Production_SecretFromEnv_OK — secrets resolved from the ENV
// indirection (hook-shared-secret-env / jwks-encryption-key-hex-env) satisfy the
// production requirement (workspace policy: secrets via secretKeyRef/env, never
// YAML).
func TestValidate_Production_SecretFromEnv_OK(t *testing.T) {
	t.Setenv("KANAME_TEST_HOOK_TOKEN", "env-hook-secret")
	t.Setenv("KANAME_TEST_JWKS_KEY", strings.Repeat("cd", 32))
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecretEnv = "KANAME_TEST_HOOK_TOKEN"
	cfg.AuthN.JWKSEncryptionKeyHexEnv = "KANAME_TEST_JWKS_KEY"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when secrets resolve from ENV", err)
	}
}

// ПРОБЫ БОЕВОГО ШИФРОВАНИЯ ДО БАЗЫ ПЕРЕЕХАЛИ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ.
//
// Здесь стояли три пробы (`disable` отвергается · незаданное отвергается ·
// require/verify-ca/verify-full принимаются). Ось судит теперь центральный
// дескриптор посадки — один перечень безопасных значений на всё дерево вместо
// копии у каждого сервиса (задача продукта #1406), — и пробы переехали за ней в
// `cmd/kaname/posture_test.go`, к тому месту, которое эту ось решает.
//
// Оставить их здесь значило бы утверждать про `Validate()` то, чего она больше
// не делает: они стали бы либо красными без предмета, либо (после ослабления)
// пробами, которые не могут упасть.
//
// Переезд ещё и ИСПРАВИЛ их предмет. Снятая копия читала поле настройки, тогда
// как в пул уходит строка `Config.DSN()`: `sslmode` приходит и из сырого URL, а
// пустое поле деривится в `disable`. Стенд, задавший режим прямо в URL, копия
// отвергала при исправной посадке; дескриптор читает ТУ строку, что уходит в
// пул, и такой стенд принимает.

// TestValidate_Dev_EmptySecrets_OK — dev mode legitimately omits AuthN secrets
// (the hook handlers accept calls without a Bearer in dev). Validate must NOT
// require them — dev behavior is unchanged.
func TestValidate_Dev_EmptySecrets_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeDev, "disable")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for dev mode with empty secrets", err)
	}
}
