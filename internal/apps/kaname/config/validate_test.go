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
// The identity posture and the provider-admin address used to be seeded here on
// the same terms; both are gone with the external identity provider
// (kaname#363).
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
		// Окно отзыва собственной двери — на тех же основаниях, что величины
		// уборки и обновления снимка выше: страж старта требует его
		// положительным в ЛЮБОМ режиме (задача #2307), потому что умолчания у
		// окна отзыва быть не может — кешируется только положительный вердикт,
		// и срок жизни записи ЕСТЬ время, которое субъект с отобранным правом
		// продолжает проходить. Пробы, которые ПРО него, значение
		// перезаписывают (authz_window_test.go).
		AuthZ: config.AuthZConfig{CacheTTL: 5 * time.Second},
		// Четыре собственных потолка — на тех же основаниях, что величины выше:
		// страж старта требует их объявленными в ЛЮБОМ режиме (приёмка
		// `KAN-QUOTA-1`, `П25`), потому что умолчания у них быть не может —
		// внешнего авторитета в самостоятельной установке нет, и спросить
		// величину не у кого. Пробы, которые ПРО них, значения перезаписывают
		// (own_ceilings_test.go).
		OwnCeilings: config.OwnCeilingsConfig{
			AccountsPerIdentity:          ptrInt64(5),
			CredentialsPerUser:           ptrInt64(12),
			CredentialsPerServiceAccount: ptrInt64(24),
			AccessKeysPerUser:            ptrInt64(3),
		},
		// Ограничение частоты писем на адрес — положительное в ЛЮБОМ режиме
		// (приёмка ID-MAIL-1, MAIL-43): умолчание объявлено загрузчику, а не
		// ручке, поэтому голая структура его не несёт и ноль здесь есть
		// попытка снять ограничение. Пробы, которые ПРО него, значение
		// перезаписывают (invite_mail_rate_limit_test.go).
		Invite: config.InviteConfig{MailRateLimit: config.InviteMailRateLimitConfig{
			MaxPerWindow: config.DefaultInviteMailPerWindow,
			Window:       config.DefaultInviteMailWindow,
		}},
		APIServer: config.APIServerConfig{
			Endpoint:         "tcp://0.0.0.0:9090",
			InternalEndpoint: "tcp://0.0.0.0:9091",
			// Свой контур выдачи ключей служебных учёток — требование посадки
			// `own` (задача #337): слушатель, на котором монтируется
			// токен-эндпоинт платформы.
			RegistryToken: registryTokenLaneSettings(),
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
			// Величины своего входа и своей чеканки посеяны ниже на тех же
			// основаниях, что величины уборки выше: без них каждая боевая проба,
			// которая не про полосу, падала бы на требованиях полосы.
			SecondFactorEncryptionKeyHex: strings.Repeat("cd", 32),
			SelfServiceFreshness:         15 * time.Minute,
			TokenSigning:                 ownMintingSettings(),
			ClientToken:                  clientTokenLaneSettings(),
			PresentedCredential:          presentedCredentialSettings(),
			Login:                        loginLaneSettings(),
			Registration:                 registrationSettings(),
			AccessKeys:                   accessKeySettings(),
			Ceremony:                     ceremonyLifespanSettings(),
			TrustedForwarderSANs:         []string{"spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"},
			TrustDomainName:              "kacho.cloud",
		},
	}
}

// TestValidate_Production_RequiresJWKSKey — production mode must reject an empty
// JWKS encryption key (used to encrypt private_key_pem in the DB).
func TestValidate_Production_RequiresJWKSKey(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
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
// production AuthN-secret requirement (the wrapping key missing → an error naming
// it). The hooks' shared secret used to be the second requirement; it went with
// the hooks (kaname#363).
func TestValidate_ProductionStrict_RequiresSecrets(t *testing.T) {
	cfg := goodEndpoints(config.ModeProductionStrict, "require")
	// the wrapping key is empty
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty AuthN secrets in production-strict")
	}
	if !strings.Contains(err.Error(), "jwks-encryption-key-hex") {
		t.Fatalf("Validate() error = %q, want it to name jwks-encryption-key-hex", err.Error())
	}
}

// TestValidate_Production_FullyPopulated_OK — a production config with the AuthN
// secret populated validates cleanly.
func TestValidate_Production_FullyPopulated_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a fully-populated production config", err)
	}
}

// TestValidate_Production_SecretFromEnv_OK — the secret resolved from the ENV
// indirection (jwks-encryption-key-hex-env) satisfies the production requirement
// (workspace policy: secrets via secretKeyRef/env, never YAML).
func TestValidate_Production_SecretFromEnv_OK(t *testing.T) {
	t.Setenv("KANAME_TEST_JWKS_KEY", strings.Repeat("cd", 32))
	cfg := goodEndpoints(config.ModeProduction, "require")
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

// TestValidate_Dev_EmptySecrets_OK — dev mode legitimately omits AuthN secrets.
// Validate must NOT require them — dev behavior is unchanged.
func TestValidate_Dev_EmptySecrets_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeDev, "disable")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for dev mode with empty secrets", err)
	}
}

// ptrInt64 — указатель на величину посадки. Ноль от «не объявлено» отличается
// именно указателем, поэтому литерал здесь не годится.
func ptrInt64(v int64) *int64 { return &v }
