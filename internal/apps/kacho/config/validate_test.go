// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// goodEndpoints — a Config seeded with the non-secret invariants already
// satisfied (mode-agnostic), so the secret/AuthN checks are the only variable.
func goodEndpoints(mode config.Mode, sslMode string) config.Config {
	return config.Config{
		APIServer: config.APIServerConfig{
			Endpoint:         "tcp://0.0.0.0:9090",
			InternalEndpoint: "tcp://0.0.0.0:9091",
		},
		Repository: config.RepositoryConfig{
			Postgres: config.PostgresConfig{
				URL:     "postgres://u:p@db:5432/kacho_iam",
				SSLMode: sslMode,
			},
		},
		AuthN: config.AuthNConfig{Mode: mode},
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
	t.Setenv("KACHO_IAM_TEST_HOOK_TOKEN", "env-hook-secret")
	t.Setenv("KACHO_IAM_TEST_JWKS_KEY", strings.Repeat("cd", 32))
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecretEnv = "KACHO_IAM_TEST_HOOK_TOKEN"
	cfg.AuthN.JWKSEncryptionKeyHexEnv = "KACHO_IAM_TEST_JWKS_KEY"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when secrets resolve from ENV", err)
	}
}

// TestValidate_Dev_EmptySecrets_OK — dev mode legitimately omits AuthN secrets
// (the hook handlers accept calls without a Bearer in dev). Validate must NOT
// require them — dev behavior is unchanged.
func TestValidate_Dev_EmptySecrets_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeDev, "disable")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for dev mode with empty secrets", err)
	}
}
