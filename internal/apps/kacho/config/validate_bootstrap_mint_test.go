// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// validate_bootstrap_mint_test.go — production boot-guard for the bootstrap-admin
// token mint (core rule #16: every service carries a fail-closed Config.Validate).
//
// InternalBootstrapTokenService/MintBootstrapToken issues a cluster `system_admin`
// Bearer. Its only credential gate is the per-RPC SPIFFE allow-list enforced by
// authzguard on :9091. An ENABLED mint (bootstrap signing key present) with an
// EMPTY allow-list therefore has no caller gate at all — the exact
// "network position is the gate" posture this hardening removes. A production
// boot in that state must be REFUSED, not warned about (an unread guard is a dead
// guard).
//
// Symmetrically: a deployment that does not enable the mint at all (no signing
// key) must still boot — the guard is scoped to the enabled mint, so charts that
// never use it are unaffected.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// prodCfgWithSecrets — a production Config whose unrelated production invariants
// (hook secret, JWKS key, TLS-mode DSN) are already satisfied.
func prodCfgWithSecrets(t *testing.T) config.Config {
	t.Helper()
	cfg := goodEndpoints(config.ModeProduction, "require")
	cfg.AuthN.HookSharedSecret = "a-strong-shared-secret"
	cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
	return cfg
}

// TestValidate_Production_BootstrapMintEnabled_EmptyAllowlist_Rejected — the
// boot-guard: mint enabled + no caller allow-list → refuse to start.
func TestValidate_Production_BootstrapMintEnabled_EmptyAllowlist_Rejected(t *testing.T) {
	cfg := prodCfgWithSecrets(t)
	cfg.AuthN.BootstrapMint.SigningKeyEnv = "KACHO_IAM_TEST_BOOTSTRAP_KEY"
	t.Setenv("KACHO_IAM_TEST_BOOTSTRAP_KEY", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")
	// allowed-client-sans deliberately empty

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want refuse-to-start: an enabled bootstrap mint with no caller allow-list is a credential-free cluster-admin mint")
	}
	if !strings.Contains(err.Error(), "allowed-client-sans") {
		t.Fatalf("Validate() error = %q, want it to name authn.bootstrap-mint.allowed-client-sans", err.Error())
	}
	// The error must never echo the key material it checked for presence.
	if strings.Contains(err.Error(), "BEGIN PRIVATE KEY") {
		t.Fatalf("Validate() error leaked key material: %q", err.Error())
	}
}

// TestValidate_Production_BootstrapMintEnabled_WithAllowlist_OK — the configured
// mint boots.
func TestValidate_Production_BootstrapMintEnabled_WithAllowlist_OK(t *testing.T) {
	cfg := prodCfgWithSecrets(t)
	cfg.AuthN.BootstrapMint.SigningKeyEnv = "KACHO_IAM_TEST_BOOTSTRAP_KEY"
	cfg.AuthN.BootstrapMint.AllowedClientSANs = []string{
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-seeder",
	}
	t.Setenv("KACHO_IAM_TEST_BOOTSTRAP_KEY", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for an allow-listed bootstrap mint", err)
	}
}

// TestValidate_Production_BootstrapMintDisabled_OK — no signing key → the mint is
// disabled; the guard must not block deployments that never use it.
func TestValidate_Production_BootstrapMintDisabled_OK(t *testing.T) {
	cfg := prodCfgWithSecrets(t)
	cfg.AuthN.BootstrapMint.SigningKeyEnv = "KACHO_IAM_TEST_BOOTSTRAP_KEY"
	t.Setenv("KACHO_IAM_TEST_BOOTSTRAP_KEY", "")

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when the bootstrap mint is not enabled", err)
	}
}

// TestValidate_Dev_BootstrapMintEnabled_EmptyAllowlist_OK — dev in-process
// fixtures are unaffected (the guard is production-scoped, like every other
// production invariant here); the RUNTIME gate in authzguard still denies a
// caller-less mint in dev.
func TestValidate_Dev_BootstrapMintEnabled_EmptyAllowlist_OK(t *testing.T) {
	cfg := goodEndpoints(config.ModeDev, "disable")
	cfg.AuthN.BootstrapMint.SigningKeyEnv = "KACHO_IAM_TEST_BOOTSTRAP_KEY"
	t.Setenv("KACHO_IAM_TEST_BOOTSTRAP_KEY", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----")

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil in dev mode", err)
	}
}
