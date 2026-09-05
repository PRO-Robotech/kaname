// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// bootstrap_mint_load_test.go — the CONFIG-PATH contract for the bootstrap-mint
// caller allow-list (#58 hardening).
//
// validate_bootstrap_mint_test.go pins the boot-guard on an already-populated
// Config struct. This file pins the step BEFORE that: the allow-list an operator
// writes actually ARRIVES in the struct. That step is the whole operator path —
// the Helm chart renders
//
//	authn:
//	  bootstrap-mint:
//	    allowed-client-sans:
//	      - spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator
//
// into kacho-iam's config.yaml (charts/kacho-iam/templates/configmap.yaml), and
// authzguard.CallerPolicy admits exactly those SANs. A silent mismatch between
// the YAML key and the mapstructure tag would not fail any build: it would render
// an allow-list nobody reads, the mint would deny EVERY caller (fail-closed, so no
// alarm fires), and in production the boot-guard would then refuse to start a
// chart that looks correctly configured. Hence a test on the literal key path.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// chartShapedConfig — the exact YAML shape charts/kacho-iam/templates/configmap.yaml
// emits for the authn section (mode + the bootstrap-mint allow-list).
const chartShapedConfig = `
authn:
  mode: "production-strict"
  bootstrap-mint:
    allowed-client-sans:
      - "spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator"
`

// writeConfig drops content into a temp config.yaml and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

// TestLoad_BootstrapMintAllowlist_FromChartShapedYAML — the key path the Helm
// chart writes is the key path Load reads.
func TestLoad_BootstrapMintAllowlist_FromChartShapedYAML(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, chartShapedConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.AuthN.BootstrapMint.AllowedSANs()
	want := "spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("AllowedSANs() = %v, want [%s] — the chart's authn.bootstrap-mint.allowed-client-sans key must reach the struct", got, want)
	}
}

// TestLoad_BootstrapMintAllowlist_FromEnv — the documented comma-separated env
// override (the escape hatch when a profile cannot be re-rendered).
func TestLoad_BootstrapMintAllowlist_FromEnv(t *testing.T) {
	t.Setenv("KACHO_IAM_AUTHN__BOOTSTRAP_MINT__ALLOWED_CLIENT_SANS",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator,spiffe://kacho.cloud/ns/kacho/sa/kacho-release-runner")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.AuthN.BootstrapMint.AllowedSANs()
	if len(got) != 2 ||
		got[0] != "spiffe://kacho.cloud/ns/kacho/sa/kacho-bootstrap-operator" ||
		got[1] != "spiffe://kacho.cloud/ns/kacho/sa/kacho-release-runner" {
		t.Fatalf("AllowedSANs() = %v, want the two comma-separated SANs", got)
	}
}

// TestLoad_BootstrapMintAllowlist_DefaultEmpty — an operator who configures
// NOTHING gets a deny-everyone mint. The default must never be "some caller".
func TestLoad_BootstrapMintAllowlist_DefaultEmpty(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.AuthN.BootstrapMint.AllowedSANs(); len(got) != 0 {
		t.Fatalf("AllowedSANs() = %v, want empty — an unconfigured cluster-admin mint must have NO callers", got)
	}
}

// TestLoad_BootstrapMintSigningKeyEnv_Default — the mint's ENABLEMENT switch is
// the presence of the signing key in the named env var; the default name is the
// one the chart's secretKeyRef populates
// (charts/kacho-iam/templates/deployment.yaml).
func TestLoad_BootstrapMintSigningKeyEnv_Default(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.AuthN.BootstrapMint.ResolveSigningKeyEnv(); got != "KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM" {
		t.Fatalf("ResolveSigningKeyEnv() = %q, want KACHO_IAM_BOOTSTRAP_SA_PRIVATE_KEY_PEM (the env the chart wires from the Secret)", got)
	}
}
