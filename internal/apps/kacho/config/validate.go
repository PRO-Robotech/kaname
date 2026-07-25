// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"strings"

	"go.uber.org/multierr"
)

// Validate checks Config invariants (pure function — no logger, no
// side-effects).
//
// Returns a multierr containing ALL detected problems at once.
//
// Checks base fields + (in production modes) the required AuthN secrets +
// production-strict TLS invariants.
func (c Config) Validate() error {
	var errs error

	errs = multierr.Append(errs, c.validateMode())

	// logger.level must be a known level so a typo fails fast at boot rather
	// than silently degrading observability. SlogLevel reports the allowed set.
	if _, err := c.Logger.SlogLevel(); err != nil {
		errs = multierr.Append(errs, err)
	}

	if listenAddress(c.APIServer.Endpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.endpoint is empty"))
	}
	if listenAddress(c.APIServer.InternalEndpoint) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("api-server.internal-endpoint is empty"))
	}

	switch strings.ToLower(c.Repository.Postgres.SSLMode) {
	case "disable", "require", "verify-ca", "verify-full":
	case "":
		// permitted — baseDSN will substitute "disable"
	default:
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.ssl-mode=%q (allowed: disable, require, verify-ca, verify-full)",
				c.Repository.Postgres.SSLMode))
	}

	if strings.TrimSpace(c.Repository.Postgres.URL) == "" {
		errs = multierr.Append(errs,
			fmt.Errorf("repository.postgres.url is empty"))
	}

	// conditions cache knobs must be positive (a non-positive size/TTL would
	// silently disable or thrash the recognition cache).
	if c.Conditions.CacheSize <= 0 {
		errs = multierr.Append(errs,
			fmt.Errorf("conditions.cache-size must be > 0 (got %d)", c.Conditions.CacheSize))
	}
	if c.Conditions.CacheTTLSeconds <= 0 {
		errs = multierr.Append(errs,
			fmt.Errorf("conditions.cache-ttl-seconds must be > 0 (got %d)", c.Conditions.CacheTTLSeconds))
	}

	if c.AuthN.Mode.IsProduction() {
		errs = multierr.Append(errs, c.validateProductionAuthNSecrets())
		errs = multierr.Append(errs, c.validateProductionBootstrapMint())

		// DB-TLS gate — applies to EVERY production variant, not strict-only. All
		// IAM data (user/SA records, session-revocation + token rows, the
		// transient SA-key client_secret briefly staged in operations.response_data
		// before redaction) traverses this link; a plaintext connection
		// (sslmode=disable, or the empty default baseDSN substitutes with
		// "disable") is a boot-time misconfiguration in production, exactly like a
		// missing mTLS listener. A network-adjacent attacker on a plaintext DB link
		// can passively read credentials and IAM rows (CWE-319). Dev mode is
		// unaffected — see InsecureDevWarnings.
		switch strings.ToLower(c.Repository.Postgres.SSLMode) {
		case "require", "verify-ca", "verify-full":
			// OK
		default:
			errs = multierr.Append(errs,
				fmt.Errorf("production mode: repository.postgres.ssl-mode must be one of require|verify-ca|verify-full (got %q)",
					c.Repository.Postgres.SSLMode))
		}
		// (production-strict adds no DB-TLS requirement beyond this gate; any
		// future extapi.openfga.tls.* strict-only checks go under a
		// c.AuthN.Mode == ModeProductionStrict branch here.)
	}

	return errs
}

// validateProductionBootstrapMint refuses to start a production binary whose
// bootstrap-admin token mint is ENABLED (the signing key is present, so the RPC
// will actually issue tokens) but has NO caller allow-list.
//
// MintBootstrapToken returns a Hydra-signed cluster `system_admin` Bearer. It
// carries no ReBAC gate by construction (it exists to obtain the FIRST token,
// before any relation exists), so the ONLY thing standing between a caller and
// full control-plane takeover is the client-certificate SPIFFE allow-list
// enforced by authzguard.CallerPolicy. With that list empty the runtime already
// denies everyone — but shipping an enabled-yet-uncallable mint is a
// misconfiguration whose usual "fix" is to reopen the hole, so it fails at boot
// with a message naming the setting (core rule #16: no WARN-and-continue guard).
//
// Scoped to the ENABLED mint: a deployment that never supplies a signing key does
// not use the mint at all and boots unchanged.
//
// Only the PRESENCE of the key is read — never its value, and the value never
// appears in the error (security.md).
func (c Config) validateProductionBootstrapMint() error {
	if !c.AuthN.BootstrapMint.Enabled() {
		return nil
	}
	if len(c.AuthN.BootstrapMint.AllowedSANs()) > 0 {
		return nil
	}
	return fmt.Errorf(
		"production mode: authn.bootstrap-mint.allowed-client-sans is empty while the bootstrap mint is enabled (%s is set) — "+
			"MintBootstrapToken issues a cluster system_admin token and must be restricted to explicit client-certificate SPIFFE SANs; "+
			"set the allow-list or unset the signing key",
		c.AuthN.BootstrapMint.ResolveSigningKeyEnv())
}

// validateMode ensures Mode is a known ENUM value.
func (c Config) validateMode() error {
	switch c.AuthN.Mode {
	case ModeDev, ModeProduction, ModeProductionStrict:
		return nil
	default:
		return fmt.Errorf("authn.mode invalid (got %s)", c.AuthN.Mode)
	}
}

// validateProductionAuthNSecrets requires the AuthN secrets the binary needs to
// authenticate the Ory hooks. In dev mode these may legitimately be empty (the
// hook handlers accept calls without a Bearer); in any production mode a missing
// secret is a boot-time misconfiguration that would otherwise only surface as a
// runtime fail-closed (availability risk).
//
// The JWKS encryption key is still demanded here even though nothing decrypts
// with it any more: its store (oidc_jwks_keys) was dropped in migration 0065 and
// its rotator in 713f7e1. The requirement is KEPT deliberately — relaxing it
// changes production start-up behaviour and is a separate decision.
//
// Secrets resolve from the YAML field OR the ENV indirection
// (hook-shared-secret-env / jwks-encryption-key-hex-env) — the same precedence
// the composition root uses (cmd/kacho-iam/hooks_mux.go). Only os.Getenv is read
// (no other side-effects), consistent with the Resolve* methods.
//
// Errors name WHICH setting is missing — never the secret value (security.md).
//
// OpenFGA store-id is intentionally NOT validated here: it is provisioned at
// runtime by the openfga-bootstrap-job (which then re-rolls the pod), so an
// empty store-id on first boot is a deliberate, documented fail-closed state
// (a loud WARN + Check-deny in cmd/kacho-iam/env.go), required for the helm
// `--wait` install ordering. Failing Validate on it would break that boot
// sequence.
func (c Config) validateProductionAuthNSecrets() error {
	var errs error
	if strings.TrimSpace(c.AuthN.ResolveHookSharedSecret()) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.hook-shared-secret is empty (set authn.hook-shared-secret-env / KACHO_IAM_HOOK_TOKEN)"))
	}
	if _, err := c.AuthN.ResolveJWKSEncryptionKey(); err != nil {
		// ResolveJWKSEncryptionKey already reports WHICH setting / what shape is
		// wrong (empty, bad hex, wrong length) without echoing the value.
		errs = multierr.Append(errs, fmt.Errorf(
			"production mode: authn.jwks-encryption-key-hex invalid: %w", err))
	}
	return errs
}

// InsecureDevWarnings returns a list of non-blocking warnings about
// insecure dev-defaults. Returns nil in production mode.
func (c Config) InsecureDevWarnings() []string {
	if c.AuthN.Mode.IsProduction() {
		return nil
	}
	var out []string
	mode := strings.ToLower(c.Repository.Postgres.SSLMode)
	if mode == "" || mode == "disable" {
		out = append(out,
			"repository.postgres.ssl-mode=disable — DB plaintext (dev only)")
	}
	return out
}
