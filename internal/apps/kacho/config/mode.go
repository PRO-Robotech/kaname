// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package config — configuration for kacho-iam.
//
// YAML + viper. Defaults are kept in defaults.go (not in struct-tags).
// ENV-binding lives in load.go via `viper.SetEnvPrefix("KACHO_IAM")` +
// delimiter `__` for hierarchy (`KACHO_IAM_REPOSITORY__POSTGRES__URL` →
// `repository.postgres.url`).
//
// Mode: ENUM Mode{ModeDev, ModeProduction, ModeProductionStrict} — overall
// service mode (anonymous-allowed / fail-closed / fail-closed+strict-TLS).
// The same ENUM governs the mandatory JWT (Kratos/Hydra) on the
// public-listener once AuthN core is wired.
package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Mode — overall service mode.
//
//	ModeDev              — anonymous-mode permitted (interceptor lets callers
//	                       through without AuthN-headers as admin); insecure
//	                       dev-defaults (TLS off, sslmode=disable) are only
//	                       logged.
//	ModeProduction       — fail-closed: every request must carry a non-empty
//	                       principal-ctx. Anonymous → PermissionDenied.
//	ModeProductionStrict — production + additionally validates extapi.*.tls.*
//	                       and repository.postgres.ssl-mode
//	                       (require|verify-ca|verify-full).
type Mode int

// ENUM values. iota order is stable; don't change without a values.yaml
// migration.
const (
	ModeDev Mode = iota
	ModeProduction
	ModeProductionStrict
)

// String — canonical name for logging / config-errors.
func (m Mode) String() string {
	switch m {
	case ModeDev:
		return "dev"
	case ModeProduction:
		return "production"
	case ModeProductionStrict:
		return "production-strict"
	default:
		return fmt.Sprintf("mode(%d)", int(m))
	}
}

// IsProduction returns true for any production variant.
func (m Mode) IsProduction() bool {
	return m == ModeProduction || m == ModeProductionStrict
}

// parseMode — pointwise inverse of String(); used by the custom
// mapstructure hook and the YAML/ENV loader.
func parseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "dev":
		return ModeDev, nil
	case "production":
		return ModeProduction, nil
	case "production-strict":
		return ModeProductionStrict, nil
	default:
		// Fail-CLOSED on an unknown/typo'd mode (F14 safe-by-default): pair the
		// error with the production value, NOT ModeDev (anonymous→full access). Both
		// consumers (the mapstructure hook + UnmarshalJSON) abort on the error today,
		// but an error-ignoring caller must still default to anonymous-fail-closed.
		return ModeProduction, fmt.Errorf("unknown mode %q (allowed: dev, production, production-strict)", s)
	}
}

// MarshalJSON / UnmarshalJSON — convenient serialisation.
func (m Mode) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

func (m *Mode) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := parseMode(s)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}
