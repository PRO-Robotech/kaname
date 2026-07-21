// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package bootstrap_token — the InternalBootstrapTokenService use-case (#58):
// idempotently provision the singleton bootstrap-admin ServiceAccount's Hydra
// OAuth client + mapping, then broker a short-lived RS256 access-token for it via
// the existing Hydra client_credentials exchange (aud = https://{API_DOMAIN}).
//
// The bootstrap SA row + its cluster system_admin grant are seeded by migration
// 0058 (deterministic id → DB-singleton). This use-case provisions only the
// runtime Hydra-backed halves (the OAuth client + its 1:1
// service_account_oauth_clients mapping), gated by the UNIQUE(sva_id) mapping
// index + a transaction-scoped advisory lock (winner-only external create,
// IBT-03), and mints the token. The signing key is env-held (k8s Secret), NEVER
// persisted in the DB — security.md secrets-at-rest posture.
package bootstrap_token

import (
	"crypto/md5" //nolint:gosec // md5 is used ONLY as a deterministic id-derivation function (NOT for security); it must match Postgres md5() in migration 0058.
	"encoding/hex"
)

// Deterministic seed strings — MUST stay byte-identical to migration 0058's
// `md5('…')` arguments so the Go-computed ids match the seeded rows.
const (
	seedBootstrapSA     = "kacho-bootstrap-admin" // → service_accounts.id (sva…)
	seedBootstrapSoc    = "kacho-bootstrap-soc"   // → service_account_oauth_clients.id (soc_…)
	seedSystemAccount   = "kacho-system"          // → the system account / owner user md5 suffix
	bootstrapClientID   = "kacho-bootstrap-admin" // Hydra OAuth2 client_id (fixed, readable)
	bootstrapClientNm   = "kacho-bootstrap-admin" // Hydra client_name
	prefixServiceAcct   = "sva"                   // 3-char corelib prefix (no underscore), matches PrefixServiceAccount
	prefixSAOAuthClient = "soc_"                  // underscore form, matches service_account_oauth_clients_id_check
	prefixUser          = "usr"
)

// md5Suffix returns the first 17 hex chars of md5(s) — identical to Postgres
// `substr(md5(s),1,17)`. All hex chars are valid Crockford-base32 (0-9a-f ⊂
// [0-9a-hjkmnp-tv-z]), so the derived ids satisfy the soc_/cag_ id CHECKs.
func md5Suffix(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // deterministic id derivation, not security.
	return hex.EncodeToString(sum[:])[:17]
}

// Identity — the deterministic bootstrap identity (derived; matches migration
// 0058's seeded rows).
type Identity struct {
	// SvaID — the bootstrap ServiceAccount id (`sva…`, seeded by 0058).
	SvaID string
	// SocID — the service_account_oauth_clients mapping id (`soc_…`); also the
	// JWK `kid` registered with Hydra and stamped in the client_assertion header.
	SocID string
	// ClientID — the Hydra OAuth2 client_id (`kacho-bootstrap-admin`).
	ClientID string
	// CreatedByUserID — the system owner user (`usr…`, FK for the mapping row).
	CreatedByUserID string
}

// DeriveIdentity computes the deterministic bootstrap identity. Pure; no I/O.
func DeriveIdentity() Identity {
	return Identity{
		SvaID:           prefixServiceAcct + md5Suffix(seedBootstrapSA),
		SocID:           prefixSAOAuthClient + md5Suffix(seedBootstrapSoc),
		ClientID:        bootstrapClientID,
		CreatedByUserID: prefixUser + md5Suffix(seedSystemAccount),
	}
}
