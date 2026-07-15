// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"encoding/base64"
	"encoding/json"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// pagination bounds — parity with kacho-corelib/validate (Kachō page_size contract):
// 0 → DefaultPageSize, (0..MaxPageSize] → as-is, >MaxPageSize → InvalidArgument.
const (
	defaultListPageSize int64 = 50
	maxListPageSize     int64 = 1000
)

// effectivePageSize resolves a List page_size to the effective SQL LIMIT.
// Unlike the legacy silent-clamp (`if pageSize>1000 { pageSize=1000 }`), a value
// over the cap is REJECTED with ErrInvalidArg → INVALID_ARGUMENT (api-conventions
// «page_size через corevalidate.PageSize»; parity with kacho-vpc). A value ≤0
// applies the default. The error is the iam sentinel family so mapRepoErr /
// MapRepoErr surface a clean INVALID_ARGUMENT (no pgx/SQL leak).
func effectivePageSize(pageSize int32) (int64, error) {
	v := int64(pageSize)
	if v < 0 || v > maxListPageSize {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "page_size must be in [0..%d] (0 means default)", maxListPageSize)
	}
	if v == 0 {
		return defaultListPageSize, nil
	}
	return v, nil
}

// base64URLEncode/Decode — alias'ы под StdEncoding с padding (parity с
// kacho-vpc/internal/repo/helpers). Используются для cursor-based page_token.
func base64URLEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func base64URLDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// jsonBytesOrEmpty — return a non-nil jsonb byte-slice for a Postgres
// `$N::jsonb` placeholder. Empty / nil → `{}` so the column stays a valid
// JSON object instead of NULL. Moved here from the deleted federation_repos.go
// since audit_outbox / conditions / access_binding_conditions repos still rely
// on it.
func jsonBytesOrEmpty(v any) []byte {
	switch x := v.(type) {
	case []byte:
		if len(x) == 0 {
			return []byte("{}")
		}
		return x
	case json.RawMessage:
		if len(x) == 0 {
			return []byte("{}")
		}
		return []byte(x)
	case string:
		if x == "" {
			return []byte("{}")
		}
		return []byte(x)
	}
	// fallback: marshal arbitrary value
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 {
		return []byte("{}")
	}
	return b
}
