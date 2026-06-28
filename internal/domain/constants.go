// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package domain — entities + value-types for kacho-iam.
//
// The domain layer depends on stdlib + multierr only — never on pgx,
// grpc-stubs, or sqlc. `kacho-proto` is permitted strictly for envelope
// types (Operation, status); for concrete IAM proto-structs we have
// `internal/dto/toproto`.
package domain

// ID prefixes for kacho-iam resources. Mirrors the canonical prefix
// constants in `kacho-corelib/ids` so the use-case layer can refer to short
// names locally (`PrefixAccount`, `PrefixProject`, …) without re-importing
// corelib for trivial id construction.
const (
	PrefixAccount        = "acc"
	PrefixProject        = "prj"
	PrefixUser           = "usr"
	PrefixServiceAccount = "sva"
	PrefixGroup          = "grp"
	PrefixRole           = "rol"
	PrefixAccessBinding  = "acb"
	// PrefixOperationIAM — separate prefix so api-gateway routes
	// `OperationService.Get(id)` correctly (by the first 3 characters of the
	// id). MUST differ from PrefixAccount — otherwise `acc<…>` (Account) and
	// an Operation on Account would collide.
	PrefixOperationIAM = "iop"
)

// ShortIDLen — full id length (prefix + body); matches kacho-corelib/ids.
const ShortIDLen = 20

// PrincipalType — allowed values for kacho_iam.operations.principal_type.
// 'system' / 'kacho-iam-bootstrap' are used for internal/background flows;
// 'user' / 'service_account' come from OIDC at the api-gateway edge.
const (
	PrincipalTypeSystem         = "system"
	PrincipalTypeAnonymous      = "anonymous"
	PrincipalTypeUser           = "user"
	PrincipalTypeServiceAccount = "service_account"
	PrincipalDisplayBootstrap   = "kacho-iam-bootstrap"
	PrincipalIDBootstrap        = "bootstrap"
)
