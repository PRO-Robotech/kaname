// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "time"

// SubjectPrivilege — enriched, public-safe projection of an AccessBinding for
// the subject-privileges view (RPC AccessBindingService.ListSubjectPrivileges).
//
// It is an AccessBinding row JOINed with its Role so the human-readable
// RoleName is resolved server-side in ONE query (access_bindings ⋈ roles on
// role_id, same kaname schema, FK access_bindings_role_fk) — no per-row
// N+1 GetRole fan-out. A dangling role (deleted after a revoke) yields an empty
// RoleName; the consumer (UI) falls back to the raw RoleID (graceful).
//
// Carries only tenant-facing, publicly-safe fields: id / role / scope / status /
// created_at / granted_by — никаких инфра-чувствительных данных и никаких
// condition/builtin_condition-internals (вне scope v1, security.md).
//
// Derivation says HOW the subject holds the privilege: DIRECT (the binding names
// the subject itself) or GROUP (the binding names a group the subject belongs to,
// named by ViaGroupID). It is computed by the read query, not stored on the
// binding — a binding does not know which of its subjects' memberships a given
// reader is asking about.
type SubjectPrivilege struct {
	BindingID       AccessBindingID
	RoleID          RoleID
	RoleName        RoleName // resolved via JOIN; "" for a dangling/deleted role
	ResourceType    ResourceType
	ResourceID      string // opaque id (any prefix, cross-service OK)
	Scope           Scope  // CLUSTER / ACCOUNT / PROJECT
	Status          AccessBindingStatus
	CreatedAt       time.Time
	GrantedByUserID UserID
	ExpiresAt       *time.Time // nullable — TTL
	// Derivation — DIRECT | GROUP. The zero value is treated as DIRECT by the
	// transport projection (a row produced without an explicit derivation is a
	// direct grant), so the proto enum never leaks UNSPECIFIED.
	Derivation PrivilegeDerivation
	// ViaGroupID — the group carrying the privilege when Derivation==GROUP; empty
	// for a DIRECT grant. Without it a GROUP row is un-actionable: the binding's
	// own subject is the group, so the administrator cannot tell which membership
	// to remove.
	ViaGroupID GroupID
}

// PrivilegeDerivation — how a subject obtained a privilege.
type PrivilegeDerivation string

const (
	// DerivationDirect — the binding's subject IS the requested subject. Also the
	// zero value's meaning (see SubjectPrivilege.Derivation).
	DerivationDirect PrivilegeDerivation = ""
	// DerivationGroup — the binding's subject is a GROUP the requested subject is
	// a member of. Groups do not nest, so this is exactly one hop.
	DerivationGroup PrivilegeDerivation = "GROUP"
)
