// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import "time"

// SubjectPrivilege — enriched, public-safe projection of an AccessBinding for
// the subject-privileges view (RPC AccessBindingService.ListSubjectPrivileges).
//
// It is an AccessBinding row JOINed with its Role so the human-readable
// RoleName is resolved server-side in ONE query (access_bindings ⋈ roles on
// role_id, same kacho_iam schema, FK access_bindings_role_fk) — no per-row
// N+1 GetRole fan-out. A dangling role (deleted after a revoke) yields an empty
// RoleName; the consumer (UI) falls back to the raw RoleID (graceful).
//
// Carries only tenant-facing, publicly-safe fields: id / role / scope / status /
// created_at / granted_by — никаких инфра-чувствительных данных и никаких
// condition/builtin_condition-internals (вне scope v1, security.md).
//
// Derivation (DIRECT vs GROUP) is NOT a stored field: v1 returns only direct
// grants (subject_id literally equals the requested subject), so the projection
// is always DIRECT — the transport layer (protoconv) sets the proto enum to
// DIRECT (GROUP reserved for a later phase).
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
}
