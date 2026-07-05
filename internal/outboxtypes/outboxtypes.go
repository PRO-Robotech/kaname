// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package outboxtypes holds the NEUTRAL writer-tx outbox payload value types
// shared across the Clean-Architecture boundary between the use-case layer
// (internal/service, which defines the emitter ports) and the CQRS Repository
// port aggregator (internal/repo/kacho, whose Writer surface also emits them).
//
// Why a dedicated leaf package: internal/repo/kacho/iface.go (the
// Repository/Reader/Writer ports) exposes EmitAuditEvent / EmitFGARelationWrite
// / EmitFGARelationDelete in terms of these payloads. If the payloads lived in
// internal/service (the use-case layer), the repo-ports package would import the
// use-case package it is a dependency OF — an inverted layer edge that is "one
// refactor away from an import cycle" (repo/kacho → service → repo/kacho).
// Hoisting the payloads into this stdlib-only leaf package lets BOTH sides
// reference a neutral type without either importing the other.
//
// This package imports ONLY the standard library.
package outboxtypes

// RelationTuple — {User, Relation, Object} triple for kacho_iam.fga_outbox
// grant/revoke writes.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

// AuditEvent — payload for a durable kacho_iam.audit_outbox compliance row. The
// repo adapter generates the id (evt_<22-char>), marshals Payload to the
// event_payload jsonb, and inserts it with status='pending'. EventType must
// satisfy the audit_outbox_event_type CHECK
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
//
// Payload carries the compliance dimensions (actor / subject / resource / key
// domain fields). It MUST NOT contain secret material (no tokens, no key PEM, no
// client_secret) — see security.md / acceptance 5.2-36.
type AuditEvent struct {
	// EventType — canonical `iam.<resource>.<action>` taxonomy value.
	EventType string
	// TenantAccountID — Account scope for per-account audit queries; "" → NULL.
	TenantAccountID string
	// Payload — the event_payload jsonb body (the use-case decides key names —
	// actor / subject_id / reason / token_jti / …).
	Payload map[string]any
}
