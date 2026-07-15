// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// governance_ports.go — narrow port-iface definitions for the writer-tx outbox
// emitters. TxBeginner opens the transaction; RelationOutboxEmitter (fga_outbox),
// ResourceMirrorEmitter (resource_mirror) and AuditOutboxEmitter (audit_outbox)
// emit their rows inside that same caller-owned transaction, so each side-effect
// commits atomically with the mutation that produced it.
//
// Service layer defines these ports; adapters in repo/kacho/pg and clients/
// implement them. Composition root (cmd/kacho-iam/main.go) injects concrete
// implementations.
package service

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/outboxtypes"
)

// TxBeginner opens a transaction. The returned handle is the opaque service.Tx
// (see tx.go) — the concrete pgx.Tx is materialized only inside repo adapters.
type TxBeginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// RelationTuple — {User, Relation, Object} triple for fga_outbox writes.
// Neutral value type owned by internal/outboxtypes so the repo-ports package
// (internal/repo/kacho) can reference it without importing this use-case package
// (dependency-rule fix); the alias keeps the ergonomic service.RelationTuple name.
type RelationTuple = outboxtypes.RelationTuple

// RelationOutboxEmitter — port for emitting kacho_iam.fga_outbox grant/revoke
// rows from writer-tx-owning code paths. Atomic with the surrounding
// mutation; the drainer applies tuples to the relation backend asynchronously.
type RelationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
}

// ResourceMirrorRow — service-layer payload for one kacho_iam.resource_mirror
// row. OUTPUT-ONLY mirror of the labels + parent-scope of a
// resource owned by another service (source of truth = owner). Labels nil →
// persisted as JSONB '{}'.
type ResourceMirrorRow struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string
	// SourceVersion — monotonic per-object marker from the owner.
	// The mirror UPSERT applies a register only when this is strictly newer than
	// the stored version (last-source-state-wins). Zero → '-infinity' (legacy).
	SourceVersion time.Time
}

// ResourceMirrorEmitter — port for UPSERT/DELETE of a kacho_iam.resource_mirror
// row inside a caller-owned writer-tx. Atomic with the
// owner-tuple fga_outbox emit (one writer-tx): a rolled-back caller-tx leaves
// neither the mirror row nor the tuple intent. The mirror-fill path only FILLS
// the mirror; the reconciler reads it. UPSERT-on-PK gives idempotency under the
// at-least-once drainer.
type ResourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx Tx, row ResourceMirrorRow) error
	DeleteTx(ctx context.Context, tx Tx, objectType, objectID string, tombstone time.Time) error
}

// AuditEvent — service-layer payload for a durable kacho_iam.audit_outbox
// compliance row. The repo adapter generates the id (evt_<22-char> — bug #126
// regression-guard), marshals Payload to the event_payload jsonb, and inserts
// it with status='pending'. EventType must satisfy the audit_outbox_event_type
// CHECK (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
//
// Payload carries the compliance dimensions (actor / subject / resource / key
// domain fields). It MUST NOT contain secret material (no tokens, no key PEM,
// no client_secret) — see security.md / acceptance 5.2-36.
//
// Neutral value type owned by internal/outboxtypes so the repo-ports package can
// reference it without importing this use-case package (dependency-rule fix);
// the alias keeps the ergonomic service.AuditEvent name.
type AuditEvent = outboxtypes.AuditEvent

// AuditOutboxEmitter — port for emitting one durable kacho_iam.audit_outbox row
// inside a caller-owned writer-tx. Atomic with the surrounding security-relevant
// mutation (запрет #10): the audit row commits iff the mutation commits, so a
// rolled-back mutation leaves no orphan compliance row and a committed mutation
// always leaves its trail.
//
// Mirrors RelationOutboxEmitter's emit-in-tx shape: the concrete pgx.Tx is
// recovered from the opaque service.Tx inside the repo adapter (txAsPgx).
type AuditOutboxEmitter interface {
	EmitTx(ctx context.Context, tx Tx, ev AuditEvent) error
}
