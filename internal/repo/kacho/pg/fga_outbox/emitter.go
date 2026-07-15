// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package fga_outbox — atomic emit-in-tx helper for kacho_iam.fga_outbox.
//
// Mirror of the SubjectChangeEmitter pattern
// (internal/repo/kacho/pg/subject_change_emitter.go).
//
// Background
//
//	Earlier every FGA tuple mutation in kacho-iam ran via a post-commit sync
//	call to RelationStore.WriteTuples/DeleteTuples (a non-fatal Warn on
//	failure). JIT auto-grant skipped FGA entirely. JIT pending Approve called
//	EmitSubjectErasure (CAEP deletion). BreakGlass.ApproveB never wrote
//	cluster_admin_grants. The cumulative effect — OpenFGA was NOT a reliable
//	source of authz truth.
//
//	All FGA mutations are now unified behind the `fga_outbox` table that
//	powers `bootstrap_admin.go` and the drainer (clients/fga_applier.go).
//	Each grant/revoke emits N rows into `kacho_iam.fga_outbox` in the SAME
//	pgx.Tx as the domain state-change. The drainer asynchronously applies
//	them to OpenFGA (with retry + idempotency). Rollback of the caller tx
//	⇒ no orphan outbox row.
//
//	Per ban #10 — within-service refs/invariants live on
//	DB-level: tx-commit is the atomicity primitive, not "INSERT then call
//	OpenFGA sync then hope".
//
// Schema (migration 0002 `kacho_iam.fga_outbox`):
//
//	id            bigserial    PK
//	event_type    text         IN ('fga.tuple.write','fga.tuple.delete')
//	payload       jsonb        {"user":"…","relation":"…","object":"…"}
//	created_at    timestamptz  default now()
//	sent_at       timestamptz  NULL until drainer applies
//	last_error    text
//	attempt_count int
//
// Drainer event types (clients/fga_applier.go):
//   - clients.FGAEventTypeWrite  = "fga.tuple.write"
//   - clients.FGAEventTypeDelete = "fga.tuple.delete"
package fga_outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

const (
	eventTypeWrite  = "fga.tuple.write"
	eventTypeDelete = "fga.tuple.delete"
)

// EmitWriteTx INSERTs N grant rows into `kacho_iam.fga_outbox` (event_type
// `fga.tuple.write`) using the caller-supplied transaction.
//
// MUST run in the same pgx.Tx as the domain state-change (AccessBinding
// insert, JIT auto-grant InsertTx, cluster_admin_grants insert). Tx rollback
// ⇒ outbox rows are not visible to the drainer.
//
// len(tuples)==0 is a no-op (returns nil) — caller decides whether 0 tuples
// is an error.
func EmitWriteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, eventTypeWrite, tuples)
}

// EmitDeleteTx INSERTs N revoke rows into `kacho_iam.fga_outbox` (event_type
// `fga.tuple.delete`).
//
// Caller supplies the EXACT tuples that were originally written by EmitWriteTx
// — symmetric revoke. Same atomicity contract as EmitWriteTx.
func EmitDeleteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, eventTypeDelete, tuples)
}

func emitTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		payload, err := json.Marshal(map[string]string{
			"user":     t.User,
			"relation": t.Relation,
			"object":   t.Object,
		})
		if err != nil {
			return fmt.Errorf("fga_outbox: marshal payload: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ($1, $2::jsonb, now())`,
			eventType, payload,
		); err != nil {
			return fmt.Errorf("fga_outbox: insert %s: %w", eventType, err)
		}
	}
	return nil
}
