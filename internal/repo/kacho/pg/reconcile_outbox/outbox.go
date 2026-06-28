// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package reconcile_outbox — emit + drain helpers for
// kacho_iam.resource_reconcile_outbox.
//
// RegisterResource/UnregisterResource enqueues an event HERE in the SAME
// writer-tx as the resource_mirror UPSERT/DELETE (atomic co-commit, ban #10).
// The reconciler-worker claims unsent events and re-evaluates every
// access_binding_target_member that references the changed object. The event is
// a "this object's mirror state changed, recompute" signal — the reconciler
// recomputes from the LIVE resource_mirror, so a delete event simply finds the
// row gone.
package reconcile_outbox

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const (
	// EventUpsert / EventDelete — the two mirror-change event types.
	EventUpsert = "mirror.upsert"
	EventDelete = "mirror.delete"
)

// Event — a claimed reconcile event.
type Event struct {
	ID         int64
	ObjectType string
	ObjectID   string
	EventType  string
}

// EmitTx enqueues a reconcile event on the caller tx (atomic co-commit with the
// resource_mirror change). objectType/objectID identify the changed object.
func EmitTx(ctx context.Context, tx pgx.Tx, eventType, objectType, objectID string) error {
	if tx == nil {
		return fmt.Errorf("reconcile_outbox: tx must not be nil")
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_reconcile_outbox (object_type, object_id, event_type)
		 VALUES ($1, $2, $3)`,
		objectType, objectID, eventType,
	); err != nil {
		return fmt.Errorf("reconcile_outbox: emit %s: %w", eventType, err)
	}
	return nil
}

// querier — pool/tx surface for the claim scan.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ClaimBatch reads the next unsent events (ordered by id) up to `limit`. It does
// NOT mark them sent — the caller marks each sent only after a successful
// reconcile (MarkSent), so a crash mid-reconcile re-delivers the event
// (at-least-once; the reconcile is idempotent). FOR UPDATE SKIP LOCKED lets
// multiple worker replicas claim disjoint batches without blocking.
func ClaimBatch(ctx context.Context, q querier, limit int) ([]Event, error) {
	rows, err := q.Query(ctx,
		`SELECT id, object_type, object_id, event_type
		   FROM kacho_iam.resource_reconcile_outbox
		  WHERE sent_at IS NULL
		  ORDER BY id ASC
		  LIMIT $1
		  FOR UPDATE SKIP LOCKED`,
		limit)
	if err != nil {
		return nil, fmt.Errorf("reconcile_outbox: claim batch: %w", err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.ObjectType, &e.ObjectID, &e.EventType); err != nil {
			return nil, fmt.Errorf("reconcile_outbox: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkSentTx marks an event drained on the caller tx (same tx as the reconcile
// writes, so the event is consumed iff the reconcile commits).
func MarkSentTx(ctx context.Context, tx pgx.Tx, id int64) error {
	if _, err := tx.Exec(ctx,
		`UPDATE kacho_iam.resource_reconcile_outbox SET sent_at = now() WHERE id = $1`,
		id,
	); err != nil {
		return fmt.Errorf("reconcile_outbox: mark sent: %w", err)
	}
	return nil
}
