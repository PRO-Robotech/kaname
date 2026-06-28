// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package resource_mirror — atomic emit-in-tx helper for kacho_iam.resource_mirror.
//
// The table is an OUTPUT-ONLY, cross-domain denormalised mirror (the source of
// truth stays with the owning service) of the labels +
// parent-scope of resources owned by OTHER services (such as compute and vpc).
// It is fed PUSH-style over the existing `compute→iam` FGA-proxy edge — IAM never
// pulls from compute, so the cross-domain graph stays acyclic.
//
// UpsertTx / DeleteTx MUST run in the SAME pgx.Tx as the owner-tuple fga_outbox
// emit (RegisterResource / UnregisterResource), so a rolled-back caller-tx
// leaves NEITHER the mirror row NOR the tuple intent (atomic co-commit, ban #10).
// Tx-commit is the atomicity primitive — never "UPSERT then call a second store".
//
// Schema (migration 0019 `kacho_iam.resource_mirror`):
//
//	object_type       text         PK ч.1   (closed-ish dotted key, e.g. "compute.instance")
//	object_id         text         PK ч.2   (opaque cross-DB soft-ref, no FK)
//	parent_project_id text                  (parent-scope for selector containment)
//	parent_account_id text                  (parent-scope for selector containment)
//	labels            jsonb        '{}'      (owner labels copy; GIN-indexed — selector matches @>)
//	updated_at        timestamptz  now()     (last-write marker)
//
// The write-path FILLS the mirror; the selector READS it (containment). Idempotency under
// the at-least-once drainer is by-construction: PK (object_type,object_id)
// makes UPSERT/DELETE a no-op-equivalent on repeat and serializes concurrent
// writers of the same object on the row-lock (deterministic last-write).
package resource_mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Row — the tenant-facing projection mirrored for one owner object. Labels nil
// is normalized to an empty JSONB object ('{}').
type Row struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string
	// SourceVersion — monotonic per-object marker from the SOURCE (compute),
	// stamped when it emitted the register intent inside its writer-tx. The
	// conditional UPSERT applies this register ONLY when it is strictly newer than
	// the stored one (last-source-state-wins). Zero value (legacy /
	// empty producer) is normalized to '-infinity' so the register still applies
	// unconditionally (back-compat).
	SourceVersion time.Time
}

// negInfinity — the sentinel a zero/legacy SourceVersion maps to ('-infinity'),
// so an older producer's empty version still applies (back-compat with a
// producer that emits no version).
func versionOr(t time.Time) any {
	if t.IsZero() {
		return "-infinity"
	}
	return t.UTC()
}

// UpsertTx INSERTs-or-conditionally-UPDATEs the mirror row for (ObjectType,
// ObjectID) using the caller-supplied transaction. UPSERT-on-PK ⇒ idempotent on
// drainer retry; the UPDATE branch is gated `WHERE source_version <
// EXCLUDED.source_version`, making the mirror LAST-SOURCE-STATE-WINS:
// a stale register-intent (older source_version,
// reordered by the HA drainer) updates 0 rows and is a no-op — NOT an error
// (at-least-once OK) and NOT an overwrite with older labels. A repeat with the
// SAME source_version is likewise a no-op (`<` is strict). Equal/newer in-order
// register applies and advances source_version.
//
// MUST run in the same pgx.Tx as the owner-tuple fga_outbox emit; tx rollback ⇒
// the row is not visible (atomic co-commit, ban #10).
func UpsertTx(ctx context.Context, tx pgx.Tx, row Row) error {
	if tx == nil {
		return fmt.Errorf("resource_mirror: tx must not be nil")
	}
	labels := row.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	payload, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("resource_mirror: marshal labels: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror
		   (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6, now())
		 ON CONFLICT (object_type, object_id) DO UPDATE
		    SET parent_project_id = EXCLUDED.parent_project_id,
		        parent_account_id = EXCLUDED.parent_account_id,
		        labels            = EXCLUDED.labels,
		        source_version    = EXCLUDED.source_version,
		        updated_at        = now()
		  WHERE resource_mirror.source_version < EXCLUDED.source_version`,
		row.ObjectType, row.ObjectID, row.ParentProjectID, row.ParentAccountID, payload, versionOr(row.SourceVersion),
	); err != nil {
		return fmt.Errorf("resource_mirror: upsert: %w", err)
	}
	return nil
}

// DeleteTx conditionally removes the mirror row for (objectType, objectID). The
// DELETE is gated `WHERE source_version <= $tombstone` so a STALE unregister
// tombstone (older than the stored register — a Delete-after-Update reorder)
// updates 0 rows and is a no-op, leaving the fresher row intact.
// An absent row → no-op (idempotent). A zero tombstone (legacy /
// empty producer) maps to '-infinity' and only matches a stored legacy
// '-infinity' register (`-infinity <= -infinity`) — i.e. when BOTH producer
// edges are legacy the old unconditional delete is preserved (back-compat). The
// producer (compute) is upgraded atomically (register & unregister carry the
// version together), so a mixed versioned-register / legacy-delete window exists only
// transiently during rollout and degrades gracefully. Same atomicity contract
// as UpsertTx.
func DeleteTx(ctx context.Context, tx pgx.Tx, objectType, objectID string, tombstone time.Time) error {
	if tx == nil {
		return fmt.Errorf("resource_mirror: tx must not be nil")
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2
		    AND source_version <= $3`,
		objectType, objectID, versionOr(tombstone),
	); err != nil {
		return fmt.Errorf("resource_mirror: delete: %w", err)
	}
	return nil
}
