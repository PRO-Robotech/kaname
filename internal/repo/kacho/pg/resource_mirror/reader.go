// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package resource_mirror

// reader.go — read-side of kacho_iam.resource_mirror.
//
// The register-side only FILLS the mirror; this read-side READS it for
// selector-matching + containment (same-DB read of the owner's denormalized
// labels/parent-scope, NO iam→owner peer call — keeps the graph acyclic). The
// reads run on a pool (sweep / standalone reconcile) OR on a caller tx (event
// reconcile inside the writer-tx). Both surfaces are provided.
//
// labels @> matchLabels uses the GIN index created in migration 0019.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// MirrorRow — the read projection of one mirror object (labels + parent-scope).
type MirrorRow struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string
}

// querier — the minimal surface both *pgxpool.Pool and pgx.Tx satisfy, so the
// same SELECTs serve the pool path (sweep) and the tx path (event reconcile).
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// MatchByLabels returns every mirror row whose object_type ∈ types AND whose
// labels satisfy the AND-equality match set (`labels @> matchLabels`). An
// empty types or empty matchLabels yields no rows (the use-case rejects those
// shapes synchronously; this is a defensive belt). The GIN index on labels
// serves the `@>` probe.
func MatchByLabels(ctx context.Context, q querier, types []string, matchLabels map[string]string) ([]MirrorRow, error) {
	if len(types) == 0 || len(matchLabels) == 0 {
		return nil, nil
	}
	payload, err := json.Marshal(matchLabels)
	if err != nil {
		return nil, fmt.Errorf("resource_mirror: marshal matchLabels: %w", err)
	}
	rows, err := q.Query(ctx,
		`SELECT object_type, object_id, parent_project_id, parent_account_id, labels
		   FROM kacho_iam.resource_mirror
		  WHERE object_type = ANY($1)
		    AND labels @> $2::jsonb
		  ORDER BY object_type ASC, object_id ASC`,
		types, payload,
	)
	if err != nil {
		return nil, fmt.Errorf("resource_mirror: match by labels: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// AllByTypes returns EVERY mirror row whose object_type ∈ types (no label filter)
// — the ARM_ANCHOR(`all`) candidate set (RBAC explicit-model 2026). Containment
// to the binding's scope is re-asserted in the use-case (IsContainedIn), so this may
// over-return cluster-wide. Empty types → no rows.
func AllByTypes(ctx context.Context, q querier, types []string) ([]MirrorRow, error) {
	if len(types) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx,
		`SELECT object_type, object_id, parent_project_id, parent_account_id, labels
		   FROM kacho_iam.resource_mirror
		  WHERE object_type = ANY($1)
		  ORDER BY object_type ASC, object_id ASC`,
		types,
	)
	if err != nil {
		return nil, fmt.Errorf("resource_mirror: all by types: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// ByTypesAndIDs returns the mirror rows whose object_type ∈ types AND object_id ∈
// ids — the ARM_NAMES candidate set (RBAC explicit-model 2026). An id absent from
// the mirror is simply not returned (PENDING until its RegisterResource lands).
func ByTypesAndIDs(ctx context.Context, q querier, types, ids []string) ([]MirrorRow, error) {
	if len(types) == 0 || len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx,
		`SELECT object_type, object_id, parent_project_id, parent_account_id, labels
		   FROM kacho_iam.resource_mirror
		  WHERE object_type = ANY($1) AND object_id = ANY($2)
		  ORDER BY object_type ASC, object_id ASC`,
		types, ids,
	)
	if err != nil {
		return nil, fmt.Errorf("resource_mirror: by types and ids: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// GetByObject returns the mirror row for (objectType, objectID). ok=false when
// the object is not (yet) in the mirror — the "PENDING_VERIFICATION" race
// (the grant arrived before the owner's RegisterResource).
func GetByObject(ctx context.Context, q querier, objectType, objectID string) (MirrorRow, bool, error) {
	var (
		out        MirrorRow
		labelsJSON []byte
	)
	err := q.QueryRow(ctx,
		`SELECT object_type, object_id, parent_project_id, parent_account_id, labels
		   FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2`,
		objectType, objectID,
	).Scan(&out.ObjectType, &out.ObjectID, &out.ParentProjectID, &out.ParentAccountID, &labelsJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MirrorRow{}, false, nil
		}
		return MirrorRow{}, false, fmt.Errorf("resource_mirror: get by object: %w", err)
	}
	if err := json.Unmarshal(labelsJSON, &out.Labels); err != nil {
		return MirrorRow{}, false, fmt.Errorf("resource_mirror: unmarshal labels: %w", err)
	}
	return out, true, nil
}

func scanRows(rows pgx.Rows) ([]MirrorRow, error) {
	var out []MirrorRow
	for rows.Next() {
		var (
			r          MirrorRow
			labelsJSON []byte
		)
		if err := rows.Scan(&r.ObjectType, &r.ObjectID, &r.ParentProjectID, &r.ParentAccountID, &labelsJSON); err != nil {
			return nil, fmt.Errorf("resource_mirror: scan: %w", err)
		}
		if err := json.Unmarshal(labelsJSON, &r.Labels); err != nil {
			return nil, fmt.Errorf("resource_mirror: unmarshal labels: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("resource_mirror: rows: %w", err)
	}
	return out, nil
}
