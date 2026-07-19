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
//
// TRANSITIVE parent_account resolution: a mirror-fed resource is registered with its
// owning PROJECT (parent_project_id); the account is resolved same-DB by iam at
// register time (register_resource.go account backfill). A row whose parent_account_id
// is still empty (a legacy/unresolved register) would make an ACCOUNT-scoped binding
// mis-miss the object — the object IS contained in the account (via its project), but
// the direct parent_account_id column is blank. Every read here therefore resolves the
// account through the project→account hierarchy same-DB:
//
//	COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '')
//
// so domain.MirrorObject.ParentAccountID always carries the FULL resolved account and
// the pure-domain IsContainedIn predicate (the semantic source of truth) decides
// account containment correctly WITHOUT reaching for the DB. The stored value wins when
// present (COALESCE order); the LEFT JOIN falls back to projects.account_id; a dangling
// project (deleted) degrades to '' (contained only in cluster) rather than erroring.
// kacho_iam.projects is IAM-native (same DB, no peer call — the graph stays acyclic).

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
		`SELECT m.object_type, m.object_id, m.parent_project_id,
		        COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '') AS parent_account_id,
		        m.labels
		   FROM kacho_iam.resource_mirror m
		   LEFT JOIN kacho_iam.projects pj ON pj.id = m.parent_project_id
		  WHERE m.object_type = ANY($1)
		    AND m.labels @> $2::jsonb
		  ORDER BY m.object_type ASC, m.object_id ASC`,
		types, payload,
	)
	if err != nil {
		return nil, fmt.Errorf("resource_mirror: match by labels: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// AllByTypes returns the mirror rows whose object_type ∈ types NARROWED to the binding's
// containment scope — the ARM_ANCHOR(`all`) candidate set (RBAC explicit-model 2026).
//
// scopeType/scopeID push the binding's containment scope INTO the SQL as a PROVEN SUPERSET
// of the pure-domain IsContainedIn re-verify (which the use-case still runs — this only
// PRE-filters), so the caller receives O(scope) rows instead of O(cluster mirror). The
// predicate MIRRORS the projected parent-scope columns byte-for-byte, so it can never DROP a
// row IsContainedIn would accept (no under-grant); any residual over-return is narrowed by
// the Go re-verify (over-broad is safe):
//
//   - "project" → parent_project_id = $2                                   (exactly IsContainedIn's project branch)
//   - "account" → COALESCE(NULLIF(parent_account_id,”), pj.account_id,”) = $2
//     (exactly IsContainedIn's account branch — the SAME resolution the SELECT projects, so
//     an object registered with only its parent_project is still contained via project→account)
//   - "cluster" / unknown → NO narrowing (cluster contains everything, IsContainedIn cluster=true;
//     an unknown scope-type conservatively falls through to no-narrowing so the Go re-verify
//     stays authoritative — over-broad, never under-broad)
//
// Empty types → no rows.
func AllByTypes(ctx context.Context, q querier, types []string, scopeType, scopeID string) ([]MirrorRow, error) {
	if len(types) == 0 {
		return nil, nil
	}
	// The scope predicate is an EXACT mirror of the projected ParentProjectID/ParentAccountID,
	// so the returned set is precisely {row | IsContainedIn(scope)} for project/account and the
	// full type-set for cluster/unknown — a guaranteed superset of the Go re-verify.
	args := []any{types}
	var scopeClause string
	switch scopeType {
	case "project":
		scopeClause = " AND m.parent_project_id = $2"
		args = append(args, scopeID)
	case "account":
		scopeClause = " AND COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '') = $2"
		args = append(args, scopeID)
	default:
		// cluster / unknown → no narrowing (Go IsContainedIn stays authoritative).
	}
	rows, err := q.Query(ctx,
		`SELECT m.object_type, m.object_id, m.parent_project_id,
		        COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '') AS parent_account_id,
		        m.labels
		   FROM kacho_iam.resource_mirror m
		   LEFT JOIN kacho_iam.projects pj ON pj.id = m.parent_project_id
		  WHERE m.object_type = ANY($1)`+scopeClause+`
		  ORDER BY m.object_type ASC, m.object_id ASC`,
		args...,
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
		`SELECT m.object_type, m.object_id, m.parent_project_id,
		        COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '') AS parent_account_id,
		        m.labels
		   FROM kacho_iam.resource_mirror m
		   LEFT JOIN kacho_iam.projects pj ON pj.id = m.parent_project_id
		  WHERE m.object_type = ANY($1) AND m.object_id = ANY($2)
		  ORDER BY m.object_type ASC, m.object_id ASC`,
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
		`SELECT m.object_type, m.object_id, m.parent_project_id,
		        COALESCE(NULLIF(m.parent_account_id, ''), pj.account_id, '') AS parent_account_id,
		        m.labels
		   FROM kacho_iam.resource_mirror m
		   LEFT JOIN kacho_iam.projects pj ON pj.id = m.parent_project_id
		  WHERE m.object_type = $1 AND m.object_id = $2`,
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
