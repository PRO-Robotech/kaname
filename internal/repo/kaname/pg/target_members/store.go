// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package target_members — store for kaname.access_binding_target_members,
// the materialized desired-state membership of a binding's target.
//
// The reconciler computes the desired member set from resource_mirror, then
// UPSERTs each member with its verification_status and DELETEs members that
// fell out — all inside the caller-owned writer-tx, atomically with the
// fga_outbox tuple emit (ban #10). Reads serve the diff (current set) and the
// read/UI projection (membership with per-member status).
//
// Idempotency: UPSERT on the PK (binding_id, object_type, object_id) makes a
// re-materialization a no-op-equivalent and serializes concurrent reconcile
// passes on the row-lock (deterministic last-write).
package target_members

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Member — one materialized target member with its verification status. RoleID +
// RuleFP attribute the member to the (role, rule) that produced it (RBAC
// rules-model) — part of the PK (binding, role, rule_fp, object).
type Member struct {
	BindingID          string
	RoleID             string
	RuleFP             string
	ObjectType         string
	ObjectID           string
	VerificationStatus domain.VerificationStatus
}

// UpsertTx inserts-or-updates a membership row to (status) for the full rule
// coordinate (binding, role, rule_fp, object), on the caller tx. Idempotent on
// the PK; the status is overwritten on conflict (a re-verify transition
// PENDING→ACTIVE/REJECTED). updated_at advances on write.
func UpsertTx(ctx context.Context, tx pgx.Tx, m Member) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.access_binding_target_members
		   (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now(), now())
		 ON CONFLICT (binding_id, role_id, rule_fp, object_type, object_id) DO UPDATE
		    SET verification_status = EXCLUDED.verification_status,
		        updated_at          = now()`,
		m.BindingID, m.RoleID, m.RuleFP, m.ObjectType, m.ObjectID, string(m.VerificationStatus),
	); err != nil {
		return fmt.Errorf("target_members: upsert: %w", err)
	}
	return nil
}

// UpsertManyTx — тот же UPSERT, что UpsertTx, но НАБОРОМ строк одним стейтментом.
//
// ЗАЧЕМ. Аддитивный проход материализации пишет по строке члена на КАЖДУЮ выдачу,
// совпавшую с одним объектом, а совпавших столько, сколько выдач покрывает область
// объекта (по дереву выдач: p50 = 9, хвост 227). Поштучная вставка делала стоимость
// прохода линейной по числу выдач соседей, хотя изменился ровно один объект.
//
// Семантика дословно та же: тот же ключ конфликта, то же перезаписывание статуса,
// то же advance updated_at. Дубли по ключу внутри одного набора схлопываются здесь —
// `ON CONFLICT … DO UPDATE` не вправе задеть одну строку дважды в одном стейтменте, и
// набор с дублем Postgres отверг бы целиком (поштучная вставка этого не требовала,
// потому что каждая строка ехала своим стейтментом). Пустой набор — no-op.
func UpsertManyTx(ctx context.Context, tx pgx.Tx, members []Member) error {
	if len(members) == 0 {
		return nil
	}
	n := len(members)
	bindings := make([]string, 0, n)
	roles := make([]string, 0, n)
	fps := make([]string, 0, n)
	objTypes := make([]string, 0, n)
	objIDs := make([]string, 0, n)
	statuses := make([]string, 0, n)
	seen := make(map[[5]string]struct{}, n)
	for _, m := range members {
		k := [5]string{m.BindingID, m.RoleID, m.RuleFP, m.ObjectType, m.ObjectID}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		bindings = append(bindings, m.BindingID)
		roles = append(roles, m.RoleID)
		fps = append(fps, m.RuleFP)
		objTypes = append(objTypes, m.ObjectType)
		objIDs = append(objIDs, m.ObjectID)
		statuses = append(statuses, string(m.VerificationStatus))
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.access_binding_target_members
		   (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
		 SELECT b, r, f, ot, oi, vs, now(), now()
		   FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[])
		        AS t(b, r, f, ot, oi, vs)
		 ON CONFLICT (binding_id, role_id, rule_fp, object_type, object_id) DO UPDATE
		    SET verification_status = EXCLUDED.verification_status,
		        updated_at          = now()`,
		bindings, roles, fps, objTypes, objIDs, statuses,
	); err != nil {
		return fmt.Errorf("target_members: upsert many (%d): %w", len(bindings), err)
	}
	return nil
}

// DeleteTx removes a membership row for the full rule coordinate (binding, role,
// rule_fp, object) on the caller tx. Used when an ACTIVE member falls out of the
// matched set (label removed / rule removed) — the reconciler
// eager-revokes its FGA tuple AND removes the row in the same tx. Absent row →
// no-op (idempotent). The DELETE is scoped by rule_fp so removing one rule's
// member never drops another rule's member of the same object.
func DeleteTx(ctx context.Context, tx pgx.Tx, bindingID, ruleFP, objectType, objectID string) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM kaname.access_binding_target_members
		  WHERE binding_id = $1 AND rule_fp = $2 AND object_type = $3 AND object_id = $4`,
		bindingID, ruleFP, objectType, objectID,
	); err != nil {
		return fmt.Errorf("target_members: delete: %w", err)
	}
	return nil
}

// ListByBindingTx returns all materialized members of a binding, ordered for a
// stable read/diff. Runs on the caller tx (reconcile diff reads the current set
// inside the same tx as the write).
func ListByBindingTx(ctx context.Context, tx pgx.Tx, bindingID string) ([]Member, error) {
	return queryMembers(ctx, tx,
		`SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status
		   FROM kaname.access_binding_target_members
		  WHERE binding_id = $1
		  ORDER BY rule_fp ASC, object_type ASC, object_id ASC`,
		bindingID)
}

// ListByBindingObjectTx returns the materialized members of ONE binding on ONE object —
// the NARROW diff base of the object-triggered reconcile pass (a mirror upsert/delete or
// a label UPDATE changes exactly one object, so only that object's members can change).
//
// The predicate leads with (object_type, object_id) so it is served by the by-object
// index: an object carries a handful of member rows (3.2 bindings on average on the
// measured stand, 66 at the tail), whereas the PK's leading column is binding_id, under
// which the hottest bindings hold 10 140 rows. Filtering the object out of a whole
// binding would be the very O(mirror) read this narrow base exists to avoid.
func ListByBindingObjectTx(ctx context.Context, tx pgx.Tx, bindingID, objectType, objectID string) ([]Member, error) {
	return queryMembers(ctx, tx,
		`SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status
		   FROM kaname.access_binding_target_members
		  WHERE object_type = $2 AND object_id = $3 AND binding_id = $1
		  ORDER BY rule_fp ASC`,
		bindingID, objectType, objectID)
}

// BindingsForObjectTx returns the distinct binding ids that have a materialized
// member referencing (objectType, objectID). The reconciler uses this on a
// mirror-change event to find which selector/byName bindings must be
// re-evaluated for that object. Served by the
// by-object index.
func BindingsForObjectTx(ctx context.Context, tx pgx.Tx, objectType, objectID string) ([]string, error) {
	// ORDER BY binding_id ASC: the reconciler takes pg_advisory_xact_lock per binding
	// in fan-out order, so the source query MUST return a deterministic order to keep
	// concurrent ReconcileObject passes deadlock-free. The use-case
	// re-sorts the union of both fan-out sources, but a deterministic SQL order keeps
	// the contract honest and the EXPLAIN stable.
	rows, err := tx.Query(ctx,
		`SELECT DISTINCT binding_id
		   FROM kaname.access_binding_target_members
		  WHERE object_type = $1 AND object_id = $2
		  ORDER BY binding_id ASC`,
		objectType, objectID)
	if err != nil {
		return nil, fmt.Errorf("target_members: bindings for object: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("target_members: scan binding id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func queryMembers(ctx context.Context, tx pgx.Tx, sql string, args ...any) ([]Member, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("target_members: query: %w", err)
	}
	defer rows.Close()
	return scanMembers(rows)
}

func scanMembers(rows pgx.Rows) ([]Member, error) {
	var out []Member
	for rows.Next() {
		var (
			m  Member
			st string
		)
		if err := rows.Scan(&m.BindingID, &m.RoleID, &m.RuleFP, &m.ObjectType, &m.ObjectID, &st); err != nil {
			return nil, fmt.Errorf("target_members: scan: %w", err)
		}
		m.VerificationStatus = domain.VerificationStatus(st)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("target_members: rows: %w", err)
	}
	return out, nil
}
