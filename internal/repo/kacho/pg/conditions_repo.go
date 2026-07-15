// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// conditions_repo.go — pgxpool-backed repository for `kacho_iam.conditions`,
// backing ConditionsService.
//
// CRUD pattern is pool-direct for the standalone read path, but each mutation
// ALSO exposes a tx-scoped variant (…Tx) running
// the identical SQL on a caller-supplied pgx.Tx. The tx-scoped variants let the
// ConditionsCRUDService commit the mutation together with its durable
// audit_outbox row in one transaction (запрет #10) — exactly the
// RevokeWithAdmin / RevokeWithAdminTx split used by SessionRevocationRepo.
//
// Race-safety: Update uses CAS on resource_version + RETURNING cardinality
// (within-service refs must be enforced at the DB level).
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// condQuerier — minimal surface shared by *pgxpool.Pool and pgx.Tx, so the
// mutation SQL is written once and runs either pool-direct (legacy read/test
// path) or on a caller-owned tx (atomic with the audit_outbox row).
type condQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ConditionsRepo — pool-direct repository.
type ConditionsRepo struct {
	pool *pgxpool.Pool
}

func NewConditionsRepo(pool *pgxpool.Pool) *ConditionsRepo {
	return &ConditionsRepo{pool: pool}
}

const condCols = `id, folder_id, created_at, name, description, labels,
                  expression, parameters_schema, status, resource_version`

// Get — single condition lookup. Returns ErrNotFound if missing or DELETING.
func (r *ConditionsRepo) Get(ctx context.Context, id domain.ConditionID) (domain.Condition, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM conditions WHERE id = $1`, condCols),
		string(id))
	out, err := scanConditionResource(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Condition{}, iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
	}
	if err != nil {
		return domain.Condition{}, mapErr(err, "", string(id))
	}
	if out.Status == domain.ConditionStatusDeleting {
		return domain.Condition{}, iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
	}
	return out, nil
}

// List — page over conditions in a folder, excluding DELETING tombstones.
func (r *ConditionsRepo) List(ctx context.Context, f condition.ListFilter) ([]domain.Condition, string, error) {
	pageSize := int64(f.PageSize)
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	conditions := []string{"status != 'DELETING'"}
	args := []any{}
	argIdx := 1
	if f.FolderID != "" {
		conditions = append(conditions, fmt.Sprintf("folder_id = $%d", argIdx))
		args = append(args, f.FolderID)
		argIdx++
	}
	if f.Filter != "" {
		if name, ok := parseConditionNameFilter(f.Filter); ok {
			conditions = append(conditions, fmt.Sprintf("name = $%d", argIdx))
			args = append(args, name)
			argIdx++
		}
	}
	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, fmt.Sprintf("(created_at, id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}
	where := "WHERE " + strings.Join(conditions, " AND ")
	q := fmt.Sprintf(`SELECT %s FROM conditions %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		condCols, where, argIdx)
	args = append(args, pageSize+1)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	out := make([]domain.Condition, 0, pageSize)
	for rows.Next() {
		c, err := scanConditionResource(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var next string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		next = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, next, nil
}

// CountReferences — count of AccessBindings referencing this condition via
// access_binding_conditions. This is only a best-effort EARLY message on the
// happy path ("Condition is in use by N AccessBindings"); it is NOT the
// integrity guard. The real guard is the DB-level FK
// access_binding_conditions.condition_id → conditions(id) ON DELETE RESTRICT
// (migration 0048), which closes the count-then-delete TOCTOU: a concurrent
// attach committing after this count read still makes the DELETE fail atomically
// with 23503 → FailedPrecondition.
func (r *ConditionsRepo) CountReferences(ctx context.Context, id domain.ConditionID) (int64, error) {
	return countConditionReferences(ctx, r.pool, id)
}

// CountReferencesTx — tx-scoped CountReferences so the Delete worker can run the
// early-message refcheck inside the SAME tx as the delete + audit row (the FK is
// the actual race-proof enforcement — see CountReferences).
func (r *ConditionsRepo) CountReferencesTx(ctx context.Context, txh service.Tx, id domain.ConditionID) (int64, error) {
	return countConditionReferences(ctx, txAsPgx(txh), id)
}

func countConditionReferences(ctx context.Context, q condQuerier, id domain.ConditionID) (int64, error) {
	// The reference relation is carried by access_binding_conditions.params
	// JSONB ('condition_id' -> id) and, since migration 0048, mirrored into the
	// real, FK-backed condition_id column (derived by a BEFORE trigger). We read
	// via the params path so the count matches the column exactly. Returns 0 on
	// no references.
	var count int64
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM access_binding_conditions
		  WHERE params ->> 'condition_id' = $1`,
		string(id)).Scan(&count)
	if err != nil {
		return 0, mapErr(err, "", string(id))
	}
	return count, nil
}

// Insert — create new Condition row. SQLSTATE 23505 (unique violation) on
// duplicate (folder_id, name) → ErrAlreadyExists.
func (r *ConditionsRepo) Insert(ctx context.Context, c domain.Condition) (domain.Condition, error) {
	return insertCondition(ctx, r.pool, c)
}

// InsertTx — tx-scoped Insert. Runs the identical SQL on a caller-owned tx so
// the condition row commits atomically with its audit_outbox row (запрет #10).
func (r *ConditionsRepo) InsertTx(ctx context.Context, txh service.Tx, c domain.Condition) (domain.Condition, error) {
	return insertCondition(ctx, txAsPgx(txh), c)
}

const insertConditionQ = `
	INSERT INTO conditions (
	    id, folder_id, created_at, name, description, labels,
	    expression, parameters_schema, status, resource_version
	) VALUES ($1, $2, COALESCE($3, now()), $4, $5,
	          COALESCE($6::jsonb, '{}'::jsonb),
	          $7, COALESCE($8::jsonb, '{}'::jsonb),
	          COALESCE(NULLIF($9, ''), 'CREATING'), 1)
	RETURNING ` + condCols

func insertCondition(ctx context.Context, q condQuerier, c domain.Condition) (domain.Condition, error) {
	row := q.QueryRow(ctx, insertConditionQ,
		string(c.ID), c.FolderID, nullableTime(c.CreatedAt),
		c.Name, c.Description, jsonBytesOrEmpty(labelsToJSON(c.Labels)),
		c.Expression, jsonBytesOrEmpty([]byte(c.ParametersSchema)),
		string(c.Status),
	)
	out, err := scanConditionResource(row)
	if err != nil {
		return domain.Condition{}, mapErr(err, c.Name, string(c.ID))
	}
	return out, nil
}

// UpdateMutable — atomic CAS on resource_version. Only mutates fields where
// the patch fields are set.
func (r *ConditionsRepo) UpdateMutable(ctx context.Context, id domain.ConditionID, patch condition.UpdatePatch, expectedVersion int64) (domain.Condition, error) {
	return updateMutableCondition(ctx, r.pool, id, patch, expectedVersion)
}

// UpdateMutableTx — tx-scoped UpdateMutable (atomic with the audit_outbox row,
// запрет #10). Identical CAS-on-resource_version semantics.
func (r *ConditionsRepo) UpdateMutableTx(ctx context.Context, txh service.Tx, id domain.ConditionID, patch condition.UpdatePatch, expectedVersion int64) (domain.Condition, error) {
	return updateMutableCondition(ctx, txAsPgx(txh), id, patch, expectedVersion)
}

func updateMutableCondition(ctx context.Context, q condQuerier, id domain.ConditionID, patch condition.UpdatePatch, expectedVersion int64) (domain.Condition, error) {
	sets := []string{"resource_version = resource_version + 1"}
	args := []any{string(id), expectedVersion}
	argIdx := 3
	if patch.Description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", argIdx))
		args = append(args, *patch.Description)
		argIdx++
	}
	if patch.HasLabels {
		sets = append(sets, fmt.Sprintf("labels = $%d::jsonb", argIdx))
		args = append(args, jsonBytesOrEmpty(labelsToJSON(patch.Labels)))
		argIdx++
	}
	if patch.Expression != nil {
		sets = append(sets, fmt.Sprintf("expression = $%d", argIdx))
		args = append(args, *patch.Expression)
		argIdx++
	}
	if patch.HasParamsSchema {
		sets = append(sets, fmt.Sprintf("parameters_schema = $%d::jsonb", argIdx))
		args = append(args, jsonBytesOrEmpty(patch.ParametersSchema))
	}
	sql := fmt.Sprintf(`UPDATE conditions
	                   SET %s
	                 WHERE id = $1 AND resource_version = $2
	                 RETURNING %s`, strings.Join(sets, ", "), condCols)
	row := q.QueryRow(ctx, sql, args...)
	out, err := scanConditionResource(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// CAS failure: row exists with different version, OR row missing.
		// Distinguish by a separate read on the SAME querier.
		exists, e2 := conditionExists(ctx, q, id)
		if e2 != nil {
			return domain.Condition{}, e2
		}
		if !exists {
			return domain.Condition{}, iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
		}
		return domain.Condition{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"Condition %s changed concurrently — retry", id)
	}
	if err != nil {
		return domain.Condition{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// SetStatus — set status, no-op CAS (single-shot).
func (r *ConditionsRepo) SetStatus(ctx context.Context, id domain.ConditionID, newStatus domain.ConditionStatus) error {
	return setConditionStatus(ctx, r.pool, id, newStatus)
}

// SetStatusTx — tx-scoped SetStatus (atomic with the audit_outbox row).
func (r *ConditionsRepo) SetStatusTx(ctx context.Context, txh service.Tx, id domain.ConditionID, newStatus domain.ConditionStatus) error {
	return setConditionStatus(ctx, txAsPgx(txh), id, newStatus)
}

func setConditionStatus(ctx context.Context, q condQuerier, id domain.ConditionID, newStatus domain.ConditionStatus) error {
	tag, err := q.Exec(ctx,
		`UPDATE conditions SET status = $2 WHERE id = $1`,
		string(id), string(newStatus))
	if err != nil {
		return mapErr(err, "", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
	}
	return nil
}

// Delete — hard delete a row. Caller must have already verified no references
// and status=DELETING.
func (r *ConditionsRepo) Delete(ctx context.Context, id domain.ConditionID) error {
	return deleteCondition(ctx, r.pool, id)
}

// DeleteTx — tx-scoped Delete (atomic with the audit_outbox row, запрет #10).
func (r *ConditionsRepo) DeleteTx(ctx context.Context, txh service.Tx, id domain.ConditionID) error {
	return deleteCondition(ctx, txAsPgx(txh), id)
}

func deleteCondition(ctx context.Context, q condQuerier, id domain.ConditionID) error {
	tag, err := q.Exec(ctx, `DELETE FROM conditions WHERE id = $1`, string(id))
	if err != nil {
		// kindHint "Condition.Delete" — a 23503 here is the ON DELETE RESTRICT
		// FK (migration 0048) firing because a concurrent attach referenced this
		// Condition after the software CountReferences precheck read 0; map it to
		// the in-use FailedPrecondition text (not "not found").
		return mapErr(err, "Condition.Delete", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "Condition %s not found", id)
	}
	return nil
}

func conditionExists(ctx context.Context, q condQuerier, id domain.ConditionID) (bool, error) {
	var one int
	err := q.QueryRow(ctx, `SELECT 1 FROM conditions WHERE id = $1`, string(id)).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, mapErr(err, "", string(id))
	}
	return true, nil
}

func scanConditionResource(row pgx.Row) (domain.Condition, error) {
	var (
		c                          domain.Condition
		labelsRaw, paramsSchemaRaw []byte
		createdAt                  time.Time
		status                     string
	)
	if err := row.Scan(
		(*string)(&c.ID), &c.FolderID, &createdAt, &c.Name, &c.Description,
		&labelsRaw, &c.Expression, &paramsSchemaRaw, &status, &c.ResourceVersion,
	); err != nil {
		return domain.Condition{}, err
	}
	c.CreatedAt = createdAt.UTC().Truncate(time.Second)
	c.Status = domain.ConditionStatus(status)
	if len(labelsRaw) > 0 {
		labels := map[string]string{}
		if err := json.Unmarshal(labelsRaw, &labels); err == nil {
			c.Labels = labels
		}
	}
	c.ParametersSchema = domain.ConditionParametersSchema(append([]byte(nil), paramsSchemaRaw...))
	return c, nil
}

// labelsToJSON — marshal labels map to []byte. nil/empty → `{}`.
func labelsToJSON(m map[string]string) []byte {
	if len(m) == 0 {
		return []byte("{}")
	}
	b, _ := json.Marshal(m)
	return b
}

// parseConditionNameFilter — minimal Kachō filter parser for `name=<val>`.
func parseConditionNameFilter(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "name=") {
		return "", false
	}
	v := strings.TrimPrefix(s, "name=")
	v = strings.Trim(v, `"`)
	if v == "" {
		return "", false
	}
	return v, true
}

// conditionsTxWriter — the tx-scoped mutation surface ConditionsRepo exposes for
// atomic-with-audit commits (takes the opaque service.Tx; the concrete pgx.Tx is
// recovered via txAsPgx). Declared locally as a compile-time guard; the
// consuming port lives in the service layer (conditions_crud_service.go).
type conditionsTxWriter interface {
	InsertTx(ctx context.Context, tx service.Tx, c domain.Condition) (domain.Condition, error)
	UpdateMutableTx(ctx context.Context, tx service.Tx, id domain.ConditionID, patch condition.UpdatePatch, expectedVersion int64) (domain.Condition, error)
	SetStatusTx(ctx context.Context, tx service.Tx, id domain.ConditionID, newStatus domain.ConditionStatus) error
	DeleteTx(ctx context.Context, tx service.Tx, id domain.ConditionID) error
	CountReferencesTx(ctx context.Context, tx service.Tx, id domain.ConditionID) (int64, error)
}

// Compile-time guards.
var (
	_ condition.ReaderIface = (*ConditionsRepo)(nil)
	_ condition.WriterIface = (*ConditionsRepo)(nil)
	_ conditionsTxWriter    = (*ConditionsRepo)(nil)
)
