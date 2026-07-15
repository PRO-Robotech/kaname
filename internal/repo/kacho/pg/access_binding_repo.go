// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// access_binding_repo.go — pgxpool-impl для access_binding.ReaderIface / WriterIface;
// lifecycle state machine on access_bindings.status (PENDING → ACTIVE → REVOKED).
//
// Strict Insert:
//
//   INSERT INTO kacho_iam.access_bindings (...)
//   VALUES ($newID, $st, $sid, $rid, $rt, $rid2, $status, $cond, $exp, $grb, $rva, $rvb, now())
//   RETURNING id, ..., created_at;
//
// На дубле (subject_id, subject_type, role_id, resource_type, resource_id)
// с revoked_at IS NULL — partial UNIQUE access_bindings_active_grant_uniq
// (migration 0003) поднимает 23505 → mapErr → ErrAlreadyExists с verbatim
// «these permissions are already granted to <subject_id> on <res_type>:<res_id>».
// Прежний `ON CONFLICT DO UPDATE SET id = access_bindings.id` (silent
// idempotent-upsert) удален — он маскировал реальный duplicate-grant и
// засорял audit-чейн.
//
// Full column coverage (13 cols):
//   id, subject_type, subject_id, role_id, resource_type, resource_id,
//   status (PENDING|ACTIVE|REVOKED — DEFAULT 'ACTIVE'), condition_id (nullable FK),
//   expires_at (nullable TTL), granted_by_user_id (audit),
//   revoked_at (nullable), revoked_by_user_id (nullable), created_at.
//
// State machine: PENDING → ACTIVE → REVOKED (terminal).
// TransitionStatus(...) — single-statement CAS UPDATE WHERE status IN (expected);
// 0 rows из RETURNING → ErrFailedPrecondition (no TOCTOU; within-service refs
// must be enforced at the DB level).
//
// Within-service refs — DB-level invariants:
//   - UNIQUE access_bindings_active_grant_uniq (5-tuple WHERE revoked_at IS NULL)
//     → 23505 → ErrAlreadyExists (verbatim text per idHint encoding).
//   - FK access_bindings_role_fk → SQLSTATE 23503 → ErrFailedPrecondition.
//   - CHECK access_bindings_status_ck — SQLSTATE 23514 → ErrInvalidArg.
//   - CHECK access_bindings_revoked_consistency_ck — same.
//   - subject_id/resource_id — soft-ref (нет FK; polymorphic + cross-DB).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type abReader struct {
	tx pgx.Tx
}

// abCols — 15 колонок access_bindings (RBAC v2 + scope + deletion_protection).
// Order parity между SELECT (scanAB) и RETURNING (Insert/TransitionStatus/
// SetDeletionProtection/DeleteGuarded).
const abCols = "id, subject_type, subject_id, role_id, resource_type, resource_id, " +
	"status, condition_id, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope, " +
	"deletion_protection, labels"

func (r *abReader) Get(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

// GetForUpdate is Get with a `FOR UPDATE` row-lock on the binding row. The γ
// reconciler calls it as the FIRST statement of its writer-tx (LoadBinding) so
// two concurrent reconcile passes of the SAME binding are serialized on the row-
// lock: the second pass blocks until the first commits its
// membership diff, then re-reads CurrentMembers seeing the already-ACTIVE member
// (no status change → idempotent skip) and emits ZERO duplicate fga_outbox
// tuples. This is a parent-row-lock critical-section pattern. A missing row ⇒
// ErrNotFound (the binding was deleted — the reconciler then does nothing).
func (r *abReader) GetForUpdate(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	row := r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings WHERE id = $1 FOR UPDATE`, abCols), string(id))
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "", string(id))
	}
	return out, nil
}

func (r *abReader) ListByScope(ctx context.Context, resourceType domain.ResourceType, resourceID string, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWithConds(ctx, f,
		[]string{"resource_type = $%d", "resource_id = $%d"},
		[]any{string(resourceType), resourceID})
}

func (r *abReader) ListBySubject(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return r.listWithConds(ctx, f,
		[]string{"subject_type = $%d", "subject_id = $%d"},
		[]any{string(subjectType), string(subjectID)})
}

// ListByAccount — admin path returning every binding in an Account scope:
//
//   - bindings directly attached to the account (resource_type='account'
//     AND resource_id = $accountID); plus
//   - bindings on every Project whose account_id = $accountID
//     (resource_type='project' AND resource_id IN (SELECT id FROM projects
//     WHERE account_id = $accountID)).
//
// Optional SubjectTypeFilter narrows to a single subject_type.
// IncludeRevoked=false (default) hides status='REVOKED' rows.
//
// Ordering: (created_at DESC, id ASC) — newest grants first; ties broken by
// id ASC to keep keyset cursors deterministic.
//
// Keyset cursor format matches encodePageToken/decodePageToken (opaque
// base64 (created_at, id)) but applies the DESC predicate
// `(created_at, id) < ($prev_ts, $prev_id)`.
//
// Within-service refs (ban #10): the subquery uses
// the FK-validated projects table — no cross-DB call required, no TOCTOU.
func (r *abReader) ListByAccount(ctx context.Context, accountID domain.AccountID, f access_binding.AccountPageFilter) ([]domain.AccessBinding, string, error) {
	pageSize := int64(f.PageSize)
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	// $1 = accountID — referenced twice (direct + project scope).
	args := []any{string(accountID)}
	argIdx := 2

	conditions := []string{
		`((resource_type = 'account' AND resource_id = $1)
		   OR (resource_type = 'project'
		       AND resource_id IN (SELECT id FROM projects WHERE account_id = $1)))`,
	}

	if !f.IncludeRevoked {
		conditions = append(conditions, `status <> 'REVOKED'`)
	}

	if f.SubjectTypeFilter != "" {
		conditions = append(conditions, fmt.Sprintf("subject_type = $%d", argIdx))
		args = append(args, f.SubjectTypeFilter)
		argIdx++
	}

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		// DESC keyset predicate: (created_at, id) < (last_seen_created_at, last_seen_id)
		// when ordered by created_at DESC + id ASC. We treat id ASC as a tiebreaker:
		// (created_at < ts) OR (created_at = ts AND id > prev_id).
		conditions = append(conditions,
			fmt.Sprintf(`(created_at < $%d OR (created_at = $%d AND id > $%d))`,
				argIdx, argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s
		ORDER BY created_at DESC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListSubjectPrivileges — enriched read for the subject-privileges view.
// Returns the subject's DIRECT AccessBindings LEFT JOINed with
// `roles` so the human-readable role_name is resolved server-side in ONE query
// (access_bindings ab ⋈ roles r ON ab.role_id = r.id; same kacho_iam schema,
// FK access_bindings_role_fk — no per-row N+1).
//
// LEFT JOIN (not INNER): a dangling role (deleted after a revoke) must not drop
// the row — the binding is returned with role_name="" (graceful).
//
// Only PENDING/ACTIVE rows are returned (status <> 'REVOKED' — parity with
// ListByAccount.include_revoked=false). v1 is DIRECT-only — subject_id literally
// equals the requested subject.
//
// Ordering & keyset cursor match ListBySubject: (created_at, id) ASC with an
// opaque base64 (created_at, id) page_token; (created_at, id) > (prev) predicate.
// page_size: 0 → DefaultPageSize(50), capped at 1000.
//
// Within-service refs (запрет #10): the JOIN reads the FK-validated `roles`
// table — no cross-DB call, no TOCTOU. Read-only — no CAS/race path.
func (r *abReader) ListSubjectPrivileges(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f access_binding.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	pageSize := int64(f.PageSize)
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	conditions := []string{
		"ab.subject_type = $1",
		"ab.subject_id = $2",
		"ab.status <> 'REVOKED'",
	}
	args := []any{string(subjectType), string(subjectID)}
	argIdx := 3

	if f.PageToken != "" {
		ts, id, err := decodePageToken(f.PageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions,
			fmt.Sprintf("(ab.created_at, ab.id) > ($%d, $%d)", argIdx, argIdx+1))
		args = append(args, ts, id)
		argIdx += 2
	}

	// COALESCE(r.name, '') so a LEFT JOIN miss (dangling role) scans as "" — the
	// Go scan target is a plain string, never NULL.
	q := fmt.Sprintf(`
		SELECT ab.id, ab.role_id, COALESCE(r.name, ''),
		       ab.resource_type, ab.resource_id, ab.scope, ab.status,
		       ab.created_at, ab.granted_by_user_id, ab.expires_at
		  FROM access_bindings ab
		  LEFT JOIN roles r ON ab.role_id = r.id
		 WHERE %s
		 ORDER BY ab.created_at ASC, ab.id ASC
		 LIMIT $%d`, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.SubjectPrivilege
	for rows.Next() {
		sp, serr := scanSubjectPrivilege(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, sp)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}

	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.BindingID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// scanSubjectPrivilege — maps a ListSubjectPrivileges row into the enriched
// domain projection. role_name is already COALESCE'd to ” (dangling role).
// scope is bounds-checked the same way as scanAB.
func scanSubjectPrivilege(row scanner) (domain.SubjectPrivilege, error) {
	var (
		sp        domain.SubjectPrivilege
		expiresAt sql.NullTime
		scopeI    int16
	)
	err := row.Scan(
		(*string)(&sp.BindingID),
		(*string)(&sp.RoleID),
		(*string)(&sp.RoleName),
		(*string)(&sp.ResourceType),
		&sp.ResourceID,
		&scopeI,
		(*string)(&sp.Status),
		&sp.CreatedAt,
		(*string)(&sp.GrantedByUserID),
		&expiresAt,
	)
	if err != nil {
		return domain.SubjectPrivilege{}, err
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		sp.ExpiresAt = &t
	}
	if scopeI < 0 || scopeI > 3 {
		sp.Scope = domain.ScopeUnspecified
	} else {
		sp.Scope = domain.Scope(scopeI) //nolint:gosec // bound-checked above
	}
	return sp, nil
}

// listWithConds — общий path-builder для ListByScope/ListBySubject.
func (r *abReader) listWithConds(ctx context.Context, f access_binding.PageFilter, condTmpls []string, condArgs []any) ([]domain.AccessBinding, string, error) {
	pageSize := int64(f.PageSize)
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	conditions := []string{}
	args := []any{}
	argIdx := 1
	for i, tmpl := range condTmpls {
		conditions = append(conditions, fmt.Sprintf(tmpl, argIdx))
		args = append(args, condArgs[i])
		argIdx++
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

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()

	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, "", mapErr(err, "", "")
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

type abWriter struct {
	abReader
}

// Insert — strict create. На дубле (subject_type, subject_id, role_id,
// resource_type, resource_id) с revoked_at IS NULL — partial UNIQUE
// access_bindings_active_grant_uniq (миграция 0003) поднимает SQLSTATE 23505,
// который маппится в ErrAlreadyExists с verbatim text:
//
//	"these permissions are already granted to <subject_id> on <resource_type>:<resource_id>"
//
// Прежняя идемпотентность (ON CONFLICT DO UPDATE SET id = access_bindings.id)
// удалена: silent-upsert скрывал реальный duplicate-grant и заставлял ревьюера
// разбираться, почему один и тот же тапл создавался под разными id. Use-case
// больше не вызывает FindExisting для pre-resolution candidate-id; reseats
// strictly create-or-conflict.
//
// Записывает все 13 колонок. Пустой Status проходит как DB-default ACTIVE
// (через COALESCE(NULLIF($7, ”), 'ACTIVE')). Nullable поля (condition_id,
// expires_at, revoked_at, revoked_by_user_id) передаются через
// nullableString/nullableTimePtr хелперы.
func (w *abWriter) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	now := time.Now().UTC()
	// Scope: explicit value when non-Unspecified, otherwise let the
	// access_bindings_scope_default_trg trigger derive from resource_type
	// (migration 0005). Passing SMALLINT NULL trips the NOT NULL constraint
	// AFTER the trigger only when the trigger leaves NEW.scope NULL — which
	// it never does (the trigger has an ELSE branch).
	// labels — own-resource tenant-facing метки самого binding-ресурса,
	// делают AccessBinding label-selectable (catalog-видимость через viewer ∪ v_list).
	labelsJSON, err := marshalLabels(b.Labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	q := fmt.Sprintf(`
		INSERT INTO access_bindings (
			id, subject_type, subject_id, role_id, resource_type, resource_id,
			status, condition_id, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, created_at, scope,
			deletion_protection, labels
		)
		VALUES (
			$1, $2, $3, $4, $5, $6,
			COALESCE(NULLIF($7, ''), 'ACTIVE'),
			$8, $9, $10, $11, $12, $13, $14, $15, $16
		)
		RETURNING %s`, abCols)
	var scopeArg any
	if b.Scope == domain.ScopeUnspecified {
		scopeArg = nil
	} else {
		scopeArg = int16(b.Scope)
	}
	row := w.tx.QueryRow(ctx, q,
		string(b.ID), string(b.SubjectType), string(b.SubjectID), string(b.RoleID),
		string(b.ResourceType), b.ResourceID,
		string(b.Status),
		nullableString(string(b.ConditionID)),
		nullableTimePtr(b.ExpiresAt),
		string(b.GrantedByUserID),
		nullableTimePtr(b.RevokedAt),
		nullableUserIDPtr(b.RevokedByUserID),
		now,
		scopeArg,
		b.DeletionProtection,
		labelsJSON,
	)
	out, err := scanAB(row)
	if err != nil {
		// idHint encoding for uniqueText: "<subject_id>|<resource_type>:<resource_id>".
		idHint := fmt.Sprintf("%s|%s:%s", b.SubjectID, b.ResourceType, b.ResourceID)
		return domain.AccessBinding{}, mapErr(err, "", idHint)
	}
	return out, nil
}

// Delete — простой DELETE. 0 rows → NotFound. Used by paths that have already
// established the binding is deletable (reconcile/expire) or by tests; the public
// Delete use-case goes through DeleteGuarded (P6 deletion_protection CAS).
func (w *abWriter) Delete(ctx context.Context, id domain.AccessBindingID) error {
	tag, err := w.tx.Exec(ctx, `DELETE FROM access_bindings WHERE id = $1`, string(id))
	if err != nil {
		return mapErr(err, "", string(id))
	}
	if tag.RowsAffected() == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
	}
	return nil
}

// DeleteGuarded — атомарный CAS-delete (по образцу vpc.address.DeleteGuarded). Single-statement
// `DELETE … WHERE id=$1 AND deletion_protection=false` берет row-lock: конкурентный
// writer ждет commit, затем видит строку уже удаленной (его CAS → 0 строк →
// NotFound) ИЛИ строку с deletion_protection=true (его CAS → 0 строк →
// FailedPrecondition). Никакого software TOCTOU (ban #10). 0 строк → повторное
// чтение различает not-found / protected.
func (w *abWriter) DeleteGuarded(ctx context.Context, id domain.AccessBindingID) error {
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_bindings WHERE id = $1 AND deletion_protection = false`, string(id))
	if err != nil {
		return mapErr(err, "", string(id))
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	// 0 rows: not-found vs protected — re-read on this tx.
	cur, gerr := w.Get(ctx, id)
	if gerr != nil {
		return gerr // ErrNotFound (или иная)
	}
	if cur.DeletionProtection {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"access binding %s has deletion_protection enabled; clear it via Update before Delete", id)
	}
	// Row exists, unprotected, yet 0 rows deleted → concurrent delete won the race.
	return iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
}

// SetDeletionProtection — atomic CAS UPDATE of the deletion_protection flag.
// Single-statement
// `UPDATE … WHERE id=$1 RETURNING …`; 0 rows → NotFound. Used by the
// Update(update_mask=["deletion_protection"]) path to clear the flag.
func (w *abWriter) SetDeletionProtection(ctx context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error) {
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET deletion_protection = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), protected)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.SetDeletionProtection", string(id))
	}
	return out, nil
}

// UpdateLabels — atomic single-statement UPDATE of the own-resource labels
// (AB mutable set расширен до {deletion_protection, labels}).
// `UPDATE … SET labels=$2 WHERE id=$1 RETURNING …` берет row-lock: конкурентный
// writer ждет commit и видит обновленный row (last-writer-wins, не TOCTOU, ban #10).
// 0 rows RETURNING → NotFound. Identity/scope/subject поля не затрагиваются.
func (w *abWriter) UpdateLabels(ctx context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error) {
	labelsJSON, err := marshalLabels(labels)
	if err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument labels: %s", err.Error())
	}
	row := w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE access_bindings
		   SET labels = $2
		 WHERE id = $1
		RETURNING %s`, abCols), string(id), labelsJSON)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrNotFound, "AccessBinding %s not found", id)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.UpdateLabels", string(id))
	}
	return out, nil
}

// TransitionStatus — atomic CAS UPDATE для state machine (PENDING → ACTIVE → REVOKED).
// Single-statement `UPDATE … WHERE id=$1 AND status = ANY($expected) RETURNING …`;
// 0 rows из RETURNING → ErrFailedPrecondition (терминальный state или mismatch).
// SQLSTATE 23514 (CHECK violation для невалидного newState) → ErrInvalidArg.
//
// При transition в REVOKED обязательно передается revokedByUserID (CHECK
// access_bindings_revoked_consistency_ck). Для PENDING→ACTIVE / ACTIVE→ACTIVE
// revokedByUserID игнорируется (NULL в DB).
//
// Race-safety: row-level lock Postgres гарантирует one-winner на одну row;
// параллельный writer ждет commit-а первого и видит уже измененное значение.
func (w *abWriter) TransitionStatus(
	ctx context.Context,
	id domain.AccessBindingID,
	expected []domain.AccessBindingStatus,
	newStatus domain.AccessBindingStatus,
	revokedByUserID *domain.UserID,
) (domain.AccessBinding, error) {
	if err := newStatus.Validate(); err != nil {
		return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if len(expected) == 0 {
		return domain.AccessBinding{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "expected statuses must not be empty")
	}
	expStrings := make([]string, len(expected))
	for i, s := range expected {
		expStrings[i] = string(s)
	}
	now := time.Now().UTC()
	var (
		revAtArg any
		revByArg any
	)
	if newStatus == domain.AccessBindingStatusRevoked {
		revAtArg = now
		if revokedByUserID == nil || *revokedByUserID == "" {
			return domain.AccessBinding{},
				iamerr.Wrapf(iamerr.ErrInvalidArg, "revoked_by_user_id is required for REVOKED transition")
		}
		revByArg = string(*revokedByUserID)
	} else {
		// PENDING / ACTIVE — revoked_at / revoked_by must be NULL (CHECK).
		revAtArg = nil
		revByArg = nil
	}
	q := fmt.Sprintf(`
		UPDATE access_bindings
		   SET status              = $2,
		       revoked_at          = $3,
		       revoked_by_user_id  = $4
		 WHERE id = $1
		   AND status = ANY($5)
		RETURNING %s`, abCols)
	row := w.tx.QueryRow(ctx, q,
		string(id), string(newStatus), revAtArg, revByArg, expStrings,
	)
	out, err := scanAB(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.AccessBinding{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"AccessBinding %s cannot transition to %s (not in expected states %v)",
				id, newStatus, expected)
		}
		return domain.AccessBinding{}, mapErr(err, "AccessBinding.TransitionStatus", string(id))
	}
	return out, nil
}

func scanAB(row scanner) (domain.AccessBinding, error) {
	return scanABWithVersion(row)
}

// scanABWithVersion scans the canonical abCols into a domain.AccessBinding. When
// versionOut is provided (γ GetWithVersion) the query MUST prepend an
// `xmin::text` column and the token is written into *versionOut[0] — the Scan
// dest list is built with the version slot first to match. Without versionOut it
// is the plain abCols scan (parity with the prior scanAB). Single helper keeps
// the field list DRY across Get / GetWithVersion / list paths.
func scanABWithVersion(row scanner, versionOut ...*string) (domain.AccessBinding, error) {
	var (
		ab           domain.AccessBinding
		conditionID  sql.NullString
		expiresAt    sql.NullTime
		revokedAt    sql.NullTime
		revokedByUID sql.NullString
		scopeI       int16
		labelsJSON   []byte
	)
	dest := make([]any, 0, 17)
	if len(versionOut) > 0 {
		dest = append(dest, versionOut[0])
	}
	dest = append(dest,
		(*string)(&ab.ID),
		(*string)(&ab.SubjectType),
		(*string)(&ab.SubjectID),
		(*string)(&ab.RoleID),
		(*string)(&ab.ResourceType),
		&ab.ResourceID,
		(*string)(&ab.Status),
		&conditionID,
		&expiresAt,
		(*string)(&ab.GrantedByUserID),
		&revokedAt,
		&revokedByUID,
		&ab.CreatedAt,
		&scopeI,
		&ab.DeletionProtection,
		&labelsJSON,
	)
	err := row.Scan(dest...)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	ab.Labels, err = unmarshalLabels(labelsJSON)
	if err != nil {
		return domain.AccessBinding{}, err
	}
	if conditionID.Valid {
		ab.ConditionID = domain.AccessBindingConditionID(conditionID.String)
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		ab.ExpiresAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		ab.RevokedAt = &t
	}
	if revokedByUID.Valid {
		u := domain.UserID(revokedByUID.String)
		ab.RevokedByUserID = &u
	}
	// gosec G115 — bounds-check int16 → int8 conversion. Scope values are
	// {0,1,2,3} guarded by access_bindings_scope_ck CHECK; any other value
	// is a corrupt row that we surface as an explicit Unspecified rather
	// than silently truncating.
	if scopeI < 0 || scopeI > 3 {
		ab.Scope = domain.ScopeUnspecified
	} else {
		ab.Scope = domain.Scope(scopeI) //nolint:gosec // bound-checked above
	}
	return ab, nil
}

// EmitSubjectChangeEvent — writes both legacy denormalised
// columns AND the canonical event_type + payload jsonb in a single INSERT.
// Single-row INSERT is atomic by construction; combined with the enclosing
// writer-tx, the outbox row is committed iff the surrounding domain mutation
// commits (within-service refs must be enforced at the DB level).
//
// payload is REQUIRED by the corelib drainer SELECT contract — Decoder[T]
// receives ONLY payload bytes, not other row columns.
func (w *abWriter) EmitSubjectChangeEvent(ctx context.Context, evt access_binding.SubjectChangeEvent) error {
	if evt.SubjectID == "" {
		return fmt.Errorf("emit subject_change_outbox: subject_id required")
	}
	if evt.EventType == "" {
		evt.EventType = deriveEventTypeFromOp(evt.Op)
	}
	if evt.Op == "" {
		evt.Op = deriveOpFromEventType(evt.EventType)
	}

	payload, err := json.Marshal(struct {
		SubjectID    string `json:"subject_id"`
		Op           string `json:"op"`
		EventType    string `json:"event_type"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
	}{
		SubjectID:    evt.SubjectID,
		Op:           evt.Op,
		EventType:    evt.EventType,
		ResourceType: evt.ResourceType,
		ResourceID:   evt.ResourceID,
	})
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: marshal payload: %w", err)
	}

	// nullable optional columns
	var resType, resID any
	if evt.ResourceType != "" {
		resType = evt.ResourceType
	}
	if evt.ResourceID != "" {
		resID = evt.ResourceID
	}

	_, err = w.tx.Exec(ctx, `
		INSERT INTO kacho_iam.subject_change_outbox
			(subject_id, op, event_type, resource_type, resource_id, payload)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
		evt.SubjectID, evt.Op, evt.EventType, resType, resID, payload)
	if err != nil {
		return fmt.Errorf("emit subject_change_outbox: %w", err)
	}
	return nil
}

// EmitRelationWrite — atomically appends N grant rows into
// kacho_iam.fga_outbox (event_type='fga.tuple.write') in the current
// writer-tx (atomicity required — see within-service refs). Drainer
// (clients/fga_applier.go) asynchronously applies to OpenFGA with retry +
// idempotency.
//
// The binding INSERT and FGA enqueue commit-or-rollback atomically — no
// post-commit sync OpenFGA writes that could diverge from the DB on failure.
func (w *abWriter) EmitRelationWrite(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.write", tuples)
}

// EmitRelationDelete — mirror of EmitRelationWrite for revoke. Caller supplies the
// EXACT tuples that were originally written by EmitRelationWrite (symmetric revoke).
func (w *abWriter) EmitRelationDelete(ctx context.Context, tuples []access_binding.RelationTuple) error {
	return w.emitFGAOutbox(ctx, "fga.tuple.delete", tuples)
}

// InsertEmittedTuples persists the EXACT FGA tuples emitted for a binding into
// kacho_iam.access_binding_emitted_tuples in the current writer-tx, co-committed
// with the matching EmitRelationWrite (ban #10). ON CONFLICT DO NOTHING
// keeps a repeated emit (idempotent re-grant / reconcile) a no-op. len==0 no-op.
func (w *abWriter) InsertEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("insert emitted tuple: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		if _, err := w.tx.Exec(ctx,
			// source='binding': written by Create + the Role.Update RoleTupleReconciler.
			// ARM_LABELS per-member rows (source='member') are owned by the γ reconciler
			// (RecordEmittedTuples) and MUST NOT be touched by the binding-level path.
			`INSERT INTO access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
			 VALUES ($1, $2, $3, $4, 'binding')
			 ON CONFLICT (binding_id, fga_user, relation, object) DO NOTHING`,
			string(bindingID), t.User, t.Relation, t.Object,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// ReplaceEmittedTuples atomically replaces a binding's persisted emitted-set
// (DELETE all rows of the binding, then INSERT the new set) in the current
// writer-tx — the Role.Update reconcile fan-out uses it so the ledger reflects
// the CURRENT emitted projection after a permission change (ban #10).
// An empty `tuples` clears the binding's ledger rows.
func (w *abWriter) ReplaceEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []access_binding.RelationTuple) error {
	// Scope the wholesale swap to the BINDING-LEVEL subset (source='binding'). The
	// Role.Update reconcile (RoleTupleReconciler) owns only those tuples; the
	// ARM_LABELS per-member rows (source='member', written by the γ reconciler) are
	// owned by RoleMembershipFanout and MUST survive a binding-level reconcile —
	// otherwise a rules-changing Role.Update of a custom role mixing a binding-level
	// arm with an ARM_LABELS arm would revoke all label-selected access (the prior
	// `DELETE … WHERE binding_id` wiped them). InsertEmittedTuples re-inserts the new
	// set as source='binding'.
	if _, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_emitted_tuples WHERE binding_id = $1 AND source = 'binding'`, string(bindingID),
	); err != nil {
		return mapErr(err, "", string(bindingID))
	}
	return w.InsertEmittedTuples(ctx, bindingID, tuples)
}

func (w *abWriter) emitFGAOutbox(ctx context.Context, eventType string, tuples []access_binding.RelationTuple) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("emit fga_outbox: incomplete tuple (user=%q relation=%q object=%q)",
				t.User, t.Relation, t.Object)
		}
		payload, err := json.Marshal(map[string]string{
			"user":     t.User,
			"relation": t.Relation,
			"object":   t.Object,
		})
		if err != nil {
			return fmt.Errorf("emit fga_outbox: marshal payload: %w", err)
		}
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
			 VALUES ($1, $2::jsonb, now())`,
			eventType, payload,
		); err != nil {
			return fmt.Errorf("emit fga_outbox %s: %w", eventType, err)
		}
	}
	return nil
}

// EmitAuditEvent atomically appends one durable compliance row into
// kacho_iam.audit_outbox in the current writer-tx (atomicity required — see
// within-service refs, запрет #10). The binding INSERT/DELETE and the audit
// enqueue commit-or-rollback together: a rolled-back grant leaves no audit row
// claiming it happened, and a committed grant always leaves its trail.
//
// The event_payload jsonb carries the compliance dimensions (actor / subject /
// resource / role_id / binding_id) so the "who granted which role to whom on
// which resource, and when" question is queryable; created_at supplies the
// "when". The row starts status='pending' for the audit drainer.
func (w *abWriter) EmitAuditEvent(ctx context.Context, ev access_binding.AuditEvent) error {
	if ev.EventType == "" {
		return fmt.Errorf("emit audit_outbox: event_type required")
	}
	// Canonical compliance dimensions, then merge any event-specific
	// ExtraPayload (e.g. selector_replaced's old/new diff). Build as map[string]any
	// so heterogeneous extra fields (nested objects) are representable; keys in
	// ExtraPayload override the canonical ones on collision.
	fields := map[string]any{
		"actor":         ev.Actor,
		"subject_type":  ev.SubjectType,
		"subject_id":    ev.SubjectID,
		"resource_type": ev.ResourceType,
		"resource_id":   ev.ResourceID,
		"role_id":       ev.RoleID,
		"binding_id":    ev.BindingID,
	}
	for k, v := range ev.ExtraPayload {
		fields[k] = v
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("emit audit_outbox: marshal payload: %w", err)
	}
	// tenant_account_id is nullable (per-account scoping when known).
	tenant := nullableString(ev.TenantAccountID)
	if _, err := w.tx.Exec(ctx,
		`INSERT INTO kacho_iam.audit_outbox
			(id, event_type, tenant_account_id, event_payload, status, attempts, created_at, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, now(), now())`,
		newAuditEventID(), string(ev.EventType), tenant, payload,
	); err != nil {
		return fmt.Errorf("emit audit_outbox %s: %w", ev.EventType, err)
	}
	return nil
}

// newAuditEventID returns an audit_outbox id of the form `evt_<22-char
// crockford-base32>`, satisfying the audit_outbox_id_check regex
// (`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`). The 22-char body mirrors
// the proven bootstrap-admin generator; domain.NewKac127ID produces only a
// 17-char body, which is below the CHECK's 20-char floor.
func newAuditEventID() string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	const bodyLen = 22
	var raw [14]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand.Read does not fail on a healthy host; a failure means
		// the system entropy source is broken — panic is the correct response.
		panic("pg: crypto/rand failed: " + err.Error())
	}
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[6:14])

	var sb strings.Builder
	sb.Grow(len("evt_") + bodyLen)
	sb.WriteString("evt_")
	for i := 0; i < bodyLen; i++ {
		bitOff := uint(i*5) % 64 // #nosec G115 -- i is the bounded loop index [0,bodyLen); i*5 cannot overflow uint.
		src := hi
		if i >= 12 {
			src = lo
		}
		val := (src >> (64 - bitOff - 5)) & 0x1f
		sb.WriteByte(crockford[val])
	}
	return sb.String()
}

// deriveEventTypeFromOp — canonical event_type for a legacy op alias.
// binding_delete→binding_revoke, binding_upsert→binding_grant, else passthrough.
func deriveEventTypeFromOp(op string) string {
	switch op {
	case "binding_delete":
		return "binding_revoke"
	case "binding_upsert":
		return "binding_grant"
	default:
		return op
	}
}

// deriveOpFromEventType — legacy op alias for a canonical event_type.
// Inverse of deriveEventTypeFromOp; used when caller provides only event_type
// (Op must satisfy DB CHECK subject_change_op_check, so we must populate it).
func deriveOpFromEventType(eventType string) string {
	switch eventType {
	case "binding_revoke":
		return "binding_delete"
	case "binding_grant":
		return "binding_upsert"
	default:
		return eventType
	}
}

// SelectEmittedTuplesBySource reads only the emitted-set rows of a binding written
// by ONE owner (source='binding' for Create + RoleTupleReconciler, source='member'
// for the γ reconciler). The Role.Update reconcile fan-out reads the 'binding'
// subset so its set-diff never sees — and so cannot revoke — the ARM_LABELS
// per-member tuples (CRITICAL ledger-source fix). The full symmetric revoke
// (delete.go) keeps using SelectEmittedTuples (the whole ledger). Zero rows ⇒ nil.
func (r *abReader) SelectEmittedTuplesBySource(ctx context.Context, bindingID domain.AccessBindingID, source string) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1 AND source = $2
		  ORDER BY relation, object, fga_user`, string(bindingID), source)
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// SelectEmittedTuples reads the persisted exact emitted-set of a binding
// (kacho_iam.access_binding_emitted_tuples). The revoke (delete.go)
// and the Role.Update reconcile fan-out use it as the source of truth for which
// FGA tuples were actually written, so the revoke is byte-symmetric to the grant
// regardless of the role's current permissions. Zero rows ⇒ empty slice (nil).
func (r *abReader) SelectEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]access_binding.RelationTuple, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT fga_user, relation, object
		   FROM access_binding_emitted_tuples
		  WHERE binding_id = $1
		  ORDER BY relation, object, fga_user`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []access_binding.RelationTuple
	for rows.Next() {
		var t access_binding.RelationTuple
		if err := rows.Scan(&t.User, &t.Relation, &t.Object); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// ListActiveByRole returns every non-revoked (PENDING/ACTIVE) binding of a role
// (Role.Update reconcile fan-out). The set is bounded by the active
// bindings of the SINGLE mutated role. Ordered (created_at, id) ASC for
// deterministic reconcile.
func (r *abReader) ListActiveByRole(ctx context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error) {
	rows, err := r.tx.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM access_bindings
		              WHERE role_id = $1 AND status <> 'REVOKED'
		              ORDER BY created_at ASC, id ASC`, abCols), string(roleID))
	if err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, err := scanAB(rows)
		if err != nil {
			return nil, mapErr(err, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(roleID))
	}
	return out, nil
}

// CountActiveByRole returns the count of non-revoked bindings of a role — the
// Role.Update fan-out bound-check (limit 10000). Cheap COUNT on role_id.
func (r *abReader) CountActiveByRole(ctx context.Context, roleID domain.RoleID) (int, error) {
	var n int
	if err := r.tx.QueryRow(ctx,
		`SELECT count(*) FROM access_bindings WHERE role_id = $1 AND status <> 'REVOKED'`,
		string(roleID)).Scan(&n); err != nil {
		return 0, mapErr(err, "", string(roleID))
	}
	return n, nil
}

// ─── multi-subject set + ListByRole ───

// ListByRole returns the bindings carrying roleID, keyset-paginated by
// (created_at, id) ASC. Mirrors the other List queries' pagination/scan/
// cursor semantics; the IncludeRevoked=false default hides REVOKED rows (a
// static predicate with no bind-arg, so this query is built inline rather than
// via listWithConds, which assumes one bind-arg per condition).
func (r *abReader) ListByRole(ctx context.Context, roleID domain.RoleID, f access_binding.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	pageSize := int64(f.PageSize)
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	conditions := []string{"role_id = $1"}
	args := []any{string(roleID)}
	argIdx := 2
	if !f.IncludeRevoked {
		conditions = append(conditions, "status <> 'REVOKED'")
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

	q := fmt.Sprintf(`SELECT %s FROM access_bindings WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		abCols, strings.Join(conditions, " AND "), argIdx)
	args = append(args, pageSize+1)

	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	defer rows.Close()
	var out []domain.AccessBinding
	for rows.Next() {
		ab, serr := scanAB(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", string(roleID))
		}
		out = append(out, ab)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", string(roleID))
	}
	var nextToken string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		nextToken = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, nextToken, nil
}

// ListSubjects returns the multi-subject set of ONE binding ordered by
// (ordinal, subject_type, subject_id). Zero rows ⇒ a
// pre-backfill legacy binding; the read-side falls back to the legacy single
// subject.
func (r *abReader) ListSubjects(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.Subject, error) {
	rows, err := r.tx.Query(ctx,
		`SELECT subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = $1
		  ORDER BY ordinal ASC, subject_type ASC, subject_id ASC`, string(bindingID))
	if err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	defer rows.Close()
	var out []domain.Subject
	for rows.Next() {
		var s domain.Subject
		if err := rows.Scan((*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", string(bindingID))
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(bindingID))
	}
	return out, nil
}

// ListSubjectsForBindings batch-loads the subjects of MANY bindings in one query
// (no per-row N+1). Bindings with no rows are absent from the map.
func (r *abReader) ListSubjectsForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	out := make(map[domain.AccessBindingID][]domain.Subject, len(bindingIDs))
	if len(bindingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(bindingIDs))
	for i, id := range bindingIDs {
		ids[i] = string(id)
	}
	rows, err := r.tx.Query(ctx,
		`SELECT binding_id, subject_type, subject_id FROM access_binding_subjects
		  WHERE binding_id = ANY($1)
		  ORDER BY binding_id ASC, ordinal ASC, subject_type ASC, subject_id ASC`, ids)
	if err != nil {
		return nil, mapErr(err, "", "")
	}
	defer rows.Close()
	for rows.Next() {
		var bid string
		var s domain.Subject
		if err := rows.Scan(&bid, (*string)(&s.Type), (*string)(&s.ID)); err != nil {
			return nil, mapErr(err, "", "")
		}
		key := domain.AccessBindingID(bid)
		out[key] = append(out[key], s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", "")
	}
	return out, nil
}

// InsertSubjects persists the multi-subject set of a binding. One row per
// subject, idempotent (ON CONFLICT DO NOTHING — re-insert is a no-op; the PK
// row-lock serializes concurrent identical inserts to exactly one row, ban #10).
// The ordinal preserves request order so subjects[0] (= the legacy single
// projection) is deterministic.
func (w *abWriter) InsertSubjects(ctx context.Context, bindingID domain.AccessBindingID, subjects []domain.Subject) error {
	if len(subjects) == 0 {
		return nil
	}
	for i, s := range subjects {
		if _, err := w.tx.Exec(ctx,
			`INSERT INTO access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING`,
			string(bindingID), string(s.Type), string(s.ID), i,
		); err != nil {
			return mapErr(err, "", string(bindingID))
		}
	}
	return nil
}

// DeleteSubject removes ONE subject's row (per-subject revoke) and reports
// whether a row was actually deleted (idempotent — a missing subject ⇒ false).
func (w *abWriter) DeleteSubject(ctx context.Context, bindingID domain.AccessBindingID, subject domain.Subject) (bool, error) {
	tag, err := w.tx.Exec(ctx,
		`DELETE FROM access_binding_subjects
		  WHERE binding_id = $1 AND subject_type = $2 AND subject_id = $3`,
		string(bindingID), string(subject.Type), string(subject.ID))
	if err != nil {
		return false, mapErr(err, "", string(bindingID))
	}
	return tag.RowsAffected() > 0, nil
}

// nullableString — пустую строку как NULL.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUserIDPtr — *UserID → string/nil для pgx (NULL когда указатель nil
// либо пустой).
func nullableUserIDPtr(u *domain.UserID) any {
	if u == nil || *u == "" {
		return nil
	}
	return string(*u)
}
