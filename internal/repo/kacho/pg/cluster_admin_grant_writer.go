// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cluster_admin_grant_writer.go — atomic-CAS Writer for cluster admin
// Grant/Revoke RPCs.
//
// Distinct from the existing `ClusterAdminGrantRepo` (iam_core_repos.go),
// which serves BG.ApproveB with `granted_until` set (time-bombed grants).
// This Writer covers the new InternalClusterService.{GrantAdmin,RevokeAdmin}
// path with `granted_until = NULL` (permanent) + sentinel-based guards.
//
// All within-DB invariants are enforced at the SQL layer (ban #10):
//
//   - Idempotent Grant — ON CONFLICT ON CONSTRAINT
//     `cluster_admin_grants_cluster_subject_uniq` DO NOTHING; loser returns
//     existing row via diagnostic SELECT.
//   - Self-revoke guard — CAS WHERE `subject_id != $principal`.
//   - Last-admin guard — CAS WHERE
//     `(SELECT count(*) FROM cluster_admin_grants WHERE granted_until IS NULL) > 1`,
//     serialized cluster-wide by a tx-scoped advisory lock (see
//     `revokeSerializeLockKey`) so the count(*) cannot be evaluated on a stale
//     snapshot vs a concurrent revoke of a DISTINCT admin (write-skew).
//   - Revoke NOT idempotent — CAS WHERE `granted_until IS NULL`;
//     0 rows + history row OR no row → ErrNotFound.
package pg

import (
	"context"
	stderrors "errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ClusterAdminGrantWriter — write-side adapter for grant/revoke RPCs.
// Uses caller-supplied tx (service.Tx, recovered via txAsPgx) — never opens
// its own transaction. Composition root wires together (Writer.Grant +
// FGAOutboxEmitter.EmitWriteTx + AuditOutbox.Emit) inside a single
// service.Transactor.WithinTx block.
type ClusterAdminGrantWriter struct {
	pool *pgxpool.Pool
}

// NewClusterAdminGrantWriter — composition root constructor. The pool is
// accepted for parity with other adapters (and for the diagnostic SELECTs
// inside Revoke that don't need the writer's tx).
func NewClusterAdminGrantWriter(pool *pgxpool.Pool) *ClusterAdminGrantWriter {
	return &ClusterAdminGrantWriter{pool: pool}
}

// revokeSerializeLockKey — advisory-lock key that serializes ALL cluster-admin
// revokes cluster-wide.
//
// The last-admin guard is a `count(*)` over sibling rows. Under READ COMMITTED
// two concurrent revokes of DISTINCT admins each take a row-lock on their OWN
// target row only — no lock on the sibling being revoked concurrently — so both
// evaluate the count against a snapshot in which the other's revoke is still
// uncommitted: both read count=2, both pass the `> 1` guard, both commit → zero
// admins (write-skew, ban #10). A tx-scoped advisory lock forces revokes to run
// one-at-a-time: the second revoke blocks until the first COMMITs, then re-reads
// count=1 and is denied (ErrLastAdmin). Grants take no such lock — adding an
// admin can never violate the "at least one admin" invariant.
const revokeSerializeLockKey = "iam:cluster-admin-revoke:" + domain.ClusterSingletonID

// Grant — INSERT a new permanent (`granted_until = NULL`) cluster_admin_grants
// row, idempotent on (cluster_id, subject_id) UNIQUE conflict.
//
// Returns:
//   - grant: the row (fresh or pre-existing)
//   - created: true on a fresh INSERT (RowsAffected==1), false on conflict.
//
// On conflict, the existing row is fetched via a diagnostic SELECT inside
// the same tx — caller sees the actual row state (including `granted_until`
// for re-grant-after-revoke cases; the use-case interprets).
//
// SQL contract:
//
//	INSERT … ON CONFLICT ON CONSTRAINT cluster_admin_grants_cluster_subject_uniq
//	DO NOTHING — suppresses both the total UNIQUE (cluster_id, subject_id)
//	AND the partial UNIQUE (subject_type, subject_id WHERE granted_until IS NULL)
//	conflicts. The total UNIQUE always covers the partial UNIQUE's predicate
//	space, so naming it on ON CONFLICT is sufficient.
func (w *ClusterAdminGrantWriter) Grant(
	ctx context.Context, txh service.Tx,
	subject domain.SubjectID, grantedBy string,
) (domain.ClusterAdminGrant, bool, error) {
	tx := txAsPgx(txh)

	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	tag, err := tx.Exec(ctx, `
		INSERT INTO kacho_iam.cluster_admin_grants
		    (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		VALUES ($1, $2, 'user', $3, $4, now(), NULL)
		ON CONFLICT ON CONSTRAINT cluster_admin_grants_cluster_subject_uniq
		DO NOTHING`,
		id, domain.ClusterSingletonID, string(subject), grantedBy)
	if err != nil {
		return domain.ClusterAdminGrant{}, false, fmt.Errorf("cluster_admin_grants insert: %w", err)
	}

	if tag.RowsAffected() == 1 {
		// Fresh INSERT — read back the row we just wrote (in same tx) so the
		// caller sees the server-set granted_at.
		existing, gerr := getCAGBySubjectTx(ctx, tx, subject)
		if gerr != nil {
			return domain.ClusterAdminGrant{}, false, fmt.Errorf("cluster_admin_grants read-after-insert: %w", gerr)
		}
		return existing, true, nil
	}

	// Conflict — fetch the row that already existed (active OR revoked
	// history; caller interprets).
	existing, gerr := getCAGBySubjectTx(ctx, tx, subject)
	if gerr != nil {
		return domain.ClusterAdminGrant{}, false, fmt.Errorf("cluster_admin_grants read-existing: %w", gerr)
	}
	return existing, false, nil
}

// Revoke — atomically mark the active grant for `subject` as revoked
// (`granted_until = now()`) under three runtime guards:
//
//  1. subject_id != principalID  — self-revoke forbidden.
//  2. (SELECT count(*) WHERE granted_until IS NULL) > 1 — last-admin guard.
//  3. granted_until IS NULL — only active rows are revocable.
//
// Single-statement UPDATE with all 3 guards in WHERE: atomic vs concurrent
// revoke (ban #10). 0 rows ⇒ diagnostic SELECTs determine
// which guard fired and return the appropriate sentinel.
//
// A tx-scoped advisory lock is taken FIRST (before the guarded UPDATE) so the
// last-admin `count(*)` guard cannot be defeated by a concurrent revoke of a
// DISTINCT admin (write-skew — see revokeSerializeLockKey). The lock
// auto-releases at COMMIT/ROLLBACK.
func (w *ClusterAdminGrantWriter) Revoke(
	ctx context.Context, txh service.Tx,
	subject domain.SubjectID, principalID string,
) (domain.ClusterAdminGrant, error) {
	tx := txAsPgx(txh)

	// Serialize concurrent revokes cluster-wide (write-skew guard). Passed as a
	// bind parameter (hashtext → int lock key) — no identifier splicing.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`, revokeSerializeLockKey); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("cluster_admin_grants revoke advisory lock: %w", err)
	}

	const q = `
		UPDATE kacho_iam.cluster_admin_grants
		   SET granted_until = now()
		 WHERE subject_type = 'user'
		   AND subject_id   = $1
		   AND granted_until IS NULL
		   AND subject_id  != $2  -- D-5 self-revoke guard
		   AND (SELECT count(*)
		          FROM kacho_iam.cluster_admin_grants
		         WHERE granted_until IS NULL) > 1  -- D-6 last-admin guard
		RETURNING id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until`
	row := tx.QueryRow(ctx, q, string(subject), principalID)
	out, err := scanCAG(row)
	if err == nil {
		return out, nil
	}
	if !stderrors.Is(err, pgx.ErrNoRows) {
		// pgxpool / network / SQLSTATE error — surface as-is for caller maperr.
		return domain.ClusterAdminGrant{}, fmt.Errorf("cluster_admin_grants update: %w", err)
	}

	// 0 rows updated — diagnose which guard fired (in same tx to see the
	// authoritative state).
	return domain.ClusterAdminGrant{}, diagnoseRevokeMiss(ctx, tx, subject, principalID)
}

// diagnoseRevokeMiss — runs the same checks as the CAS WHERE clause, in
// order matching error semantic precedence:
//
//  1. self-revoke         → ErrSelfRevoke
//  2. not-admin / history → ErrNotFound
//  3. last-admin          → ErrLastAdmin
//
// Order matters: a caller revoking SELF when they are the last admin should
// see "cannot revoke own cluster admin grant" (the self-protection message
// is more actionable than the last-admin message).
func diagnoseRevokeMiss(ctx context.Context, tx pgx.Tx, subject domain.SubjectID, principalID string) error {
	// 1. self-revoke?
	if string(subject) == principalID {
		return iamerr.Wrapf(iamerr.ErrSelfRevoke, "cannot revoke own cluster admin grant")
	}

	// 2. Does an active row exist for the subject at all?
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants
		   WHERE subject_type = 'user' AND subject_id = $1 AND granted_until IS NULL`,
		string(subject)).Scan(&n); err != nil {
		return fmt.Errorf("cluster_admin_grants diag-active: %w", err)
	}
	if n == 0 {
		return iamerr.Wrapf(iamerr.ErrNotFound, "User %s is not an active cluster admin", subject)
	}

	// 3. Active row exists but count overall is 1 ⇒ last-admin.
	var total int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants WHERE granted_until IS NULL`).
		Scan(&total); err != nil {
		return fmt.Errorf("cluster_admin_grants diag-total: %w", err)
	}
	if total == 1 {
		return iamerr.Wrapf(iamerr.ErrLastAdmin, "cannot revoke last active cluster admin")
	}

	// Shouldn't reach here — UPDATE with the 3 guards should have matched.
	// Fail loudly so wiring bugs surface in tests.
	return iamerr.Wrapf(iamerr.ErrInternal,
		"cluster_admin_grants Revoke: 0 rows but no guard explained it (subject=%s, principal=%s, total=%d)",
		subject, principalID, total)
}

// getCAGBySubjectTx — read the active OR most-recently-touched row for the
// given subject. Returns `pgx.ErrNoRows` if no row at all (then caller wraps).
//
// "Active OR most-recent": after a successful Grant (active row), reads the
// active row; after a Grant idempotent-conflict with revoked history, reads
// the revoked row (caller sees !IsActive). LIMIT 1 + ORDER BY granted_at DESC
// gives deterministic single-row result.
func getCAGBySubjectTx(ctx context.Context, tx pgx.Tx, subject domain.SubjectID) (domain.ClusterAdminGrant, error) {
	row := tx.QueryRow(ctx, `
		SELECT id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until
		  FROM kacho_iam.cluster_admin_grants
		 WHERE subject_type = 'user' AND subject_id = $1
		 ORDER BY (granted_until IS NULL) DESC, granted_at DESC
		 LIMIT 1`, string(subject))
	return scanCAG(row)
}

// Reactivate — re-activates a previously-revoked grant for `subject` by
// setting `granted_until = NULL` and updating `granted_by`/`granted_at` to
// reflect the new grantor.
//
// Called when Grant (D-4) finds an existing row that is NOT active
// (`granted_until IS NOT NULL`) — the schema has a TOTAL UNIQUE on
// (cluster_id, subject_id), so a new INSERT would conflict; Reactivate
// updates the existing row in place instead.
//
// CAS guard: WHERE `granted_until IS NOT NULL` — prevents accidental
// overwrite of an already-active row (race between two concurrent re-grants).
// 0 rows from RETURNING means a concurrent winner already re-activated —
// caller reads the now-active row via getCAGBySubjectTx and returns it as
// `created=false` (idempotent).
func (w *ClusterAdminGrantWriter) Reactivate(
	ctx context.Context, txh service.Tx,
	subject domain.SubjectID, grantedBy string,
) (domain.ClusterAdminGrant, error) {
	tx := txAsPgx(txh)
	const q = `
		UPDATE kacho_iam.cluster_admin_grants
		   SET granted_until = NULL,
		       granted_by    = $2,
		       granted_at    = now()
		 WHERE subject_type = 'user'
		   AND subject_id   = $1
		   AND granted_until IS NOT NULL   -- CAS: only revoked rows
		RETURNING id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until`
	row := tx.QueryRow(ctx, q, string(subject), grantedBy)
	out, err := scanCAG(row)
	if err == nil {
		return out, nil
	}
	if !stderrors.Is(err, pgx.ErrNoRows) {
		return domain.ClusterAdminGrant{}, fmt.Errorf("cluster_admin_grants reactivate: %w", err)
	}
	// 0 rows — concurrent winner already reactivated; read back the active row.
	existing, gerr := getCAGBySubjectTx(ctx, tx, subject)
	if gerr != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("cluster_admin_grants reactivate read-back: %w", gerr)
	}
	return existing, nil
}

// (scanCAG lives in iam_core_repos.go and is shared between repos.)
