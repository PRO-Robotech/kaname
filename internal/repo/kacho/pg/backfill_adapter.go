// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// backfill_adapter.go — pgx adapter for the
// seed.BackfillStore + seed.VerifyStore ports (Clean Architecture: the backfill
// runner + verify-gate use-cases depend only on those ports; this is the only place
// that touches pgx for them).
//
// The backfill sweep (seed.BackfillRunner) lists active bindings in chunks and
// reconciles each through the EXISTING reconcile use-case (its own writer-tx +
// per-binding advisory lock) — so this adapter holds NO reconcile SQL; it owns only
// the singleton-lock + chunked listing + the verify-gate reads/forward-smoke seed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// backfillSingletonLockKey — the well-known advisory-lock key for the backfill
// singleton. A fixed bigint distinct from any per-binding hashtext key. The
// number is arbitrary-but-stable ("P8BF" mnemonic) and documented here so a future
// advisory-lock user does not collide.
const backfillSingletonLockKey int64 = 0x50_38_42_46 // "P8BF"

// BackfillAdapter — composition-root adapter for the backfill + verify-gate.
type BackfillAdapter struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewBackfillAdapter constructs the adapter over a pool. The logger is nil-safe
// (falls back to slog.Default) and is used to surface a singleton-lock release
// failure rather than swallowing it.
func NewBackfillAdapter(pool *pgxpool.Pool) *BackfillAdapter {
	return &BackfillAdapter{pool: pool, logger: slog.Default()}
}

var (
	_ seed.BackfillStore = (*BackfillAdapter)(nil)
	_ seed.VerifyStore   = (*BackfillAdapter)(nil)
)

// ── seed.BackfillStore ──────────────────────────────────────────────────────────

// TryAcquireSingletonBackfillLock takes a SESSION-scoped pg_try_advisory_lock on
// the well-known key (non-blocking). It dedicates ONE pool connection for the
// whole sweep so the session lock outlives individual statements; the release
// closure unlocks and returns the connection to the pool. ok=false ⇒ another
// process holds the lock ⇒ the caller skips the sweep.
func (a *BackfillAdapter) TryAcquireSingletonBackfillLock(ctx context.Context) (bool, func(context.Context), error) {
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("backfill: acquire conn for singleton lock: %w", err)
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, backfillSingletonLockKey).Scan(&ok); err != nil {
		conn.Release()
		return false, nil, fmt.Errorf("backfill: pg_try_advisory_lock: %w", err)
	}
	if !ok {
		conn.Release()
		return false, nil, nil
	}
	release := func(rctx context.Context) {
		// Unlock on the SAME session that took the lock, then return the conn.
		// Detach from the caller's (possibly-cancelled) ctx: a cancelled rctx would
		// make conn.Exec a no-op and leak the session lock until the conn is recycled.
		// WithoutCancel keeps any deadline/values but drops cancellation so the unlock
		// always runs. A failed unlock is logged (defense-in-depth observability) —
		// the session lock is still released when the conn is closed/recycled, but a
		// silent failure would hide a real DB problem.
		uctx := context.WithoutCancel(rctx)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, backfillSingletonLockKey); err != nil {
			a.logger.WarnContext(uctx, "backfill: singleton advisory-unlock failed (released on conn recycle)",
				slog.Any("err", err))
		}
		conn.Release()
	}
	return true, release, nil
}

// ListActiveBindingIDsChunk returns up to `limit` ACTIVE binding ids with id >
// afterID (keyset pagination, ORDER BY id ASC). Pool-scoped read OUTSIDE the
// per-binding reconcile tx (each binding reconciles in its own tx).
func (a *BackfillAdapter) ListActiveBindingIDsChunk(ctx context.Context, afterID string, limit int) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT id
		   FROM kacho_iam.access_bindings
		  WHERE status = 'ACTIVE' AND id > $1
		  ORDER BY id ASC
		  LIMIT $2`,
		afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding ids chunk: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("backfill: scan active binding id: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// ── seed.VerifyStore ────────────────────────────────────────────────────────────

// ListActiveBindingMaterialization returns, for every ACTIVE binding, whether it
// EXPECTS explicit materialization and its current ledger-tuple count. The
// expectation is the reconciler's OWN verdict — the count of ACTIVE
// access_binding_target_members the last reconcile pass produced — NOT a heuristic
// over the role rules. This is exact: a binding the reconciler decided to
// materialize (a contained selector member, or the account/project scope-self
// member) has ≥1 ACTIVE member; a binding the reconciler leaves empty (a
// cluster-scoped `*.*.*` super-admin served by the short-circuit, a wildcard
// content rule whose ObjectTypes are skipped, a selector matching nothing in the
// mirror) has 0 ACTIVE members → it expects nothing and an empty ledger is correct.
// The no-access-loss failure (Verify) is exactly "ACTIVE members exist but the
// ledger is empty" — a member the reconciler activated without emitting its tuple.
func (a *BackfillAdapter) ListActiveBindingMaterialization(ctx context.Context) ([]seed.BindingMaterialization, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT b.id,
		        COALESCE(am.cnt, 0) AS active_members,
		        COALESCE(lt.cnt, 0) AS ledger_count
		   FROM kacho_iam.access_bindings b
		   LEFT JOIN (
		        SELECT binding_id, count(*) AS cnt
		          FROM kacho_iam.access_binding_target_members
		         WHERE verification_status = 'ACTIVE'
		         GROUP BY binding_id
		   ) am ON am.binding_id = b.id
		   LEFT JOIN (
		        SELECT binding_id, count(*) AS cnt
		          FROM kacho_iam.access_binding_emitted_tuples
		         GROUP BY binding_id
		   ) lt ON lt.binding_id = b.id
		  WHERE b.status = 'ACTIVE'`)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding materialization: %w", err)
	}
	defer rows.Close()

	var out []seed.BindingMaterialization
	for rows.Next() {
		var (
			id            string
			activeMembers int
			ledgerCount   int
		)
		if err := rows.Scan(&id, &activeMembers, &ledgerCount); err != nil {
			return nil, fmt.Errorf("backfill: scan binding materialization: %w", err)
		}
		out = append(out, seed.BindingMaterialization{
			BindingID:     domain.AccessBindingID(id),
			ExpectsTuples: activeMembers > 0,
			LedgerCount:   ledgerCount,
		})
	}
	return out, rows.Err()
}

// ListOwnerBindingsMissingMembers returns the ids of ACTIVE account-scoped OWNER
// bindings (role_id = the owner system-role) that have ZERO ACTIVE target members.
// An owner-binding ALWAYS materializes ≥1 member (its scope-self
// member on account:<A>), so an owner-binding with 0 ACTIVE members is a wholesale
// reconcile failure — flagged by the verify-gate. Restricted to owner bindings so the
// check never false-flags a legitimately-empty binding (a cluster super-admin served by
// the short-circuit, a thin permissions-only role, a selector matching nothing).
func (a *BackfillAdapter) ListOwnerBindingsMissingMembers(ctx context.Context) ([]domain.AccessBindingID, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT b.id
		   FROM kacho_iam.access_bindings b
		  WHERE b.status = 'ACTIVE'
		    AND b.role_id = $1
		    AND b.resource_type = 'account'
		    AND NOT EXISTS (
		      SELECT 1
		        FROM kacho_iam.access_binding_target_members m
		       WHERE m.binding_id = b.id
		         AND m.verification_status = 'ACTIVE'
		    )
		  ORDER BY b.id ASC`,
		domain.OwnerRoleID)
	if err != nil {
		return nil, fmt.Errorf("backfill: list owner bindings missing members: %w", err)
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("backfill: scan owner binding missing members: %w", err)
		}
		out = append(out, domain.AccessBindingID(id))
	}
	return out, rows.Err()
}

// SeedSmokeMirrorObject creates a synthetic resource_mirror row (project/account
// parented + labels) for the forward-smoke (verify-gate). A now() source_version
// wins any monotonic-version guard.
func (a *BackfillAdapter) SeedSmokeMirrorObject(ctx context.Context, objectType, objectID, parentProject, parentAccount string, labels map[string]string) error {
	labelsJSON, err := json.Marshal(labels)
	if err != nil {
		return fmt.Errorf("backfill: marshal smoke labels: %w", err)
	}
	if len(labels) == 0 {
		labelsJSON = []byte("{}")
	}
	if _, err := a.pool.Exec(ctx,
		`INSERT INTO kacho_iam.resource_mirror
		   (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
		 VALUES ($1, $2, $3, $4, $5::jsonb, now(), now())
		 ON CONFLICT (object_type, object_id) DO UPDATE
		    SET parent_project_id = EXCLUDED.parent_project_id,
		        parent_account_id = EXCLUDED.parent_account_id,
		        labels            = EXCLUDED.labels,
		        source_version    = now(),
		        updated_at        = now()`,
		objectType, objectID, parentProject, parentAccount, string(labelsJSON)); err != nil {
		return fmt.Errorf("backfill: seed smoke mirror object %s:%s: %w", objectType, objectID, err)
	}
	return nil
}

// RemoveSmokeMirrorObject removes the synthetic forward-smoke mirror row.
func (a *BackfillAdapter) RemoveSmokeMirrorObject(ctx context.Context, objectType, objectID string) error {
	_, err := a.pool.Exec(ctx,
		`DELETE FROM kacho_iam.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		objectType, objectID)
	if err != nil {
		return fmt.Errorf("backfill: remove smoke mirror object %s:%s: %w", objectType, objectID, err)
	}
	return nil
}

// SmokeOwnerBindingCandidate returns ONE ACTIVE account-scoped OWNER binding and its
// account id, to drive the boot forward-smoke. The owner (`*.*`) role
// bound at ACCOUNT scope is the bounded-scope owner-content path: a fresh resource in
// the account forward-materializes the owner's per-object content tuple.
// Deterministic (ORDER BY id) so the smoke is stable across boots. ok=false when no
// owner-binding exists yet (brand-new cluster) → the caller skips the smoke.
func (a *BackfillAdapter) SmokeOwnerBindingCandidate(ctx context.Context) (domain.AccessBindingID, string, bool, error) {
	var (
		bindingID string
		accountID string
	)
	err := a.pool.QueryRow(ctx,
		`SELECT id, resource_id
		   FROM kacho_iam.access_bindings
		  WHERE status = 'ACTIVE'
		    AND role_id = $1
		    AND resource_type = 'account'
		  ORDER BY id ASC
		  LIMIT 1`,
		domain.OwnerRoleID).Scan(&bindingID, &accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("backfill: smoke owner-binding candidate: %w", err)
	}
	return domain.AccessBindingID(bindingID), accountID, true, nil
}

// ListActiveBindingRelationChecks returns, for every ACTIVE binding, the per-object
// v_* read-enforcement tuples (v_get / v_list) the relation-satisfies-action gate
// must Check against real FGA. These are the cutover-critical relations: the
// catalog gates `<domain>.<res>.get`→v_get and `…list`→v_list under Design-B, so the
// gate proves each materialized read tuple actually RESOLVES the enforced relation —
// not merely that the ledger is non-empty. Restricted to v_get/v_list (the read
// surface the cutover flips) so the gate's FGA Check fan-out is bounded to the
// relations whose mis-materialization caused the live owner-403 bug. Pool-scoped
// read OUTSIDE any reconcile tx.
func (a *BackfillAdapter) ListActiveBindingRelationChecks(ctx context.Context) ([]seed.BindingRelationCheck, error) {
	rows, err := a.pool.Query(ctx,
		`SELECT t.binding_id, t.fga_user, t.relation, t.object
		   FROM kacho_iam.access_binding_emitted_tuples t
		   JOIN kacho_iam.access_bindings b ON b.id = t.binding_id
		  WHERE b.status = 'ACTIVE'
		    AND t.relation IN ('v_get', 'v_list')
		  ORDER BY t.binding_id ASC, t.object ASC, t.relation ASC`)
	if err != nil {
		return nil, fmt.Errorf("backfill: list active binding relation checks: %w", err)
	}
	defer rows.Close()
	var out []seed.BindingRelationCheck
	for rows.Next() {
		var c seed.BindingRelationCheck
		var bindingID string
		if err := rows.Scan(&bindingID, &c.Subject, &c.Relation, &c.Object); err != nil {
			return nil, fmt.Errorf("backfill: scan binding relation check: %w", err)
		}
		c.BindingID = domain.AccessBindingID(bindingID)
		out = append(out, c)
	}
	return out, rows.Err()
}

// LedgerHasObject reports whether the binding's ledger records ANY tuple on the
// given fga-object (forward-smoke success check).
func (a *BackfillAdapter) LedgerHasObject(ctx context.Context, bindingID domain.AccessBindingID, fgaObject string) (bool, error) {
	var n int
	if err := a.pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND object = $2`,
		string(bindingID), fgaObject).Scan(&n); err != nil {
		return false, fmt.Errorf("backfill: ledger has object %s for binding %s: %w", fgaObject, bindingID, err)
	}
	return n > 0, nil
}
