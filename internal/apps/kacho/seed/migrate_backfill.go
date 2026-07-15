// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// migrate_backfill.go — RBAC explicit-model migrate-step (part of
// expand→migrate→contract). The singleton single-shot backfill that
// re-materializes the explicit per-object FGA tuples for EVERY active binding
// BEFORE the contract step removes the FGA cascade.
//
// This step does NOT remove the FGA derivation cascade / scope_grant — that is
// the subsequent contract step (it removed the cascade + scope_grant + the dead
// org type). The backfill only ADDS the explicit materialization so no operator
// loses access in the contract window (no-access-loss).
//
// Two pieces:
//
//   BackfillOwnerBindings — the idempotent SQL data-migration body (mirror of
//     migration 0036) exposed so an account created AFTER goose.Up (which the
//     migration could not see) is still covered. Idempotent via the active-grant
//     partial-UNIQUE.
//
//   BackfillRunner.RunOnce — the reconcile-backfill SWEEP. Under a PROCESS-WIDE
//     singleton SESSION advisory lock (pg_advisory_lock — even at N replicas
//     exactly ONE process executes the sweep; the others skip), it lists every ACTIVE binding
//     in bounded CHUNKS (not one monster tx) and reconciles each through the
//     SAME single materialization path (the reconciler). Each binding reconcile
//     opens its OWN writer-tx and takes its OWN per-binding xact-lock, so the
//     materialization is idempotent and commutative with live forward-mat.
//
// Clean Architecture: the runner depends only on the ReconcileEngine surface +
// the narrow BackfillStore port (singleton-lock + chunked binding listing),
// implemented by the pg BackfillAdapter. No pgx here except the raw SQL helper
// BackfillOwnerBindings which is a composition-root data-migration utility.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ownerRoleIDExpr / the deterministic owner-binding-id expression mirror migration
// 0035 / 0036 so the SQL body here and the migration agree byte-for-byte.
const (
	// backfillOwnerBindingsSQL inserts an owner-binding for every account lacking an
	// ACTIVE owner-role binding (idempotent via NOT EXISTS + the active-grant
	// partial-UNIQUE).
	//
	// no-access-loss on re-grant after revoke: the id is a FRESH
	// NON-deterministic value, NOT the prior deterministic 'acb'||md5('owner-binding:'
	// ||a.id). A revoked owner-binding leaves a TOMBSTONE row carrying that deterministic
	// id (status=REVOKED, revoked_at set); the old `ON CONFLICT (id) DO NOTHING` then
	// silently DROPPED the needed re-grant (the PK collided with the tombstone) → the
	// account was left with NO active owner-binding. Keying off a fresh id makes the
	// re-grant a genuine new ACTIVE row; idempotency rests on the active-grant
	// partial-UNIQUE access_bindings_active_grant_uniq (WHERE revoked_at IS NULL) via
	// ON CONFLICT on that partial index — a revoked tombstone is NOT in it, so it never
	// suppresses a re-grant, while a concurrent double-insert of an ACTIVE grant is a
	// clean no-op (not a 23505 error). The id stays acb-prefixed (20 chars) so type
	// routing is unchanged.
	backfillOwnerBindingsSQL = `
INSERT INTO kacho_iam.access_bindings
  (id, subject_type, subject_id, role_id, resource_type, resource_id,
   status, granted_by_user_id, deletion_protection)
SELECT
  'acb' || substr(md5(a.id || '|owner-binding|' || clock_timestamp()::text || random()::text), 1, 17),
  'user',
  a.owner_user_id,
  'rol' || substr(md5('owner'), 1, 17),
  'account',
  a.id,
  'ACTIVE',
  'system',
  true
FROM kacho_iam.accounts a
WHERE NOT EXISTS (
  SELECT 1
    FROM kacho_iam.access_bindings b
   WHERE b.subject_type  = 'user'
     AND b.subject_id    = a.owner_user_id
     AND b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
     AND b.resource_type = 'account'
     AND b.resource_id   = a.id
     AND b.revoked_at IS NULL
)
ON CONFLICT (subject_id, subject_type, role_id, resource_type, resource_id)
  WHERE revoked_at IS NULL
  DO NOTHING`

	// backfillOwnerSubjectsSQL projects the single-subject row for every active
	// owner-binding (parity with migration 0028). Identical to migration 0036
	// statement (2).
	backfillOwnerSubjectsSQL = `
INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
SELECT b.id, b.subject_type, b.subject_id, 0
  FROM kacho_iam.access_bindings b
 WHERE b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
   AND b.resource_type = 'account'
   AND b.revoked_at IS NULL
ON CONFLICT (binding_id, subject_type, subject_id) DO NOTHING`

	// backfillOwnerHierarchyTuplesSQL emits the owner-binding OBJECT hierarchy
	// parent-pointer FGA tuple (account:<A>#account@iam_access_binding:<id>) for every
	// active owner-binding (no-access-loss). This boot-path is the SOLE home
	// for the hierarchy-pointer INTENT for EXISTING owner-bindings — migration 0037 was
	// reduced to a no-op precisely because a goose data-migration must not enqueue an
	// fga_outbox row (it pollutes every outbox-counting test/tool). The pointer is the
	// binding-lifecycle tuple the reconcile-sweep does NOT materialize; without it the
	// account owner has no viewer/editor path to its own owner-binding object and
	// Get/Delete authz-DENY. Idempotent via the NOT EXISTS payload de-dupe; the
	// fga_outbox drainer is at-least-once + idempotent at OpenFGA. It also covers
	// accounts created AFTER goose.Up, which a migration can never see.
	backfillOwnerHierarchyTuplesSQL = `
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     'account:' || b.resource_id,
    'relation', 'account',
    'object',   'iam_access_binding:' || b.id
  ),
  now()
FROM kacho_iam.access_bindings b
WHERE b.role_id       = 'rol' || substr(md5('owner'), 1, 17)
  AND b.resource_type = 'account'
  AND b.revoked_at IS NULL
  AND NOT EXISTS (
    SELECT 1
      FROM kacho_iam.fga_outbox o
     WHERE o.event_type        = 'fga.tuple.write'
       AND o.payload->>'user'     = 'account:' || b.resource_id
       AND o.payload->>'relation' = 'account'
       AND o.payload->>'object'   = 'iam_access_binding:' || b.id
  )`
)

// BackfillOwnerBindings runs the idempotent owner-binding data-backfill on the pool,
// in ONE short tx: (1) the owner-binding row + (2) its projected subject row (the
// migration 0036 body, mirrored here so a post-goose.Up account is covered), and
// (3) the owner-binding OBJECT hierarchy parent-pointer fga_outbox intent
// (no-access-loss) — the latter lives ONLY here, NOT in a migration, so the
// outbox carries no migration side-effect (migration 0037 is a no-op). All three are
// lightweight one-row-per-account inserts — the per-object CONTENT tuples remain the
// reconcile-sweep's chunked concern. Safe to re-run: the active-grant partial-UNIQUE
// + the NOT EXISTS guards make it a no-op once every account has an owner-binding and
// its hierarchy pointer is queued/applied.
func BackfillOwnerBindings(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("backfill owner-bindings: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, backfillOwnerBindingsSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: insert bindings: %w", err)
	}
	if _, err := tx.Exec(ctx, backfillOwnerSubjectsSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: insert subjects: %w", err)
	}
	if _, err := tx.Exec(ctx, backfillOwnerHierarchyTuplesSQL); err != nil {
		return fmt.Errorf("backfill owner-bindings: emit hierarchy tuples: %w", err)
	}
	if err := syncOwnerRoleSelectorsTx(ctx, tx); err != nil {
		return fmt.Errorf("backfill owner-bindings: sync owner role selectors: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("backfill owner-bindings: commit: %w", err)
	}
	committed = true
	return nil
}

// syncOwnerRoleSelectorsTx UPSERTs the owner system-role's UNIFIED materializing
// selector into role_rule_selectors (forward fast-path). The owner role is seeded
// by raw SQL (migration 0035), so — unlike a custom role written via Role.Create —
// its role_rule_selectors row is NOT populated by ReplaceRuleSelectors.
// Without this row the forward path (SelectorBindingsMatchingObject, driven by
// RegisterResource → ReconcileObject) never matches an owner binding for a brand-new
// object, so owner-content-forward would only converge on the periodic sweep.
// This seeds the anchor selector — the wildcard `*.*` rule expanded to the full
// materializable type set (domain.MaterializingSelectors) — so a freshly-registered
// object materializes the owner's content tuple on its change event (≤2s). Idempotent:
// ON CONFLICT (role_id, rule_fp) re-applies the same row.
func syncOwnerRoleSelectorsTx(ctx context.Context, tx pgxExecer) error {
	for _, sel := range domain.OwnerRoleRules().MaterializingSelectors() {
		if len(sel.ObjectTypes) == 0 {
			// Defensive: a GLOBAL-only projection would be empty; the owner is bounded,
			// so MaterializingSelectors (role-level, wildcard-expanding) yields the full
			// type set. Skip an empty selector — role_rule_selectors_types_nonempty
			// CHECK forbids a 0-type row.
			continue
		}
		armTextOwner := ownerArmText(sel.Arm)
		if _, err := tx.Exec(ctx,
			`INSERT INTO kacho_iam.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, resource_names, match_labels, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, '{}'::text[], '{}'::jsonb, now(), now())
			 ON CONFLICT (role_id, rule_fp) DO UPDATE
			    SET arm            = EXCLUDED.arm,
			        object_types   = EXCLUDED.object_types,
			        resource_names = EXCLUDED.resource_names,
			        match_labels   = EXCLUDED.match_labels,
			        updated_at     = now()`,
			domain.OwnerRoleID, sel.RuleFP, armTextOwner, sel.ObjectTypes); err != nil {
			return fmt.Errorf("upsert owner role selector %s: %w", sel.RuleFP, err)
		}
	}
	return nil
}

// ownerArmText maps the owner selector arm to the role_rule_selectors.arm enum text.
// The owner `*.*` rule is ARM_ANCHOR; the names/labels cases are defensive parity.
func ownerArmText(a domain.Arm) string {
	switch a {
	case domain.ArmNames:
		return "names"
	case domain.ArmLabels:
		return "labels"
	default:
		return "anchor"
	}
}

// pgxExecer is the minimal Exec surface (pgx.Tx / pgxpool.Pool both satisfy it) the
// owner-selector sync needs — keeps the helper tx/pool-agnostic.
type pgxExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// BackfillReconcileEngine — the reconcile surface the sweep drives (one binding at
// a time; the reconciler opens its own writer-tx + per-binding xact-lock).
type BackfillReconcileEngine interface {
	ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error
}

// BackfillStore — the narrow port the runner needs: the process-wide singleton
// try-lock + chunked listing of all active binding ids. Implemented by the pg
// BackfillAdapter.
type BackfillStore interface {
	// TryAcquireSingletonBackfillLock takes a SESSION-scoped pg_advisory_lock on a
	// well-known key with the NON-blocking try variant. ok=false ⇒ another process
	// already holds it ⇒ this RunOnce skips (exactly one executor). The release
	// closure MUST be called to free the session lock after the sweep.
	TryAcquireSingletonBackfillLock(ctx context.Context) (ok bool, release func(context.Context), err error)

	// ListActiveBindingIDsChunk returns up to `limit` ACTIVE binding ids whose id is
	// strictly greater than `afterID` (keyset pagination, ORDER BY id ASC). An empty
	// result ⇒ the sweep is done. Pool-scoped read OUTSIDE the per-binding reconcile
	// tx (each binding reconciles in its own tx).
	ListActiveBindingIDsChunk(ctx context.Context, afterID string, limit int) ([]domain.AccessBindingID, error)
}

// BackfillConfig — runner tunables.
type BackfillConfig struct {
	// ChunkSize bounds the listing batch. Defaults to 500 when ≤0.
	ChunkSize int
	// Logger — optional; slog.Default() when nil.
	Logger *slog.Logger
}

// BackfillResult — sweep outcome (observability / verify-gate / tests).
type BackfillResult struct {
	// Executed reports whether THIS RunOnce acquired the singleton lock and ran the
	// sweep (false ⇒ another process was the executor).
	Executed bool
	// BindingsReconciled — count of bindings reconciled (Executed=true only).
	BindingsReconciled int
	// Chunks — number of listing batches consumed (Executed=true only).
	Chunks int
}

// BackfillRunner — the singleton single-shot reconcile-backfill sweep.
type BackfillRunner struct {
	engine    BackfillReconcileEngine
	store     BackfillStore
	chunkSize int
	logger    *slog.Logger
}

// NewBackfillRunner constructs the runner.
func NewBackfillRunner(engine BackfillReconcileEngine, store BackfillStore, cfg BackfillConfig) *BackfillRunner {
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 500
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BackfillRunner{engine: engine, store: store, chunkSize: chunk, logger: logger}
}

// RunOnce executes the reconcile-backfill sweep exactly once across the cluster.
//
// It first tries the PROCESS-WIDE singleton advisory lock (non-blocking). If
// another process holds it, RunOnce returns Executed=false immediately — no
// double-sweep. Otherwise it holds the lock for the whole sweep and releases it at
// the end.
//
// It walks every ACTIVE binding in keyset-paginated CHUNKS, reconciling each
// binding in its OWN writer-tx (the engine opens it) — never tens of thousands of
// INSERTs in one tx.
//
// The reconcile diff is idempotent and commutative with live
// forward-materialization (the ledger partial-UNIQUE backstops a racing
// forward-emit), so re-running RunOnce makes no further changes.
func (r *BackfillRunner) RunOnce(ctx context.Context) (BackfillResult, error) {
	ok, release, err := r.store.TryAcquireSingletonBackfillLock(ctx)
	if err != nil {
		return BackfillResult{}, fmt.Errorf("backfill: acquire singleton lock: %w", err)
	}
	if !ok {
		r.logger.InfoContext(ctx, "backfill: singleton lock held by another process — skipping")
		return BackfillResult{Executed: false}, nil
	}
	defer release(ctx)

	res := BackfillResult{Executed: true}
	afterID := ""
	for {
		chunk, lerr := r.store.ListActiveBindingIDsChunk(ctx, afterID, r.chunkSize)
		if lerr != nil {
			return res, fmt.Errorf("backfill: list active bindings (after %q): %w", afterID, lerr)
		}
		if len(chunk) == 0 {
			break
		}
		res.Chunks++
		for _, bID := range chunk {
			if rerr := r.engine.ReconcileBinding(ctx, bID); rerr != nil {
				return res, fmt.Errorf("backfill: reconcile binding %s: %w", bID, rerr)
			}
			res.BindingsReconciled++
			afterID = string(bID)
		}
		// A short chunk means we've reached the end (no need for an extra empty query).
		if len(chunk) < r.chunkSize {
			break
		}
	}
	r.logger.InfoContext(ctx, "backfill: reconcile-sweep complete",
		slog.Int("bindings_reconciled", res.BindingsReconciled),
		slog.Int("chunks", res.Chunks))
	return res, nil
}
