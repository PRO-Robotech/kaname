// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// recovery_completions_integration_test.go — testcontainers integration tests
// for InternalUserService.OnRecoveryCompleted, driven through the use-case
// (operations LRO) against a real Postgres.
//
// Scenario trace:
//   - TestOnRecoveryCompleted_S01_Blocked_ReEnable_Revoke_Audit_Idempotent
//   - TestOnRecoveryCompleted_S02_Active_NoopReEnable_Revoke_Audit
//   - TestOnRecoveryCompleted_S03_UnknownExternalID_NotFound_NoSideEffects
//   - TestOnRecoveryCompleted_S04_EmailMismatch_FailedPrecondition_NoSideEffects
//   - TestOnRecoveryCompleted_S05_DuplicateJTI_IdempotentNoop (concurrent goroutines)
//   - sync-validation → covered by use-case unit tests (internal_on_recovery_test.go)
//   - TestOnRecoveryCompleted_S07_MidTxFailure_FullRollback (fault-injection)
//   - TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	userapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// recoveryAuditFaultErr — the injected mid-tx failure (fault-injection path).
var recoveryAuditFaultErr = fmt.Errorf("injected audit fault")

// seedAccountAndUser inserts (account, user) with the given external_id / email /
// invite_status in one tx (DEFERRABLE FK chicken-and-egg). Returns the ids.
func seedAccountAndUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, externalID, email, status string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		string(uid), string(accID), externalID, email, "Recovery User", status)
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), fmt.Sprintf("rec-acc-%s", accID[len(accID)-6:]), string(uid))
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// awaitOp polls the ops repo until done (or timeout).
func awaitOp(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operation %s not done within deadline", id)
	return nil
}

func auditRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, recoveryJTI string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user.recovery_completed'
		   AND event_payload->>'recovery_jti' = $1`, recoveryJTI).Scan(&n))
	return n
}

// ── S01 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S01_Blocked_ReEnable_Revoke_Audit_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, accID := seedAccountAndUser(t, ctx, pool, "krt_alice", "alice@example.com", "BLOCKED")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "operation must succeed")

	// metadata
	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(uid), meta.GetUserId())
	assert.GreaterOrEqual(t, meta.GetRevokedSessionCount(), int32(1))

	// re-enabled: invite_status = ACTIVE
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB, "BLOCKED → ACTIVE re-enable")

	// revoke-all cutoff present, reason password-change
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	// exactly one audit row, re_enabled=true, tenant=acc
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_001"))
	var (
		reEnabled bool
		tenant    string
	)
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (event_payload->>'re_enabled')::bool, tenant_account_id
		  FROM kacho_iam.audit_outbox
		 WHERE event_payload->>'recovery_jti' = $1`, "rec_flow_001").Scan(&reEnabled, &tenant))
	assert.True(t, reEnabled)
	assert.Equal(t, string(accID), tenant)

	// ledger row exists
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_001").Scan(&ledgerN))
	assert.Equal(t, 1, ledgerN)
}

// ── S02 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S02_Active_NoopReEnable_Revoke_Audit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_bob", "bob@example.com", "ACTIVE")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_bob", RecoveryJTI: "rec_flow_002", Email: "bob@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error)

	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB, "ACTIVE stays ACTIVE (re-enable no-op)")

	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, meta.GetRevokedSessionCount(), int32(1))

	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_002"))
	var reEnabled bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (event_payload->>'re_enabled')::bool FROM kacho_iam.audit_outbox
		 WHERE event_payload->>'recovery_jti' = $1`, "rec_flow_002").Scan(&reEnabled))
	assert.False(t, reEnabled, "re_enabled=false for an already-ACTIVE user")
}

// ── S03 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S03_UnknownExternalID_NotFound_NoSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_ghost", RecoveryJTI: "rec_flow_003", Email: "ghost@example.com",
	})
	require.Error(t, err, "unknown identity → sync NOT_FOUND (no Operation)")
	assert.Nil(t, op)

	// no side-effects
	assertNoSideEffects(t, ctx, pool, "rec_flow_003")
}

// ── S04 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S04_EmailMismatch_FailedPrecondition_NoSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_carol", "carol@example.com", "ACTIVE")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_carol", RecoveryJTI: "rec_flow_004", Email: "attacker@evil.example.com",
	})
	require.Error(t, err)
	assert.Nil(t, op)

	// status unchanged
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB)
	assertNoSideEffects(t, ctx, pool, "rec_flow_004")
}

// ── S05 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S05_DuplicateJTI_IdempotentNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_alice", "alice@example.com", "BLOCKED")
	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)

	// First processing.
	op1, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
	})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, op1.ID).Error)

	// Capture cutoff C1.
	var c1 time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&c1))

	// Concurrent duplicate deliveries of the SAME recovery_jti (at-least-once).
	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			dop, derr := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
				ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
			})
			if derr == nil && dop != nil {
				_ = awaitOp(t, ctx, opsRepo, dop.ID).Error
			}
		}()
	}
	wg.Wait()

	// Cutoff did NOT move forward (no second cutoff).
	var c2 time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&c2))
	assert.WithinDuration(t, c1, c2, time.Millisecond,
		"duplicate delivery must NOT advance the cutoff (monotonicity preserved relative to recovery moment)")

	// Exactly one audit row, exactly one ledger row.
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_001"), "no duplicate audit row")
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_001").Scan(&ledgerN))
	assert.Equal(t, 1, ledgerN, "exactly one ledger row")
}

// ── S07 — mid-tx failure → full rollback, no stuck idempotency key ────────
func TestOnRecoveryCompleted_S07_MidTxFailure_FullRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	realRepo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_dan", "dan@example.com", "BLOCKED")

	// Fault-injection: a repo whose Writer fails on EmitAuditEvent (after the
	// idempotency-insert + re-enable + cutoff, before commit) → full rollback.
	faulty := &faultyAuditRepo{Repository: realRepo}
	uc := userapp.NewOnRecoveryCompletedUseCase(faulty, opsRepo)

	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_dan", RecoveryJTI: "rec_flow_007", Email: "dan@example.com",
	})
	require.NoError(t, err, "sync stages pass; the fault is inside the async writer-tx")
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.NotNil(t, done.Error, "operation must fail")

	// Full rollback: status stays BLOCKED, no cutoff, no audit, no ledger row.
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "BLOCKED", statusDB, "re-enable rolled back")

	var cutoffN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&cutoffN))
	assert.Equal(t, 0, cutoffN, "cutoff rolled back")

	assert.Equal(t, 0, auditRowCount(t, ctx, pool, "rec_flow_007"), "audit rolled back")

	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_007").Scan(&ledgerN))
	assert.Equal(t, 0, ledgerN, "no stuck idempotency key — flow can be reprocessed")
}

// ── S09 — one Kratos identity across N accounts ───────────────────────────
//
// SPEC-vs-SCHEMA clarification (resolved).
//
// Two UNIQUE guards interact on external_id: the per-Account
// `users_account_external_id_unique` and migration 0011's stricter GLOBAL partial
// UNIQUE `users_active_external_id_uniq` (ON external_id WHERE invite_status='ACTIVE'
// AND external_id<>”). The two interact as follows:
//   - TWO ACTIVE rows per external_id is IMPOSSIBLE (the global guard forbids it).
//   - But a BLOCKED row in one Account + an ACTIVE row in ANOTHER Account, both
//     sharing external_id, IS a reachable stored state (BLOCKED rows are
//     unrestricted by the partial index). Re-enabling that BLOCKED row →
//     ACTIVE would collide with the ACTIVE sibling on the global guard (23505).
//     So a "both rows ACTIVE" form stays unreachable; the
//     BLOCKED+ACTIVE-across-accounts form (handled by the SAVEPOINT-bounded skip
//     in internal_on_recovery.go) is the real multi-account case. See
//     docs/architecture/recovery-completion-multi-account.md.
//
// This test pins the canonical single-non-PENDING multi-account shape: a single
// non-PENDING (here BLOCKED, the canonical identity row) matched by external_id
// plus a PENDING sibling in another Account (external_id=” → NOT matched by
// external_id). Recovery re-enables + revokes the canonical row; the PENDING
// sibling is untouched. The BLOCKED+ACTIVE collision degradation is covered by
// TestOnRecoveryCompleted_S09b_BlockedActiveAcrossAccounts_SkipReEnable_StillRevokeAudit.
func TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// Canonical identity row (BLOCKED) + a PENDING sibling in another Account.
	u1, _ := seedAccountAndUser(t, ctx, pool, "krt_eve", "eve@example.com", "BLOCKED")
	uPending, _ := seedAccountAndUser(t, ctx, pool, "", "eve@example.com", "PENDING")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_eve", RecoveryJTI: "rec_flow_009", Email: "eve@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error)

	// Canonical row re-enabled BLOCKED → ACTIVE.
	var s1 string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(u1)).Scan(&s1))
	assert.Equal(t, "ACTIVE", s1, "canonical row BLOCKED → ACTIVE")

	// Canonical row got a revoke-all cutoff (reason password-change).
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(u1)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	// PENDING sibling untouched (not matched by external_id; no cutoff, still PENDING).
	var sPending string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uPending)).Scan(&sPending))
	assert.Equal(t, "PENDING", sPending, "PENDING sibling (external_id='') is not part of the recovery")
	var pendingCutoffN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`, string(uPending)).Scan(&pendingCutoffN))
	assert.Equal(t, 0, pendingCutoffN, "PENDING sibling gets no cutoff")

	// metadata: user_id = canonical row, count = 1 (single matched non-PENDING row).
	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(u1), meta.GetUserId(), "metadata.user_id = canonical identity row")
	assert.Equal(t, int32(1), meta.GetRevokedSessionCount())

	// one audit row for the identity recovery.
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_009"))
}

// ── S09b — BLOCKED + ACTIVE across two accounts (SAVEPOINT-bounded skip) ───
//
// A multi-account identity with an
// ACTIVE row in Account A AND a BLOCKED row in Account B (a REACHABLE stored
// state — migration 0011's `users_active_external_id_uniq` is GLOBAL: ≤1 ACTIVE
// per external_id, but BLOCKED rows are unrestricted). Re-enabling the BLOCKED
// row → ACTIVE raises 23505 against the global guard. The recovery worker runs
// all steps in ONE writer-tx; without a SAVEPOINT, that 23505 aborts the tx
// (25P02) and the subsequent revoke/audit/commit all fail — so the advertised
// "skip the colliding re-enable, still revoke + audit" degradation is impossible.
//
// With the SAVEPOINT fix, the colliding re-enable is rolled back to the savepoint
// (tx stays usable), that row is skipped (stays BLOCKED), but revoke-all + audit
// DO commit and the whole Operation succeeds. This test MUST be RED before the
// SAVEPOINT fix (the op aborts) and GREEN after.
func TestOnRecoveryCompleted_S09b_BlockedActiveAcrossAccounts_SkipReEnable_StillRevokeAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// ACTIVE row in Account A (older = canonical primary), BLOCKED row in Account
	// B (newer), both sharing external_id krt_frank + email frank@example.com.
	// This is INSERT-able: 0011 only forbids two ACTIVE per external_id, not
	// BLOCKED+ACTIVE.
	uActive, accA := seedAccountAndUser(t, ctx, pool, "krt_frank", "frank@example.com", "ACTIVE")
	uBlocked, _ := seedAccountAndUser(t, ctx, pool, "krt_frank", "frank@example.com", "BLOCKED")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_frank", RecoveryJTI: "rec_flow_009b", Email: "frank@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "operation must SUCCEED (not abort): the colliding re-enable is skipped via SAVEPOINT, revoke+audit commit")

	// The ACTIVE row stays ACTIVE (re-enable no-op).
	var sActive string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uActive)).Scan(&sActive))
	assert.Equal(t, "ACTIVE", sActive, "ACTIVE sibling stays ACTIVE")

	// The BLOCKED row's re-enable COLLIDED on the global guard → skipped → stays BLOCKED.
	var sBlocked string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uBlocked)).Scan(&sBlocked))
	assert.Equal(t, "BLOCKED", sBlocked, "colliding BLOCKED→ACTIVE re-enable is skipped (stays BLOCKED)")

	// BUT revoke-all cutoff committed for BOTH matched rows (security goal: revoke
	// the identity's old sessions even when one row's re-enable collides).
	var revActive, revBlocked string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uActive)).Scan(&revActive))
	assert.Equal(t, "password-change", revActive, "ACTIVE row got revoke-all cutoff")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uBlocked)).Scan(&revBlocked))
	assert.Equal(t, "password-change", revBlocked, "BLOCKED row STILL got revoke-all cutoff (degradation requirement)")

	// Audit row committed (the op did NOT abort).
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_009b"), "audit row commits despite the collision")

	// Ledger row committed (the idempotency gate is intact for this jti).
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_009b").Scan(&ledgerN))
	assert.Equal(t, 1, ledgerN, "ledger row committed")

	// metadata: primary user_id = canonical ACTIVE row; revoked count = 2 (both matched rows).
	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(uActive), meta.GetUserId(), "primary = canonical ACTIVE row (first by created_at)")
	assert.Equal(t, int32(2), meta.GetRevokedSessionCount(), "both matched rows revoked")
	_ = accA
}

// assertNoSideEffects — no cutoff / no audit / no ledger row for the given jti.
func assertNoSideEffects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, recoveryJTI string) {
	t.Helper()
	var auditN int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user.recovery_completed'
		   AND event_payload->>'recovery_jti' = $1`, recoveryJTI).Scan(&auditN))
	assert.Equal(t, 0, auditN, "no audit row")
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, recoveryJTI).Scan(&ledgerN))
	assert.Equal(t, 0, ledgerN, "no ledger row")
}

// faultyAuditRepo wraps a real Repository; its Writer fails on EmitAuditEvent so
// the recovery writer-tx fails AFTER the idempotency-insert + re-enable + cutoff
// but BEFORE commit (fault-injection path). Everything else delegates to the
// real tx, so the rollback is the real Postgres rollback.
type faultyAuditRepo struct {
	*kachopg.Repository
}

func (r *faultyAuditRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &faultyAuditWriter{Writer: w}, nil
}

type faultyAuditWriter struct {
	kachorepo.Writer
}

// EmitAuditEvent — injected fault: returns an error so the recovery writer-tx
// rolls back (the use-case maps the failure and rolls back via DoWithWriteTx).
func (w *faultyAuditWriter) EmitAuditEvent(context.Context, service.AuditEvent) error {
	return recoveryAuditFaultErr
}
