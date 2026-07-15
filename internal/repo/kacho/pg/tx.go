// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// tx.go — реализация Reader/Writer-TX поверх pgx.Tx.
//
// Wires per-aggregate Reader/Writer implementations (account, project, user,
// service_account, group, role, access_binding) onto a single tx. Each
// per-aggregate reader/writer lives in its own file.

import (
	"context"
	"regexp"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kacho "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// readTx — kacho.Reader поверх pgx.Tx (TxOptions{AccessMode: ReadOnly}).
type readTx struct {
	tx pgx.Tx
}

func (r *readTx) Accounts() account.ReaderIface { return &accountReader{tx: r.tx} }

func (r *readTx) Projects() project.ReaderIface {
	return &projectReader{tx: r.tx}
}
func (r *readTx) Users() user.ReaderIface {
	return &userReader{tx: r.tx}
}
func (r *readTx) ServiceAccounts() service_account.ReaderIface {
	return &saReader{tx: r.tx}
}
func (r *readTx) Groups() group.ReaderIface {
	return &groupReader{tx: r.tx}
}
func (r *readTx) Roles() role.ReaderIface {
	return &roleReader{tx: r.tx}
}
func (r *readTx) AccessBindings() access_binding.ReaderIface {
	return &abReader{tx: r.tx}
}

func (r *readTx) Commit(ctx context.Context) error   { return r.tx.Commit(ctx) }
func (r *readTx) Rollback(ctx context.Context) error { return r.tx.Rollback(ctx) }

// writeTx — kacho.Writer поверх pgx.Tx (RW).
type writeTx struct {
	readTx
	// ownerFKHint — owner id of the account inserted on this tx (if any). Set by
	// accountWriter.Insert via the AccountsW sink; consumed by Commit to render the
	// canonical "User <id> not found" text when the DEFERRABLE accounts_owner_fk
	// fires at commit-time (see Commit below).
	ownerFKHint string
}

func (w *writeTx) AccountsW() account.WriterIface {
	return &accountWriter{
		accountReader:   accountReader{tx: w.tx},
		ownerFKHintSink: &w.ownerFKHint,
	}
}

func (w *writeTx) ProjectsW() project.WriterIface {
	return &projectWriter{projectReader: projectReader{tx: w.tx}}
}
func (w *writeTx) UsersW() user.WriterIface {
	return &userWriter{userReader: userReader{tx: w.tx}}
}
func (w *writeTx) ServiceAccountsW() service_account.WriterIface {
	return &saWriter{saReader: saReader{tx: w.tx}}
}
func (w *writeTx) GroupsW() group.WriterIface {
	return &groupWriter{groupReader: groupReader{tx: w.tx}}
}
func (w *writeTx) RolesW() role.WriterIface {
	return &roleWriter{roleReader: roleReader{tx: w.tx}}
}
func (w *writeTx) AccessBindingsW() access_binding.WriterIface {
	return &abWriter{abReader: abReader{tx: w.tx}}
}

// Commit overrides readTx.Commit for the write path so a constraint violation
// that only surfaces at COMMIT — notably the DEFERRABLE INITIALLY DEFERRED
// accounts_owner_fk (a non-existent account owner is NOT caught by the INSERT
// statement) — is translated through the constraint-aware SQLSTATE→sentinel
// bridge instead of leaking the raw *pgconn.PgError to the caller, which would
// hit shared.MapRepoErr's sentinel-only INTERNAL fallback and misclassify a
// tenant-precondition failure as codes.Internal "internal error". The owner-id
// hint (recorded by accountWriter.Insert) yields the canonical Kachō
// "User <id> not found" FailedPrecondition text. mapErr(nil, …) is nil-safe.
func (w *writeTx) Commit(ctx context.Context) error {
	return mapErr(w.tx.Commit(ctx), "", w.ownerFKHint)
}

// EmitAuditEvent appends one durable audit_outbox compliance row on THIS
// writer-tx's pgx.Tx (atomic with the surrounding mutation — запрет #10). The
// emit logic is shared with the service.AuditOutboxEmitter adapter via
// insertAuditEventTx (single source of truth: 22-char `evt_…` id guard,
// status='pending').
func (w *writeTx) EmitAuditEvent(ctx context.Context, ev service.AuditEvent) error {
	return insertAuditEventTx(ctx, w.tx, ev)
}

// EmitFGARelationWrite appends N FGA owner/hierarchy tuple-write intent rows
// into kacho_iam.fga_outbox (event_type='fga.tuple.write') on THIS writer-tx's
// pgx.Tx — atomic with the surrounding resource INSERT (запрет #10). Reuses the
// shared fga_outbox.EmitWriteTx helper (single source of truth with the
// access_binding emit + InternalIAMService.RegisterResource relay), so a
// rolled-back create leaves no orphan intent and a committed create always leaves
// the owner-tuple intent for the live drainer to deliver.
func (w *writeTx) EmitFGARelationWrite(ctx context.Context, tuples []service.RelationTuple) error {
	return fga_outbox.EmitWriteTx(ctx, w.tx, serviceTuplesToClients(tuples))
}

// EmitFGARelationDelete — symmetric tuple-delete intent emit (event_type=
// 'fga.tuple.delete') on THIS writer-tx (resource Delete co-commit).
func (w *writeTx) EmitFGARelationDelete(ctx context.Context, tuples []service.RelationTuple) error {
	return fga_outbox.EmitDeleteTx(ctx, w.tx, serviceTuplesToClients(tuples))
}

// EmitReconcileEvent enqueues a resource_reconcile_outbox event on THIS
// writer-tx: an IAM-OWN-resource label change (Project/Account.Update
// with labels in the mask) co-commits a reconcile trigger so the selector
// reconciler re-evaluates iam-direct selector bindings that match/no-longer-match
// the object — parity with the mirror-change trigger (resource_mirror
// upsert co-commits the same event). Atomic with the UPDATE (ban #10): a
// rolled-back update leaves no orphan event. eventType is "mirror.upsert" |
// "mirror.delete" (reused literals — an iam-direct label change is an upsert).
func (w *writeTx) EmitReconcileEvent(ctx context.Context, eventType, objectType, objectID string) error {
	return reconcile_outbox.EmitTx(ctx, w.tx, eventType, objectType, objectID)
}

// InsertRecoveryCompletion — idempotency-gate INSERT on THIS writer-tx
// (recovery_completions, migration 0015). ON CONFLICT DO NOTHING
// + backstop SELECT → (stored row, inserted). PK row-lock serializes concurrent
// deliveries of one recovery_jti.
func (w *writeTx) InsertRecoveryCompletion(ctx context.Context, rc domain.RecoveryCompletion) (domain.RecoveryCompletion, bool, error) {
	return insertRecoveryCompletionTx(ctx, w.tx, rc)
}

// UpsertUserTokenRevokeAll — per-user monotonic revoke-all cutoff on THIS
// writer-tx (user_token_revocations, migration 0012). Reuses the canonical
// GREATEST upsert (single source of truth with the pool-scoped repo) so the
// cutoff commits atomically with the recovery re-enable + audit (запрет #10).
func (w *writeTx) UpsertUserTokenRevokeAll(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	_, err := w.tx.Exec(ctx, upsertRevokeAllSQL,
		string(u.UserID), u.RevokeBefore, u.Reason, string(revokedBy),
	)
	if err != nil {
		return mapErr(err, "", string(u.UserID))
	}
	return nil
}

// Savepoint / RollbackToSavepoint / ReleaseSavepoint — tx-scoped SAVEPOINT
// primitives on THIS writer-tx's pgx.Tx. SAVEPOINT names cannot be parameterized
// in SQL, so the name is spliced into the statement; safeSavepointName guards
// against injection (panic on an unsafe name — programmer error, callers pass
// static literals).
//
// These let a caller bound a statement that may raise a recoverable SQLSTATE
// (e.g. 23505) without aborting the whole tx (25P02) — see the recovery worker
// in internal/apps/kacho/api/user/internal_on_recovery.go.
func (w *writeTx) Savepoint(ctx context.Context, name string) error {
	n := safeSavepointName(name)
	if _, err := w.tx.Exec(ctx, "SAVEPOINT "+n); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

func (w *writeTx) RollbackToSavepoint(ctx context.Context, name string) error {
	n := safeSavepointName(name)
	if _, err := w.tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+n); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

func (w *writeTx) ReleaseSavepoint(ctx context.Context, name string) error {
	n := safeSavepointName(name)
	if _, err := w.tx.Exec(ctx, "RELEASE SAVEPOINT "+n); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

// AdvisoryXactLock takes pg_advisory_xact_lock(hashtext($1)) on THIS writer-tx.
// The key is passed as a bind parameter (hashtext maps it to the int4 lock key),
// so no identifier-splicing / injection surface. The lock is transaction-scoped
// and auto-releases at COMMIT/ROLLBACK — mirroring the reconcile-adapter's
// per-binding lock and the JWKS-rotate per-alg lock.
func (w *writeTx) AdvisoryXactLock(ctx context.Context, key string) error {
	if _, err := w.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, key); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

// safeSavepointName validates a SAVEPOINT identifier (must match
// [A-Za-z_][A-Za-z0-9_]*). SAVEPOINT names can't be passed as bind parameters,
// so the name is concatenated into the SQL text; an unsafe name is a programmer
// error (callers pass static literals), so we panic rather than silently
// proceed — this can never originate from tenant input.
func safeSavepointName(name string) string {
	if !savepointNameRe.MatchString(name) {
		panic("pg: unsafe savepoint name: " + name)
	}
	return name
}

var savepointNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Compile-time interface satisfaction guards.
var (
	_ kacho.Reader = (*readTx)(nil)
	_ kacho.Writer = (*writeTx)(nil)
)
