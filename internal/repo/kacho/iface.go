// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package kacho — CQRS Repository корень для kacho-iam.
//
// Repository.Reader(ctx) → ReadTX (read-only, может работать на slave-pool);
// Repository.Writer(ctx) → WriteTX (read-write, всегда на master).
//
// Внутри одной Writer-TX атомарно объединяются: domain-mutation + outbox-emit.
// Внутри Reader-TX — только SELECT'ы; mutation panic'нет.
//
// Конкретные ресурсные репо живут в подпакетах:
//   - kacho/account
//   - kacho/project
//   - kacho/user
//   - kacho/service_account
//   - kacho/group
//   - kacho/role
//   - kacho/access_binding
//   - kacho/outbox
package kacho

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/outboxtypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// Repository — корневой entry-point. Конкретная реализация — `pg` подпакет.
type Repository interface {
	// Reader открывает read-only TX (G.4: на slave-pool, если настроен).
	Reader(ctx context.Context) (Reader, error)
	// Writer открывает read-write TX (всегда master). Caller обязан вызвать
	// Commit() или Rollback() ровно один раз.
	Writer(ctx context.Context) (Writer, error)
	// Close — освобождает pgxpool (вызывается из main по shutdown).
	Close()
}

// Reader — read-only TX, дающий доступ ко всем ресурсным Reader-iface'ам.
type Reader interface {
	Accounts() account.ReaderIface
	Projects() project.ReaderIface
	Users() user.ReaderIface
	ServiceAccounts() service_account.ReaderIface
	Groups() group.ReaderIface
	Roles() role.ReaderIface
	AccessBindings() access_binding.ReaderIface

	// Commit/Rollback — на Reader-TX оба noop'оподобны (read-only), но обязаны
	// быть вызваны для возврата соединения в pool.
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Writer — read-write TX. Включает все Reader-iface'ы (Writer-TX тоже умеет
// читать в рамках своей snapshot'ы) + Writer-iface'ы для mutation.
type Writer interface {
	Reader

	AccountsW() account.WriterIface
	ProjectsW() project.WriterIface
	UsersW() user.WriterIface
	ServiceAccountsW() service_account.WriterIface
	GroupsW() group.WriterIface
	RolesW() role.WriterIface
	AccessBindingsW() access_binding.WriterIface

	// EmitAuditEvent appends one durable kacho_iam.audit_outbox compliance row
	// inside THIS writer-tx — atomic with the surrounding domain mutation
	// (запрет #10): the audit row commits iff the mutation commits, so a
	// rolled-back mutation leaves no orphan compliance row and a committed one
	// always leaves its trail. Reuses the shared audit_outbox emitter
	// emit path (22-char `evt_…` id, status='pending'). Used by the async CRUD
	// use-cases (Account/Project/User/ServiceAccount/Group/Role) to record
	// "who created/updated/deleted which resource, and when".
	EmitAuditEvent(ctx context.Context, ev outboxtypes.AuditEvent) error

	// EmitFGARelationWrite / EmitFGARelationDelete append N FGA owner/hierarchy
	// tuple-write (resp. tuple-delete) intent rows into kacho_iam.fga_outbox
	// inside THIS writer-tx — atomic with the surrounding resource mutation
	// (запрет #10 / SEC-D). The intent row commits iff the
	// resource INSERT commits, so a rolled-back create leaves no orphan intent
	// AND a committed create always leaves the owner-tuple intent that the live
	// fga_outbox drainer (cmd/kacho-iam/serve.go) delivers to OpenFGA at-least-once
	// + idempotently (409 → success). This replaces the former best-effort
	// post-commit relationhook.WriteHierarchyTuple ("Non-fatal") path, which lost
	// the tuple on any FGA outage → owner locked out of their own resource.
	//
	// Used by the own-resource Create use-cases (Account/Project/Group/
	// ServiceAccount/Role) + user bootstrap to co-commit the owner/hierarchy
	// owner-tuple intent. Event types reuse the existing kacho_iam.fga_outbox
	// CHECK literals 'fga.tuple.write'/'fga.tuple.delete' (migration 0001) —
	// no new literal, no new migration. len(tuples)==0 is a no-op. Mirrors the
	// already-atomic AccessBindingsW().EmitRelationWrite emit path.
	EmitFGARelationWrite(ctx context.Context, tuples []outboxtypes.RelationTuple) error
	EmitFGARelationDelete(ctx context.Context, tuples []outboxtypes.RelationTuple) error

	// EmitReconcileEvent enqueues a resource_reconcile_outbox event on THIS
	// writer-tx (T3/Q2): an IAM-OWN-resource label change (Project/Account.Update
	// labels-in-mask) co-commits a reconcile trigger so the selector reconciler
	// re-evaluates iam-direct selector bindings whose membership the change affects
	// — parity with the mirror-change trigger (resource_mirror upsert
	// co-commits the same event). Atomic with the UPDATE (ban #10). objectType is
	// the dotted closed-table key ("iam.project" / "iam.account"); eventType is
	// "mirror.upsert" | "mirror.delete" (reused literals).
	EmitReconcileEvent(ctx context.Context, eventType, objectType, objectID string) error

	// InsertRecoveryCompletion — idempotency-gate INSERT for the Kratos
	// recovery-completed webhook (kacho_iam.recovery_completions, migration 0015).
	// Runs `INSERT … ON CONFLICT (recovery_jti) DO NOTHING` and
	// then reads back the stored row, all on THIS writer-tx:
	//   - inserted=true  → this recovery_jti is new → caller runs the side-effects
	//     (re-enable + revoke-all cutoff + audit) in the SAME tx, then commits.
	//   - inserted=false → already processed → idempotent no-op; the returned
	//     domain.RecoveryCompletion carries the stored user_id /
	//     revoked_session_count for the replayed Operation.metadata.
	// The PK row-lock serializes concurrent deliveries of one recovery_jti
	// (exactly one writer wins the INSERT). On a mid-tx rollback the ledger row
	// rolls back too (no "stuck" idempotency key — запрет #10).
	InsertRecoveryCompletion(ctx context.Context, rc domain.RecoveryCompletion) (domain.RecoveryCompletion, bool /*inserted*/, error)

	// UpsertUserTokenRevokeAll — per-user "revoke-all-before" cutoff written on
	// THIS writer-tx (kacho_iam.user_token_revocations, migration 0012). Same
	// monotonic GREATEST upsert as the pool-scoped path, but tx-scoped so the
	// cutoff commits atomically with the recovery re-enable + audit
	// (запрет #10). The cutoff never moves backwards; the PK row-lock
	// serializes concurrent writers.
	UpsertUserTokenRevokeAll(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error

	// Savepoint / RollbackToSavepoint / ReleaseSavepoint — tx-scoped savepoint
	// primitives for bounding a statement that may raise a recoverable SQLSTATE
	// (e.g. 23505) WITHOUT aborting the whole writer-tx.
	//
	// Postgres puts a tx into the aborted state (25P02) after ANY error, so every
	// subsequent statement fails — UNLESS the error is rolled back to a SAVEPOINT
	// taken before the failing statement. The recovery worker uses
	// these to skip a per-row BLOCKED→ACTIVE re-enable that collides with the
	// global `users_active_external_id_uniq` (a sibling is already ACTIVE) while
	// still running the revoke-all cutoff + audit on the now-clean tx:
	//
	//	if err := w.Savepoint(ctx, name); err != nil { return err }
	//	_, _, rerr := w.UsersW().ReEnable(ctx, id)
	//	if errors.Is(rerr, ErrAlreadyExists) {
	//	    _ = w.RollbackToSavepoint(ctx, name) // tx usable again, row skipped
	//	} else if rerr != nil {
	//	    return rerr                           // other error → full rollback
	//	} else {
	//	    _ = w.ReleaseSavepoint(ctx, name)     // success → drop the savepoint
	//	}
	//
	// `name` MUST be a safe SQL identifier (static literal or sanitized — never
	// raw user input). The pg adapter validates it and panics on an unsafe name
	// (programmer error, not a runtime/tenant-facing condition).
	Savepoint(ctx context.Context, name string) error
	RollbackToSavepoint(ctx context.Context, name string) error
	ReleaseSavepoint(ctx context.Context, name string) error

	// AdvisoryXactLock takes a transaction-scoped
	// pg_advisory_xact_lock(hashtext(key)) on THIS writer-tx. It serializes
	// concurrent writer-txs that pass the SAME key, and auto-releases at
	// COMMIT/ROLLBACK (no manual unlock). Used to make a check-then-insert
	// atomic where no single-statement CAS / UNIQUE can express the invariant —
	// e.g. the RC-5 personal-account bootstrap gate, whose "owns-zero-accounts"
	// predicate cannot be a partial UNIQUE (a user may legitimately own many
	// accounts) and whose random account name defeats accounts_name_unique. The
	// caller takes the lock FIRST, then RE-CHECKs the predicate inside the same
	// tx (ban #10 — DB-level serialization, not a cross-tx software check).
	AdvisoryXactLock(ctx context.Context, key string) error
}
