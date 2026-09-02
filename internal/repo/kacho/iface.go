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
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/visibility"
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

	// Visibility — структурные факты о ВЫЗЫВАЮЩЕМ, по которым списочный use-case
	// сужает набор кандидатов ДО чтения первой строки (задача #645). Живёт на той
	// же TX, что и страница, поэтому memo и её догрузка видят один снимок.
	//
	// Реализация может вернуть nil (дублёр, которому эти факты не нужны). Списочный
	// use-case обязан трактовать nil как «сузить нечем» и отказать, а не листать
	// ненаречённое: пустая страница и «мне нечем ответить» — разные ответы, и
	// второй обязан быть отличим.
	Visibility() visibility.ReaderIface

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
	// AND a committed create always leaves the owner-tuple intent, out of which a
	// trigger folds the direct fact in the SAME commit. This replaces the former
	// прежний путь записи ПОСЛЕ коммита ("Non-fatal", снят), который терял
	// the tuple on any outage of the store → owner locked out of their own resource.
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

	// EmitInviteMail ставит намерение отправить письмо приглашения в
	// `kacho_iam.invite_mail_outbox` на ЭТОЙ writer-транзакции — атомарно со
	// строкой приглашения (ban #10).
	//
	// Атомарность здесь несущая, а не удобная: при откате приглашения намерения
	// нет ВОВСЕ (человек не получит письма о приглашении, которого не случилось),
	// а при состоявшемся приглашении оно переживает смерть процесса. Прямой вызов
	// ретранслятора из обработчика не даёт ни того, ни другого.
	//
	// userID служит ключом партиции порядка: письма одному человеку уходят в том
	// порядке, в котором их поставили. Ссылки-предъявителя намерение не несёт —
	// доступ даёт владение почтовым ящиком, а не обладание письмом.
	EmitInviteMail(ctx context.Context, userID, accountID, to, loginURL string) error

	// InsertRecoveryCompletion — idempotency-gate INSERT for the Kratos
	// recovery-completed webhook (kacho_iam.recovery_completions, migration 0015).
	// Runs `INSERT … ON CONFLICT (recovery_jti) DO NOTHING` and
	// then reads back the stored row, all on THIS writer-tx:
	//   - inserted=true  → this recovery_jti is new → caller runs the side-effects
	//     (revoke-all cutoff + audit) in the SAME tx, then commits.
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
	// cutoff commits atomically with the recovery audit event
	// (запрет #10). The cutoff never moves backwards; the PK row-lock
	// serializes concurrent writers.
	UpsertUserTokenRevokeAll(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error

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
