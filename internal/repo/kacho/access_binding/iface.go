// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access_binding — CQRS port-iface'ы для kacho_iam.access_bindings.
package access_binding

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/visibility"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error)
	// List — the unified read (redesign-2026 F11). Optional predicate fields
	// (subject/role/scope-type/scope-id) constrain the result; keyset paginated
	// by (created_at, id) ASC. Read VISIBILITY is not a predicate here: the
	// use-case applies it per-object to the rows this returns
	// (internal/authzfilter).
	//
	// `Candidates` is NOT that visibility and must not be read as it: it selects
	// which rows are worth reading (a superset of the visible, from iam's own
	// tables), while the verdict on each stays with the model. Without it the page
	// is a raw window and everything past it is lost before any verdict — see the
	// field's own doc.
	List(ctx context.Context, filter ListFilter) ([]domain.AccessBinding, string, error)
	ListByScope(ctx context.Context, resourceType domain.ResourceType, resourceID string, filter PageFilter) ([]domain.AccessBinding, string, error)
	ListBySubject(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, filter PageFilter) ([]domain.AccessBinding, string, error)
	// ListSubjectPrivileges returns the subject's direct AccessBindings JOINed
	// with `roles` so the human-readable role_name is resolved server-side in a
	// SINGLE query (access_bindings ⋈ roles on role_id; same kacho_iam schema,
	// FK access_bindings_role_fk — no per-row N+1 GetRole). Used
	// by the enriched `AccessBindingService.ListSubjectPrivileges` RPC.
	// Differs from ListBySubject in:
	//   - LEFT JOIN roles → dangling role yields RoleName="" (graceful),
	//   - status <> 'REVOKED' filter (only PENDING/ACTIVE),
	//   - returns the enriched domain.SubjectPrivilege projection.
	// Ordering & keyset cursor are identical to ListBySubject: (created_at, id)
	// ASC, opaque base64 (created_at, id) page_token. v1 is DIRECT-only
	// (subject_id literally equals the requested subject).
	ListSubjectPrivileges(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, filter PageFilter) ([]domain.SubjectPrivilege, string, error)
	// ListByAccount returns all bindings in scope of an Account:
	//   * bindings directly attached (resource_type='account', resource_id=accountID); plus
	//   * bindings on every Project whose account_id = accountID.
	//
	// Used by the admin-only `AccessBindingService.ListByAccount` RPC so an
	// account admin can audit every subject with any access to the account
	// (not only those they granted themselves). Authorisation lives in the
	// use-case layer (account-owner / FGA admin gate).
	//
	// Ordering: (created_at DESC, id ASC) — newest grants first; ties broken
	// by id ASC. Keyset cursor format is opaque base64 (created_at, id) and
	// is interchangeable with ListByScope/ListBySubject implementations.
	ListByAccount(ctx context.Context, accountID domain.AccountID, filter AccountPageFilter) ([]domain.AccessBinding, string, error)
	// SelectEmittedTuples returns the EXACT FGA tuple set that was emitted for a
	// binding at grant time / last reconcile (the persisted
	// kacho_iam.access_binding_emitted_tuples ledger). This is the
	// source of truth for a SYMMETRIC revoke: Delete reads it and emits
	// EmitRelationDelete on EXACTLY this set instead of re-deriving from the
	// binding's CURRENT (possibly-mutated) role. It is also the diff base for the
	// Role.Update reconcile fan-out (old emitted-set vs derive-from-new-role).
	// Zero rows ⇒ empty slice (a binding with no emitted tuples, e.g. an arm that
	// emitted nothing). Read on the caller's tx (revoke reads it inside the same
	// writer-tx as the DELETE, BEFORE the row — and its emitted rows — are
	// CASCADE-dropped).
	SelectEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID) ([]RelationTuple, error)

	// SelectEmittedTuplesBySource returns only the emitted-set rows written by ONE
	// owner: source='binding' (Create + the Role.Update RoleTupleReconciler) or
	// source='member' (the γ ARM_LABELS reconciler). The Role.Update reconcile reads
	// the 'binding' subset so its set-diff cannot see — and so cannot revoke or wipe
	// — the per-member tuples (CRITICAL ledger-source fix). The full symmetric revoke
	// (delete.go) keeps reading the WHOLE ledger via SelectEmittedTuples. Read on the
	// caller's tx. Zero rows ⇒ empty slice (nil).
	SelectEmittedTuplesBySource(ctx context.Context, bindingID domain.AccessBindingID, source string) ([]RelationTuple, error)

	// SelectTuplesClaimedByOtherActiveBindings returns the SUBSET of `tuples` that is
	// ALSO recorded in the emitted-tuple ledger of an ACTIVE binding OTHER than
	// excludeBinding — i.e. the tuples a revoke of excludeBinding MUST leave alone.
	//
	// WHY IT EXISTS. The ledger PK is per binding (binding_id, fga_user, relation,
	// object), while the tuple itself is NOT refcounted: two bindings of the SAME
	// subject on the SAME scope hold TWO ledger rows for ONE live tuple. Replaying a
	// binding's own ledger set verbatim as deletions therefore removes access another
	// ACTIVE binding still grants (silent access-loss, and self-sustaining — the
	// ledger is read as the mirror of the rights state, so no reconcile pass
	// re-writes it).
	// Delete/Revoke subtract this set so a shared tuple is removed only when the LAST
	// ACTIVE claimant releases it — the same rule the reconciler already applies
	// internally (reconcile.ReconcileStore.TuplesStillClaimedByOtherBindings).
	//
	// The join requires the other binding to be ACTIVE: a REVOKED/expired binding
	// does not keep a tuple alive. Read on the caller's tx (the revoke runs it inside
	// its own writer-tx, so the answer is consistent with the delete it guards).
	// Empty `tuples` ⇒ empty result, no query.
	SelectTuplesClaimedByOtherActiveBindings(ctx context.Context, excludeBinding domain.AccessBindingID, tuples []RelationTuple) ([]RelationTuple, error)

	// ListActiveByRole returns every NON-revoked (PENDING/ACTIVE) binding that
	// references roleID. Used by the Role.Update reconcile fan-out: when
	// a role's permissions change, every active binding of that role must have its
	// FGA tuple projection reconciled to the new permissions. The fan-out is
	// BOUNDED by the number of active bindings of the single mutated role (not all
	// bindings). REVOKED bindings are excluded — their tuples are already gone.
	// No pagination: the set is small (bindings of one role) and reconciled in one
	// writer-tx; ordering is (created_at, id) ASC for determinism.
	ListActiveByRole(ctx context.Context, roleID domain.RoleID) ([]domain.AccessBinding, error)

	// CountActiveByRole returns the number of NON-revoked bindings of a role — the
	// bound-check for the Role.Update rules-change fan-out: a role carried by
	// more than the contract limit (10000) active bindings is rejected
	// FAILED_PRECONDITION before any fan-out work, so a single Role.Update cannot
	// trigger an unbounded reconcile. Cheap COUNT served by the role_id index.
	CountActiveByRole(ctx context.Context, roleID domain.RoleID) (int, error)

	// ListByRole returns the bindings that carry roleID, keyset-paginated by
	// (created_at, id) ASC (RBAC rules-model audit "who
	// holds role R"). IncludeRevoked=false (default) hides status='REVOKED' rows.
	// Scope-filter (only the bindings whose scope the caller may read) lives in
	// the use-case layer, as for the other List RPCs. Read-only — no race path.
	ListByRole(ctx context.Context, roleID domain.RoleID, filter ListByRoleFilter) ([]domain.AccessBinding, string, error)

	// ListActiveHoldingMembership возвращает выдачи, которые ДЕРЖАТ членство
	// человека в аккаунте, — те самые, из-за которых отложенный триггер
	// `membership_carrying_rights_is_kept` (миграция 472002) отвергает исключение.
	// Возвращает до `limit` идентификаторов И полную их величину: перечень
	// ограничен сверху, и клиент, читающий только его, принял бы «названо пять»
	// за «их пять».
	//
	// # Предикат ПОВТОРЯЕТ триггер, и это несущее требование
	//
	// Живые (`status='ACTIVE'`) · адресующие ЭТОГО человека (обе проекции субъекта,
	// легаси-одиночная и множественная) · в области ЭТОГО аккаунта либо его
	// проекта. Разойдись он с триггером — отказ называл бы не то, что помешало:
	// шире, и клиент отзывает лишнее, а исключение всё равно не проходит; уже, и
	// он отзывает названное, упирается снова и не понимает, почему.
	//
	// # Это НЕ проверка-перед-снятием
	//
	// Решает по-прежнему база (ban #10). Чтение идёт ПОСЛЕ отказа и только затем,
	// чтобы отказ назвал предмет; пустой ответ (выдачи успели отозвать) отказ не
	// отменяет — он лишь остаётся неперечисленным.
	ListActiveHoldingMembership(ctx context.Context, userID domain.UserID, accountID domain.AccountID, limit int) (ids []string, total int, err error)

	// ListSubjects returns the multi-subject set of ONE binding ordered by
	// (ordinal, subject_type, subject_id) (the read-projection).
	// Zero rows ⇒ a legacy binding written before the backfill — the read-side
	// then projects the legacy single subject as a one-element subjects[]
	// (the use-case applies that fallback; the repo returns verbatim rows).
	ListSubjects(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.Subject, error)

	// ListSubjectsForBindings batch-loads the subjects of MANY bindings in one
	// query (avoids per-row N+1 on List / ListByRole). Result maps binding id →
	// ordered subjects; a binding with no rows is absent from the map (caller
	// applies the legacy single-subject fallback).
	ListSubjectsForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error)

	// ListMaterializedAtForBindings batch-loads, for MANY bindings in one query,
	// the instant each one's per-object access last became live: MAX(updated_at)
	// over its ACTIVE rows in access_binding_target_members (the reconciler's
	// ledger). Mirrors ListSubjectsForBindings (no per-row N+1).
	//
	// A binding with NO ACTIVE member is ABSENT from the map — the caller leaves
	// domain.AccessBinding.MaterializedAt zero, which the API projects as an unset
	// field. PENDING_VERIFICATION members do NOT count: reporting a pending member
	// as materialized would tell an administrator the grant works when it does not.
	//
	// This is the read-only observable for the eventually-consistent
	// materialization window (Operation.done is durability, NOT visibility — ban
	// #9). It never gates a write.
	ListMaterializedAtForBindings(ctx context.Context, bindingIDs []domain.AccessBindingID) (map[domain.AccessBindingID]time.Time, error)
}

type WriterIface interface {
	// Insert — strict create. На дубле активного 5-tuple (WHERE revoked_at
	// IS NULL) partial UNIQUE access_bindings_active_grant_uniq поднимает
	// SQLSTATE 23505 → mapErr → ErrAlreadyExists с verbatim text «these
	// permissions are already granted to <subject_id> on
	// <res_type>:<res_id>». Идемпотентный ON CONFLICT-upsert удален в
	// migration 0003.
	Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error)
	Delete(ctx context.Context, id domain.AccessBindingID) error

	// DeleteGuarded — atomic CAS-delete honoring deletion_protection (RBAC
	// explicit-model). Single-statement
	// `DELETE … WHERE id=$1 AND deletion_protection=false`; 0 rows → re-read:
	// protected → ErrFailedPrecondition, absent → ErrNotFound. No software TOCTOU.
	DeleteGuarded(ctx context.Context, id domain.AccessBindingID) error

	// RevokeGuarded — atomic CAS soft-revoke (redesign-2026 F10 IAM-1-28). Unlike
	// DeleteGuarded (physical row-removal) this RETAINS the row and transitions
	// status ACTIVE→REVOKED, stamping revoked_at=now() and revoked_by_user_id for
	// audit-retention. Single-statement
	// `UPDATE … SET status='REVOKED', revoked_at=now(), revoked_by_user_id=$2
	//    WHERE id=$1 AND status='ACTIVE' AND deletion_protection=false RETURNING …`
	// takes a row-lock — the concurrent writer waits the commit and sees the row
	// already REVOKED (its CAS → 0 rows → ErrFailedPrecondition), so exactly one
	// revoke wins under concurrency (ban #10, no software TOCTOU). 0 rows → re-read
	// disambiguates: absent → ErrNotFound; deletion_protection=true →
	// ErrFailedPrecondition (clear the flag via Update first, exactly like Delete);
	// status≠ACTIVE (already REVOKED / PENDING) → ErrFailedPrecondition (terminal).
	// Because REVOKED rows carry revoked_at, the partial active-grant UNIQUE
	// (access_bindings_active_grant_uniq WHERE revoked_at IS NULL) frees the slot,
	// so an identical re-grant Create afterwards is a NEW ACTIVE row (IAM-1-29).
	// revokedBy MUST be non-empty (CHECK access_bindings_revoked_consistency_ck
	// requires revoked_at + status='REVOKED' to move together).
	RevokeGuarded(ctx context.Context, id domain.AccessBindingID, revokedBy domain.UserID) (domain.AccessBinding, error)

	// SetDeletionProtection — atomic CAS UPDATE of the deletion_protection flag.
	// 0 rows → ErrNotFound. Used by the
	// Update(update_mask=["deletion_protection"]) clear path.
	SetDeletionProtection(ctx context.Context, id domain.AccessBindingID, protected bool) (domain.AccessBinding, error)

	// UpdateLabels — atomic single-statement UPDATE of the own-resource labels
	// (AB mutable set расширен до {deletion_protection, labels}). Row-lock
	// сериализует конкурентные writer'ы (ban #10, last-writer-wins, не TOCTOU).
	// 0 rows → ErrNotFound. Used by the Update(update_mask=["labels"]) path; делает
	// AccessBinding label-selectable (catalog-видимость через viewer ∪ v_list).
	UpdateLabels(ctx context.Context, id domain.AccessBindingID, labels domain.Labels) (domain.AccessBinding, error)

	// TransitionStatus — atomic CAS UPDATE для lifecycle state machine.
	// Single-statement `UPDATE … WHERE status = ANY(expected)`;
	// 0 rows → ErrFailedPrecondition (terminal state или not-found).
	// При newStatus = REVOKED обязателен ненулевой revokedByUserID — CHECK
	// access_bindings_revoked_consistency_ck требует revoked_at NOT NULL вместе
	// с status='REVOKED'.
	// Запрет #10: row-level lock Postgres гарантирует one-winner на одну row.
	TransitionStatus(
		ctx context.Context,
		id domain.AccessBindingID,
		expected []domain.AccessBindingStatus,
		newStatus domain.AccessBindingStatus,
		revokedByUserID *domain.UserID,
	) (domain.AccessBinding, error)

	// EmitSubjectChangeEvent writes a kacho_iam.subject_change_outbox row in the
	// current transaction, used to drive api-gateway authz-cache invalidation.
	// Serialises the SubjectChangeEvent into the payload jsonb column AND
	// writes denormalised columns (subject_id, op, event_type, resource_type,
	// resource_id) in a single INSERT (atomic by construction). event_type/op
	// are cross-derived when one is omitted.
	//
	// The admissible values of op are closed by DB CHECK subject_change_op_check
	// and listed IN FULL on the SubjectChangeEvent.Op field below — deliberately
	// not repeated here. The previous wording repeated three of the seven and
	// attributed that shorter set to the constraint itself: a caller reading it
	// would take the remaining four for illegal, while the very same file listed
	// them correctly 130 lines down. Two places about one subject, one of them
	// wrong, and the wrong one sat in the interface people read first.
	//
	// Caller MUST invoke inside the same Writer-tx as the domain state-change
	// (запрет #10). Drainer (kacho-iam/internal/clients.NewSubjectChangeApplier)
	// drains via the corelib generic Drainer[T].
	EmitSubjectChangeEvent(ctx context.Context, evt SubjectChangeEvent) error

	// EmitRelationWrite — atomic FGA-tuple emit inside the writer-tx.
	// INSERTs N rows into kacho_iam.fga_outbox (event_type='fga.tuple.write')
	// in the current Writer-tx; a trigger on that INSERT folds each row into a
	// direct fact in the SAME commit. Tx rollback ⇒ no orphan rows (запрет #10).
	//
	// Caller supplies the tuples as {User, Relation, Object} triples (see
	// kacho-iam/internal/clients.RelationTuple). len(tuples)==0 is a no-op.
	EmitRelationWrite(ctx context.Context, tuples []RelationTuple) error

	// EmitRelationDelete — symmetric revoke for EmitRelationWrite (event_type='fga.tuple.delete').
	EmitRelationDelete(ctx context.Context, tuples []RelationTuple) error

	// InsertEmittedTuples persists the EXACT FGA tuples emitted for a binding into
	// kacho_iam.access_binding_emitted_tuples in THIS writer-tx — co-committed with
	// the matching EmitRelationWrite (ban #10). The ledger row commits iff
	// the fga_outbox emit commits, so "what was emitted" is always recorded
	// alongside the emit. `INSERT … ON CONFLICT (binding_id, fga_user, relation,
	// object) DO NOTHING` — re-emitting an already-recorded tuple (idempotent
	// re-grant / repeated reconcile) is a no-op. len(tuples)==0 is a no-op.
	InsertEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []RelationTuple) error

	// ReplaceEmittedTuples atomically REPLACES a binding's persisted emitted-set
	// with the supplied tuples in THIS writer-tx (DELETE all rows of the binding
	// then INSERT the new set) — used by the Role.Update reconcile fan-out so the
	// ledger always reflects the CURRENT emitted projection after a permission
	// change. Atomic with the surrounding fga_outbox delta emit (ban #10). An empty
	// `tuples` clears the binding's ledger rows.
	ReplaceEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []RelationTuple) error

	// InsertSubjects persists the multi-subject set of a binding into
	// access_binding_subjects in THIS writer-tx. One row per
	// subject (PK binding_id,subject_type,subject_id); `INSERT … ON CONFLICT DO
	// NOTHING` makes a re-insert of the same (binding,subject) idempotent. The
	// `ordinal` preserves request order so subjects[0] (= the legacy single
	// projection) is deterministic. The rows commit iff the surrounding binding
	// INSERT commits (atomic, ban #10). len(subjects)==0 is a no-op.
	InsertSubjects(ctx context.Context, bindingID domain.AccessBindingID, subjects []domain.Subject) error

	// DeleteSubject removes ONE subject of a binding inside THIS writer-tx and
	// returns whether a row was actually deleted (idempotent — a missing subject
	// returns false). Used by per-subject revoke: removing one subject's
	// child row + EmitRelationDelete on that subject's tuple-set leaves the other
	// subjects' rows and tuples untouched. The repo does NOT enforce the
	// last-subject guard (the use-case rejects emptying the set; revoking the
	// whole binding is AccessBinding.Delete).
	DeleteSubject(ctx context.Context, bindingID domain.AccessBindingID, subject domain.Subject) (bool, error)

	// EmitAuditEvent — durable compliance event emit inside the writer-tx.
	// INSERTs one row into kacho_iam.audit_outbox carrying the canonical
	// "who granted/revoked which role to whom on which resource, and when"
	// fact in the event_payload jsonb. A drainer streams these into the audit
	// topic; the row is committed iff the surrounding binding mutation commits
	// (запрет #10 — atomic emit-in-tx, no orphan compliance rows).
	//
	// For an IAM control plane the grant/revoke audit trail is the single most
	// security-relevant fact and MUST be durable — unlike fga_outbox (ReBAC
	// sync) and subject_change_outbox (cache invalidation), which are
	// operational side-channels, not a compliance log.
	EmitAuditEvent(ctx context.Context, ev AuditEvent) error
}

// AuditEventType — canonical audit_outbox event_type for AccessBinding
// lifecycle. Values satisfy the audit_outbox_event_type_check regex
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
type AuditEventType string

const (
	// AuditEventTypeGranted — emitted in the grant (Create) writer-tx.
	AuditEventTypeGranted AuditEventType = "iam.access_binding.granted"
	// AuditEventTypeRevoked — emitted in the revoke (Delete/TransitionStatus) writer-tx.
	AuditEventTypeRevoked AuditEventType = "iam.access_binding.revoked"
	// NB: the legacy AuditEventTypeSelectorReplaced (emitted by the removed
	// ReplaceTargetSelector RPC) was dropped in the rules-model clean-cut —
	// object-selection now lives in role.rules, not per-binding selectors.
)

// AuditEvent — payload for EmitAuditEvent. Carries the compliance-relevant
// dimensions of an AccessBinding grant/revoke. The repo serialises Actor /
// Subject / Resource / RoleID / BindingID into the audit_outbox.event_payload
// jsonb and scopes the row to TenantAccountID for per-account audit queries.
//
// Kept in the repo-iface package (like RelationTuple / SubjectChangeEvent) so
// the use-case does not import a transport/pg type to build the event.
type AuditEvent struct {
	// EventType — granted or revoked (see AuditEventType constants).
	EventType AuditEventType
	// Actor — the principal that performed the action (granted_by on grant,
	// revoked_by — falling back to granted_by — on revoke). Empty when the
	// caller identity is unknown (recorded as "" rather than fabricated).
	Actor string
	// SubjectType / SubjectID — who the access was granted to/revoked from.
	SubjectType string
	SubjectID   string
	// ResourceType / ResourceID — what the access is/was on.
	ResourceType string
	ResourceID   string
	// RoleID — the role whose permissions were granted/revoked.
	RoleID string
	// BindingID — id of the AccessBinding row (ties the audit event to the row).
	BindingID string
	// TenantAccountID — Account scope for per-account audit queries; optional
	// (NULL in audit_outbox.tenant_account_id when empty).
	TenantAccountID string
	// ExtraPayload — optional event-specific fields merged into the
	// event_payload jsonb on top of the canonical dimensions (actor / subject /
	// resource / role_id / binding_id). Used by events that carry a material
	// before/after diff — e.g. selector_replaced emits old_selector/new_selector.
	// Keys here override the canonical ones on collision (so a specialised event
	// stays in full control of its payload shape).
	ExtraPayload map[string]any
}

// RelationTuple — minimal payload shape for fga_outbox emit. Kept here (in the
// repo-iface package) so the service-layer use-case does NOT need to import
// internal/clients just to build a tuple list.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

// SubjectChangeEvent — payload for EmitSubjectChangeEvent + drainer Decoder.
// Mirrors the JSON shape stored in subject_change_outbox.payload column.
type SubjectChangeEvent struct {
	// SubjectID — raw (unprefixed) FGA subject id (e.g. "usr_alice",
	// "sva_bot", "grp_admins"). The drainer applier maps to FGA-prefixed
	// form; читателем журнала является КРАЙ, открывающий чтение сам (задача #1024).
	SubjectID string `json:"subject_id"`

	// SubjectType — FGA object type of the subject: user | service_account |
	// group (domain.SubjectType, which IS the FGA vocabulary verbatim).
	//
	// Carried EXPLICITLY because the applier has to name the subject the way the
	// edge keys its verdict cache (`<type>:<id>`), and the producer is the only
	// place that KNOWS the type — every emit site holds it already. Deriving it
	// back out of the id is a guess, and the guess that stood here read a
	// separator that minted ids do not contain.
	SubjectType string `json:"subject_type,omitempty"`

	// EventType — canonical event tag, preferred over Op for new readers.
	// Values: binding_revoke / binding_grant / group_member_change.
	EventType string `json:"event_type"`

	// Op — legacy alias (informational; backward compat with the still-served
	// PollSubjectChanges RPC). When empty, the writer derives it from EventType.
	//
	// Must satisfy the DB CHECK subject_change_op_check, whose dictionary is the
	// union of BOTH spellings — binding_upsert / binding_delete (the op aliases
	// this field normally carries) and binding_grant / binding_revoke /
	// group_member_change (canonical event_type values, admitted because
	// deriveOpFromEventType passes an unmapped event type through to Op as-is).
	// Every value in it has a producer; jit_revoke and bg_revoke had none and
	// were retired by migration 754001.
	Op string `json:"op"`

	// Величин предмета (`resource_type`/`resource_id`) здесь НЕТ и не должно
	// быть: они стояли «подсказкой на будущее» для пообъектного сброса кэша
	// решений, которого не существует. Их не выбирала проекция чтения, не
	// выставлял контракт `PollSubjectChanges`, не читал потребитель на крае — а
	// заполняла их каждая мутация выдачи, в writer-транзакции. Сняты вместе с
	// колонками журнала (миграция 20260829124512, kacho#1462).
	//
	// Понадобится пообъектный сброс — он приведёт СВОЮ величину вместе с
	// читателем, а не за фазу до него.
}

type PageFilter struct {
	PageSize  int32
	PageToken string
}

// ListFilter — params for the unified List (redesign-2026 F11). Every predicate
// is optional; an empty predicate set lists the whole (unfiltered) page.
// ScopeType is the BARE within-service anchor kind (cluster/account/project),
// mapped from the dotted `scope=` filter value by the use-case.
//
// NB: there is deliberately NO visible-id push-down here. Per-object read
// visibility is applied by the use-case to the rows this filter RETURNS
// (internal/authzfilter), not pushed into the SQL: the only way to obtain a
// visible-id set up front is to enumerate everything visible — a question the
// external engine answered capped at 1000 objects of the type in its store with no
// continuation token, so narrowing the query by that set silently hid a tenant's own
// bindings. The engine is gone; the question stays unbounded by construction.
type ListFilter struct {
	PageSize  int32
	PageToken string
	SubjectID string // subject= (matches subject_id)
	RoleID    string // role= (matches role_id)
	ScopeType string // scope= (bare resource_type: cluster|account|project)
	ScopeID   string // scopeId= (matches resource_id)
	// AccountID — сужение до области ОДНОГО аккаунта: строки, привязанные к
	// самому аккаунту, ПЛЮС строки на каждом его проекте (задача #1737).
	//
	// Это НЕ ScopeID. ScopeID сверяется с resource_id строки, поэтому
	// `ScopeType="account"` + `ScopeID=<acct>` отдаёт привязки к САМОМУ аккаунту
	// и ни одной привязки его проектов. Здесь — фан-аут «аккаунт ⇒ его проекты»,
	// то есть охват ListByAccount, и предикат у обоих ОДИН
	// (`accountScopePredicate`), чтобы «тот же охват» было свойством кода, а не
	// совпадением двух написаний.
	//
	// Пусто ЗНАЧИТ «не сужать». Проверка формата — ответственность вызывающего и
	// стоит в use-case первым стейтментом: репозиторий негодную строку просто не
	// найдёт, а вызывающий обязан получить INVALID_ARGUMENT, а не пустую страницу.
	//
	// Применяется НЕЗАВИСИМО от Candidates. Полос, где Candidates равен nil, две
	// (администратор облака и держатель cluster-scoped выдачи), и на них
	// реализация «дописать аккаунт в сужение кандидатов» не исполнилась бы вовсе:
	// ответ остался бы на вид исправным и шире запрошенного.
	AccountID string
	// IncludeRevoked — default false hides status='REVOKED' rows (F10 soft-revoke
	// retains the row). Parity with ListByAccount/ListByRole: a revoked grant is
	// no longer a grant, so the unified read must not return it next to live ones
	// (a re-grant of the same 5-tuple would otherwise show up twice). true returns
	// the retained rows too (audit-retention read).
	IncludeRevoked bool
	// After — курсор keyset В РАЗОБРАННОМ ВИДЕ: страница начинается со строки,
	// строго следующей за (CreatedAt, ID). nil — с начала.
	//
	// Пара с PageToken взаимоисключающая по построению: одно значение выражается
	// ровно одним способом, и путь, задающий After, PageToken не задаёт.
	After *Cursor

	// Candidates — сужение НАБОРА КАНДИДАТОВ до надмножества видимого
	// вызывающему (задача #645).
	//
	// # Почему у привязки сужение шире, чем «колонка аккаунта»
	//
	// У access_bindings колонки аккаунта НЕТ: аккаунт привязки выводится из её
	// области — `resource_type='account'` даёт его прямо, `resource_type='project'`
	// через проект.
	//
	// ЗДЕСЬ СТОЯЛО «это ровно то выражение, которым пользуется ListByAccount, и
	// репозиторий переиспользует его, а не заводит второе» — и это было неверно
	// (#1737, §9 приёмки). Выражение сужения кандидатов от предиката
	// ListByAccount отличается: у него есть дизъюнкт по `id` и массив вместо
	// скаляра, потому что оно называет НАБОР аккаунтов, а не один. Комментарий,
	// противоречащий коду, — латентный дефект: следующий правит код под него.
	//
	// Переиспользование теперь есть, но у ДРУГОГО поля: фан-аут одного аккаунта
	// (`AccountID` ниже) и `ListByAccount` берут один предикат
	// `accountScopePredicate`. Это сужение — по-прежнему своё выражение, и оно
	// решает другой вопрос (см. следующий абзац).
	//
	// Набор является надмножеством видимого ПО МОДЕЛИ, и это проверяемо по её
	// тексту (`fga_model.fga`, тип `iam_access_binding`): читать привязку даёт
	// либо прямой кортеж на неё (ObjectIDs), либо `super_admin`, который выводится
	// `admin from account` / `super_admin from project` (AccountIDs — оба случая
	// сводятся к аккаунту области) либо `any_admin from cluster` (администратор
	// облака — сужения нет вовсе). Четвёртого пути к чтению у типа нет.
	//
	// nil ЗНАЧИТ «не сужать», и это НЕ то же, что пустой набор.
	//
	// Сужение НЕ решает вопрос о доступе: оно отбирает кандидатов, вердикт по
	// каждому выносит модель прав (`security.md` §«Авторизация живёт в МОДЕЛИ»).
	Candidates *visibility.PageScope
}

// Cursor — граница keyset-обхода `(created_at, id) ASC`.
type Cursor struct {
	CreatedAt time.Time
	ID        string
}

// ListByRoleFilter — params for ListByRole. IncludeRevoked
// default false (only PENDING/ACTIVE returned).
type ListByRoleFilter struct {
	PageSize       int32
	PageToken      string
	IncludeRevoked bool
}

// AccountPageFilter — params for ListByAccount.
//
// SubjectTypeFilter narrows the result to a single subject_type
// ("user" / "service_account" / "group"); empty disables the filter.
// IncludeRevoked=true returns rows with status='REVOKED' too (default false:
// only PENDING/ACTIVE).
type AccountPageFilter struct {
	PageSize          int32
	PageToken         string
	SubjectTypeFilter string
	IncludeRevoked    bool
}
