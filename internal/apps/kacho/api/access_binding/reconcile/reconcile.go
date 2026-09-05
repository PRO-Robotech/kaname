// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconcile — selector/containment reconciler.
//
// Selector membership is DYNAMIC: labels change in the owning service and arrive
// over the compute→iam RegisterResource edge into kacho_iam.resource_mirror.
// The reconciler MATERIALIZES the desired per-object set for a binding from the
// mirror (same-DB, no iam→owner peer call — keeps the graph acyclic), DIFFS
// it against the stored access_binding_target_members, and EMITS/EAGER-REVOKEs
// the per-object FGA tuples through fga_outbox — all in ONE writer-tx (ban #10).
//
// Clean Architecture: this use-case depends ONLY on the domain + the
// ReconcileStore / BindingSource ports (defined here). The pgx implementation is
// the adapter in repo/kacho/pg. No pgx/grpc here.
//
// Triggers:
//
//	(a) Create / Role.Update (rules change) — ReconcileBinding(bindingID).
//	(b) resource_mirror change (RegisterResource) — ReconcileObject(type,id) via
//	    the resource_reconcile_outbox event.
//	(c) periodic sweep — ReconcileBinding over every label-selector binding,
//	    defense-in-depth against a lost event / worker restart.
package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// BindingScope — the minimal binding facts the reconciler needs to materialize
// membership: the scope-anchor and the FGA emission inputs (subject + the role's
// ARM_LABELS selectors). Loaded by BindingSource from a binding id. The
// rules-based RBAC model has no per-binding target arm — the
// binding is thin; the only dynamic membership source is the role's ARM_LABELS
// rules (LabelSelectors).
type BindingScope struct {
	BindingID   domain.AccessBindingID
	Scope       domain.ScopeAnchor
	SubjectType string
	SubjectID   string
	RoleID      string
	// Selectors — the role's UNIFIED materializing selectors (flat explicit
	// RBAC model): ARM_ANCHOR(all) + ARM_NAMES + ARM_LABELS. When non-empty the
	// binding has dynamic per-rule membership: each selector (rule_fp) is matched
	// against the feed per its arm (all-in-scope / by-id / by-label) and
	// materialized; the per-object tuples are derived from the selector's VERBS.
	// Empty ⇒ a thin binding with no materialized members (e.g. a legacy
	// permissions-only role — its tier tuples are the binding-level Create concern,
	// not here). Binding-time scope_grant emission is removed; the reconciler is the
	// SINGLE materialization path.
	Selectors []domain.RuleSelector
	// ScopeSelfVerbs — the role's verbs that apply to the binding's OWN scope
	// resource-type: a `*.*` superuser rule OR an
	// `iam.<scopeResource>` rule. When non-empty the reconciler materializes the
	// tier (+ verb-bearing v_*) tuple ON THE SCOPE OBJECT ITSELF (the write-authz /
	// no-access-loss anchor). Empty ⇒ a content-only role grants nothing on the
	// scope anchor (its access lives on the matched content objects). Derived by the
	// adapter from role.Rules.ScopeSelfVerbs(scope.resource).
	ScopeSelfVerbs []string
	// Target — the binding's per-object least-privilege selection (redesign-2026 F8,
	// IAM-1-21). When Target.Resources is non-empty the grant is restricted to EXACTLY
	// the listed objects: the role.rules ARM_ANCHOR arm is resolved by the target ids
	// (never MatchAllInScope), every arm's matches are INTERSECTED with the target set,
	// and the scope-self anchor grant is SUPPRESSED (a per-object target never grants
	// tier on the whole scope object). AllInScope / empty ⇒ the whole-anchor grant
	// (existing behaviour — the role.rules selectors drive membership across the scope).
	// Loaded by the adapter from the persisted access_bindings.target column.
	Target domain.AccessTarget
	// Active reports whether the binding is still ACTIVE (a REVOKED/expired
	// binding is not re-materialized).
	Active bool
}

// DesiredMember — one object the reconciler decided belongs to a binding's
// membership, with the containment verdict and the FGA tuples to emit when
// ACTIVE. ObjectType is the dotted closed-table key.
//
// RuleFP attributes the desired member to the producing role.rules ARM_LABELS rule
// — its content-hash. Tuples is the per-object FGA tuple set to emit
// on an ACTIVE transition, precomputed from the rule's verbs (carried here so
// applyDiff need not re-derive). In the rules-based RBAC model there
// is no legacy selector/byName arm — every member is rule-derived.
type DesiredMember struct {
	RuleFP     string
	ObjectType string
	ObjectID   string
	Status     domain.VerificationStatus
	Tuples     []domain.MembershipTuple
}

// EmittedTupleRef — одна запись реестра выданных кортежей вместе с выдачей, которая её
// породила. Нужна затем, чтобы весь веер прохода записывался ОДНИМ обращением: реестр
// ключуется по (выдача, субъект, отношение, объект), поэтому идентификатор выдачи обязан
// ехать вместе с кортежем, а не быть общим параметром вызова.
type EmittedTupleRef struct {
	BindingID domain.AccessBindingID
	Tuple     domain.MembershipTuple
}

// ReconcileStore — the tx-scoped port the reconciler drives. Every method runs
// inside the single writer-tx the implementation opens for one reconcile pass,
// so the membership writes + FGA tuple emits + containment audit all commit
// together or roll back together (ban #10). The implementation is the pg
// adapter. NOTE: reconcile commits its OWN tx; the resource_reconcile_outbox
// event is marked sent in a SEPARATE short tx by the worker after this commit
// (at-least-once, redelivery safe — the reconcile diff is idempotent), NOT in
// this tx.
type ReconcileStore interface {
	// AcquireBindingLock takes pg_advisory_xact_lock(hashtext(binding_id)) on the
	// reconcile writer-tx. It is the FIRST statement
	// of a per-binding reconcile so concurrent passes of the SAME binding serialize
	// on the xact-scoped lock (released automatically on commit/rollback — never
	// pool-scoped). This makes the concurrent integration assertion
	// deterministic and, together with the LoadBinding `SELECT … FOR NO KEY UPDATE`
	// row lock + the ledger partial-UNIQUE backstop, guarantees exactly-once
	// materialization under N replicas.
	//
	// SHARE-режима у этого порта НЕТ и он не нужен: аддитивный форвард не берёт
	// advisory вовсе (reconcile/forward.go, «LOCK CHOICE»). Прежний
	// AcquireBindingLockShared существовал ради одного — развести дочерние вставки
	// форварда с `FOR UPDATE` полного прохода; режим строки ослаблен до
	// `FOR NO KEY UPDATE`, конфликта нет, и метод снят, чтобы ожидание не завелось
	// обратно «по аналогии».
	AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error

	// LoadBinding loads the minimal scope/selector/role facts for a binding.
	// ok=false when the binding no longer exists (deleted — the reconciler then
	// does nothing; the CASCADE already dropped its members).
	//
	// The implementation takes a `SELECT … FOR UPDATE` row-lock on the binding row so
	// two concurrent FULL reconcile passes of the same binding serialize (the delete-
	// stale diff must not race). The forward fast-path does NOT use this — see
	// LoadBindingUnlocked.
	LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingUnlocked loads the SAME BindingScope facts as LoadBinding but WITHOUT
	// the `FOR UPDATE` row-lock (and the forward fast-path additionally skips the
	// advisory lock). It is the read the ADDITIVE forward path (ReconcileObjectForward)
	// uses: because that path only ADDS the freshly-registered object's tuples (never a
	// delete-stale diff), it needs no serialization against a concurrent pass of the
	// same binding, so it must not take the binding row-lock that would re-serialize all
	// registrations sharing one editor/owner binding (the throughput bottleneck this
	// fast-path removes). ok=false when the binding no longer exists.
	LoadBindingUnlocked(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// LoadBindingsUnlocked — то же чтение, что LoadBindingUnlocked, но для ЦЕЛОГО НАБОРА
	// выдач за фиксированное число обращений к базе (не по два на выдачу).
	//
	// Веер материализации адресуется числом ВЫДАЧ, покрывающих область объекта, а не
	// числом объектов: меняется один объект, а кандидатов у него столько, сколько выдач
	// его области. Перепись по дереву выдач (8267 объектов зеркала) дала p50 = 9
	// кандидатов, p95 = 19, p99 = 226, максимум 227, поэтому поштучное чтение делало
	// хвост в 454 последовательных обращения внутри одной транзакции.
	//
	// Контракт: выдача, которой в базе нет (удалена), в карте ОТСУТСТВУЕТ — ровно как
	// ok=false у одиночного чтения; роль, удалённая из-под выдачи, даёт «нет покрытия»
	// (пустые селекторы), а не ошибку. Блокировок не берёт — путь аддитивен.
	LoadBindingsUnlocked(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]BindingScope, error)

	// MatchSelector returns the MIRROR objects matching a selector's
	// types+matchLabels (labels @> matchLabels) — the consumer-owned feed
	// (compute/vpc/nlb, FeedMirror). Used to compute the desired set on a
	// ReconcileBinding pass.
	MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// MatchAllInScope returns the mirror objects of the given types (ARM_ANCHOR /
	// `all` — no label filter) NARROWED to the binding's containment `scope`. The scope
	// is pushed into the SQL as a PROVEN SUPERSET of the reconciler's IsContainedIn
	// re-verify (which STILL runs — the SQL only PRE-filters), so the reconciler receives
	// O(scope) rows instead of O(cluster mirror). The consumer-owned feed (FeedMirror).
	// `types` contains ONLY mirror-fed types (the reconciler partitions by feed-source
	// before calling).
	MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)

	// MatchByIDs returns the mirror objects of the given types whose object_id is in
	// `ids` (ARM_NAMES — exact-id selector). An id not
	// (yet) in the mirror is simply absent (PENDING until its RegisterResource lands,
	// then the forward path picks it up). The consumer-owned feed (FeedMirror).
	MatchByIDs(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchAllInScopeIAMDirect / MatchByIDsIAMDirect are the iam-direct
	// analogues for IAM's OWN objects (iam.project / iam.account + content) read SAME-DB
	// from the native tables. `types` contains ONLY iam-direct types. MatchAllInScopeIAMDirect
	// pushes the binding's containment `scope` into the SQL as a PROVEN SUPERSET of the
	// IsContainedIn re-verify (same as MatchAllInScope); MatchByIDsIAMDirect (names arm) stays
	// unscoped — a foreign-scope id-match is a wanted REJECTED-containment audit signal.
	MatchAllInScopeIAMDirect(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error)
	MatchByIDsIAMDirect(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchIAMDirect returns IAM's OWN objects matching a selector's
	// types+matchLabels read SAME-DB from the native tables (FeedIAMDirect —
	// iam.project/iam.account). The returned MirrorObject carries the iam-hierarchy
	// parent (project→its account_id; account→its own id) so the SAME
	// IsContainedIn predicate decides containment. iam-direct objects are always
	// in their source table, so they are never PENDING. `types` here contains ONLY
	// iam-direct types (the reconciler partitions by feed-source before calling).
	MatchIAMDirect(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// GetMirrorObject returns the mirror row for one object (containment verify of
	// a specific member on a mirror-change event / byName ref). ok=false ⇒ not in
	// mirror ⇒ PENDING_VERIFICATION.
	GetMirrorObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)

	// GetIAMDirectObject returns the same-DB own-table projection (containment
	// parents + labels) of ONE iam-native object (iam.project / iam.account + the
	// content types user/serviceAccount/group/role/accessBinding). It is the
	// iam-direct analogue of GetMirrorObject, used by the ADDITIVE forward fast-path
	// for a brand-new iam-direct object — which lives in ITS OWN table, never the
	// mirror. The projection stamps the SAME containment parents (parentAccount /
	// parentProject) and labels the iam-direct match queries produce, so the shared
	// per-object verdict (IsContainedIn / selectorMatchesObject / desiredMemberForObject)
	// decides identically to the FULL path. ok=false when the type is not iam-direct
	// or the row does not exist. Never PENDING (an iam object is in its own table the
	// instant it exists) — same-DB read, no peer call (graph stays acyclic).
	GetIAMDirectObject(ctx context.Context, objectType, objectID string) (domain.MirrorObject, bool, error)

	// CurrentMembers returns the materialized members of a binding (the diff base) —
	// the WHOLE-binding read, used only by the binding-triggered passes (ReconcileBinding
	// / ExpireBinding / sweep), whose desired set genuinely spans the whole scope.
	CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error)

	// CurrentMembersForObject returns the materialized members of ONE binding on ONE
	// object — the NARROW diff base of the object-triggered pass (ReconcileObject). A
	// mirror upsert/delete changes exactly one object, so only that object's members can
	// change; reading the binding's WHOLE member set for it is the O(mirror) recompute
	// (the two hottest measured bindings carry 10 140 members each). Indexed by the
	// members' (binding_id, object_type, object_id) key.
	CurrentMembersForObject(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string) ([]domain.TargetMember, error)

	// BindingsForObject returns binding ids that have a member referencing the
	// object (used to fan a mirror-change event out to affected bindings).
	BindingsForObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// SelectorBindingsMatchingObject returns ACTIVE selector-binding ids whose
	// selector NOW matches the given mirror object (objectType ∈ selector.types
	// AND mirror.labels @> selector.match_labels) — INCLUDING bindings that do
	// NOT yet have a member row for it. This is the fast-path that lets a brand-
	// new matching object be picked up on the mirror-change event (≤2s) instead
	// of waiting for the periodic sweep. Same-DB read of the
	// selector spec + mirror labels (no peer call — graph stays acyclic).
	SelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// IAMDirectSelectorBindingsMatchingObject is the iam-direct analogue of
	// SelectorBindingsMatchingObject: ACTIVE selector-binding ids whose selector
	// NOW matches the given IAM-OWN object (objectType ∈ selector.types AND the
	// object's OWN-TABLE labels @> selector.match_labels), INCLUDING bindings with
	// no member row yet. Used by the Q2 trigger (Project/Account.Update labels) to
	// pick up a freshly-matching iam-direct object on the label-change event. Same-
	// DB read (own table), no mirror, no peer-call.
	IAMDirectSelectorBindingsMatchingObject(ctx context.Context, objectType, objectID string) ([]domain.AccessBindingID, error)

	// UpsertMember / DeleteMember materialize/remove a membership row. The member
	// is keyed by the FULL rule coordinate (binding, role-via-binding, rule_fp,
	// object) — so the SAME object under two rules is two rows and a
	// removed rule deletes ONLY its row.
	UpsertMember(ctx context.Context, m domain.TargetMember) error
	DeleteMember(ctx context.Context, bindingID domain.AccessBindingID, ruleFP, objectType, objectID string) error

	// LedgerTuplesForObject reads the recorded emitted tuples for one object of a
	// binding (access_binding_emitted_tuples WHERE binding_id=… AND object=…). Used
	// to eager-revoke a role.rules member whose rule was removed: the rule's verbs
	// are gone so the tuples cannot be re-derived — they are revoked from the SAVED
	// ledger set (revoke the saved tuple-set, do not re-derive).
	LedgerTuplesForObject(ctx context.Context, bindingID domain.AccessBindingID, object string) ([]domain.MembershipTuple, error)

	// TuplesStillClaimedByOtherBindings returns the SUBSET of `tuples` still recorded
	// in the emitted-tuple ledger of an ACTIVE binding OTHER than excludeBinding (same
	// subject — the tuples carry the subject as fga_user, so a different binding of a
	// different subject cannot match). The emitted-tuple ledger PK is keyed PER BINDING
	// (binding_id, fga_user, relation, object — migration 0024), so two bindings of the
	// SAME subject that materialize the IDENTICAL FGA tuple on the SAME object hold TWO
	// ledger rows for ONE non-refcounted tuple. The eager-revoke of one binding's
	// member must NOT delete a tuple another active binding still claims (the cross-binding
	// shared-tuple class). The reconciler subtracts this set
	// before emitting a tuple-delete, so the shared tuple is revoked only when the LAST
	// owning binding releases it. The query joins against access_bindings to require the
	// other binding be ACTIVE (a REVOKED other binding does not keep a tuple alive).
	TuplesStillClaimedByOtherBindings(ctx context.Context, excludeBinding domain.AccessBindingID, tuples []domain.MembershipTuple) (map[domain.MembershipTuple]struct{}, error)

	// EmitTupleWrite / EmitTupleDelete enqueue the per-object FGA tuples (+ the
	// scope hierarchy parent-pointer is the binding-lifecycle concern handled at
	// Create/Delete, NOT per member) into fga_outbox on the tx.
	EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error
	EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error

	// RecordEmittedTuples / ForgetEmittedTuples co-commit the per-member FGA tuples
	// into the persisted emitted-tuple ledger (access_binding_emitted_tuples)
	// in the SAME reconcile writer-tx as the matching EmitTupleWrite /
	// EmitTupleDelete (ban #10). The ledger is the authoritative "what was emitted"
	// set the symmetric revoke (delete.go) replays and the Role.Update reconcile
	// fan-out diffs against — UNIFYING the selector arm's per-member tuples with the
	// all_in_scope / resources[] arms' tuples already in the ledger. Without this the
	// selector member-tuples were emitted to fga_outbox but never recorded, so the
	// revoke orphaned them and a role tier change never reconciled them.
	// RecordEmittedTuples is INSERT … ON CONFLICT DO UPDATE SET source='member' (idempotent re-emit);
	// ForgetEmittedTuples removes exactly the supplied member rows (eager-revoke /
	// fell-out). A deleted binding's rows are dropped by the FK ON DELETE CASCADE.
	RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error

	// UpsertMembers / RecordEmittedTuplesBatch — те же записи, что UpsertMember и
	// RecordEmittedTuples, но НАБОРОМ и за фиксированное число обращений к базе, каким
	// бы ни был размер веера. Аддитивный форвард материализует по строке члена и по
	// записи реестра на КАЖДУЮ совпавшую выдачу, поэтому поштучная запись делала
	// стоимость прохода линейной по числу выдач области (p50 = 9 кандидатов, хвост 227
	// по дереву выдач) — при том что изменился ровно один объект.
	//
	// Семантика сохраняется дословно: тот же ON CONFLICT, та же идемпотентность повтора,
	// тот же порядок строк (а на порядке id очереди держится поголовный FIFO партиции —
	// выдача и отзыв одного ключа НЕ коммутативны). Пустой набор — no-op.
	UpsertMembers(ctx context.Context, members []domain.TargetMember) error
	RecordEmittedTuplesBatch(ctx context.Context, refs []EmittedTupleRef) error
	ForgetEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error

	// EmitContainmentAudit writes the "rejected: not contained in scope" audit
	// event (not silent) on the tx.
	EmitContainmentAudit(ctx context.Context, bindingID domain.AccessBindingID, objectType, objectID string, scope domain.ScopeAnchor) error

	// RevokeExpiredBinding atomically CAS-transitions an ACTIVE binding to REVOKED
	// (`UPDATE … WHERE status='ACTIVE' AND id=$id`, ban #10 — not TOCTOU). ok=false
	// when 0 rows updated (already revoked / concurrent Delete won). Used by the
	// expiry eager-revoke pass; the per-object tuple revokes are emitted
	// separately by the caller via the ACTIVE members it loaded.
	RevokeExpiredBinding(ctx context.Context, bindingID domain.AccessBindingID) (ok bool, err error)
}

// ExpiredBindingSource lists bindings whose TTL has elapsed (expiry scan,
// index (status, expires_at)). Pool-scoped (the scan reads outside the per-binding
// revoke tx); each id is then revoked in its own writer-tx via ExpireBinding.
type ExpiredBindingSource interface {
	ListExpiredBindingIDs(ctx context.Context) ([]domain.AccessBindingID, error)
}

// TxRunner runs fn inside a single writer-tx, committing on success and rolling
// back on error/panic. The reconciler's whole pass is one atomic unit.
type TxRunner interface {
	WithTx(ctx context.Context, fn func(ctx context.Context, s ReconcileStore) error) error
}

// Reconciler — the selector/containment reconciler use-case.
type Reconciler struct {
	tx     TxRunner
	logger *slog.Logger
	// cat — источник КАТАЛОЖНОГО ФАКТА: какие глаголы объявлены живым типом.
	//
	// Обязателен, а не опционален, как `size` ниже: без него проход не может
	// вычислить ни одного кортежа, и незаполненное поле дало бы не «наблюдение
	// выключено», а «выдача не материализуется» — тихо и целиком.
	cat catalog.Source
	// size — OPTIONAL recorder of how big one binding's materialization is. nil ⇒ the
	// observation is a no-op; the pass itself does not depend on it.
	size SizeRecorder
}

// SizeRecorder receives the SIZE of one binding's desired set: how many objects its
// selectors matched, and how many tuples those objects produce.
//
// A grant below the three cascading levels expands PER OBJECT, so its cost is «matched
// objects × the verbs of the rule». Nothing counted that expansion, which left «this
// grant grew large» indistinguishable from «this grant is ordinary» — and the
// difference surfaces not where the grant is issued but later, on somebody else's
// request, along a path that never mentions the binding. No ceiling is enforced here:
// the reachable size has not been measured, and a limit chosen before the measurement
// either refuses legitimate grants or refuses nothing while looking like a control.
type SizeRecorder interface {
	ObserveBindingMaterialization(objects, tuples int)
}

// SyncFGATuple — одна тройка набора, собираемого проходом реконсайлера.
//
// Имя историческое и оставлено намеренно: тип пересекает границу пакета, а
// переименование ради красоты стоило бы правки вызывающих без единого изменения
// свойства. Адресат у набора теперь один — вычитание переживших выдач в базе.
type SyncFGATuple struct {
	User     string
	Relation string
	Object   string
}

// ПРЯМОГО ПИСАТЕЛЯ В ЧУЖОЕ ХРАНИЛИЩЕ У РЕКОНСАЙЛЕРА БОЛЬШЕ НЕТ.
//
// Он применял вычисленный набор ПОСЛЕ коммита, чтобы закрыть окно между коммитом
// и дренажом очереди. Окна нет: прямой факт складывается из строки журнала
// триггером, в той же транзакции, — то есть материализация стала тождеством
// коммита, и догонять её нечем.
//
// Сбор набора (`syncFGACollector`) ОСТАЛСЯ и остался не по инерции: вычитание
// переживших выдач при снятии («кортеж, который держит другая действующая
// выдача, не снимается») делается его же данными и делается в базе.

// New constructs the reconciler.
//
// `cat` — источник каталожного факта; параметр ОБЯЗАТЕЛЬНЫЙ (см. поле `cat`).
func New(tx TxRunner, logger *slog.Logger, cat catalog.Source) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{tx: tx, logger: logger, cat: cat}
}

// WithSizeRecorder wires the OPTIONAL materialization-size recorder. nil-safe: an
// unwired recorder leaves the pass byte-identical, it only stops being measured.
func (r *Reconciler) WithSizeRecorder(rec SizeRecorder) *Reconciler {
	r.size = rec
	return r
}

// observeSize reports the size of a binding's desired set. Objects are counted as
// DISTINCT (type, id): the same object matched by two rules of one role is two members
// but ONE object, and counting members instead would inflate the object figure by the
// rule count, which the tuple figure already carries.
//
// A pass that matched nothing is reported as zero rather than skipped — a selector that
// stopped matching would otherwise look exactly like a binding nobody reconciles.
func (r *Reconciler) observeSize(desired []DesiredMember) {
	if r.size == nil {
		return
	}
	objects := make(map[string]struct{}, len(desired))
	tuples := 0
	for _, d := range desired {
		objects[d.ObjectType+":"+d.ObjectID] = struct{}{}
		tuples += len(d.Tuples)
	}
	r.size.ObserveBindingMaterialization(len(objects), tuples)
}

// syncFGACollector accumulates, across a single reconcile pass, the per-object tuples a
// reconcileBinding emitted to fga_outbox for ACTIVE members. NOTHING is applied anywhere
// after the pass commits — see the note above SyncFGATuple: the direct fact is folded out
// of the journal row by a trigger, inside the same transaction. What the collector is
// still FOR is the subtraction at the end of the pass: flushDeletes must not strip a
// tuple this very pass re-wrote. A nil collector de-duplicates nothing and the collect
// calls degrade to cheap pass-throughs. Not concurrency-shared: one collector per WithTx
// pass, and a pass runs single-goroutine under the per-binding advisory lock.
type syncFGACollector struct {
	// seen — что ЭТОТ проход уже записал. Единственный носитель, ради которого
	// сбор и существует: вычитание в конце прохода.
	//
	// Рядом лежали два накопителя — записанное и снятое, — и оба уезжали
	// пост-коммитным применителем в чужое хранилище. Применителя нет (стадия S6,
	// эпик #747), и накопители сняты вместе с ним: срез, который заполняют и
	// никогда не читают, снаружи неотличим от работающего механизма.
	seen map[SyncFGATuple]struct{}
	// pendingDeletes — the per-binding FGA tuple-deletes the pass wants to emit,
	// DEFERRED to the end of the pass (flushDeletes) so the cross-binding
	// shared-tuple subtraction can run against the FULL pass write-set + the
	// other-active-bindings ledger regardless of the order bindings reconcile in.
	// A binding that loses a member (label swap / rule removal) collects its
	// would-be-deletes here; flushDeletes emits only the tuples NO surviving claim
	// (in-pass write OR another active binding's ledger) keeps alive. Without the
	// deferral a binding revoked BEFORE its sibling binding writes the identical
	// tuple would strip a still-valid cross-binding tuple.
	pendingDeletes []pendingDelete
}

// pendingDelete — one binding's deferred tuple-delete request (the eager-revoke
// already forgot the tuple from THIS binding's ledger inline; only the
// cross-binding-sensitive FGA delete is deferred).
type pendingDelete struct {
	binding domain.AccessBindingID
	tuples  []domain.MembershipTuple
}

// deferDelete records a binding's would-be tuple-deletes for the end-of-pass flush.
func (c *syncFGACollector) deferDelete(binding domain.AccessBindingID, tuples []domain.MembershipTuple) {
	if c == nil || len(tuples) == 0 {
		return
	}
	c.pendingDeletes = append(c.pendingDeletes, pendingDelete{binding: binding, tuples: tuples})
}

// collectNew records a member's ACTIVE-emit tuples DE-DUPLICATED across the whole pass
// and returns exactly the subset NOT already emitted in this pass — the set the caller
// must enqueue into fga_outbox.
//
// One reconcile pass (ReconcileObject fanning over many bindings, or the scope-self
// member plus a `*.*` content member that both target account:<X>, or two rules of one
// binding whose verb sets overlap) derives the SAME tuple more than once. The de-dup used
// to be mandatory for a second reason as well — the external engine's batch write refused
// a whole request that carried a duplicate — and that reason went away with the engine.
//
// What remains is producer cost, and it is enough on its own: a second fga_outbox row for
// a tuple this very transaction already enqueued buys nothing, because both rows fold
// into the same direct fact. The measured stand showed 27 outbox
// rows for 21 distinct tuples in a single pass — 2.2 rows per distinct tuple table-wide.
// The de-dup is strictly PER-PASS (per writer-tx) and keyed on the tuple, so it can never
// collapse a grant → revoke → grant sequence: those are three separate passes, each with
// its own collector, and the revoke in between clears the member row and the ledger.
//
// The per-binding LEDGER write is deliberately NOT de-duplicated by this set: the ledger
// PK is (binding_id, fga_user, relation, object), so two bindings claiming the identical
// tuple must each keep their OWN row — that is what makes the cross-binding revoke
// subtraction (TuplesStillClaimedByOtherBindings) correct.
//
// A nil collector (sync-FGA unwired) de-duplicates nothing and returns the input as-is.
func (c *syncFGACollector) collectNew(tuples []domain.MembershipTuple) []domain.MembershipTuple {
	if c == nil {
		return tuples
	}
	if c.seen == nil {
		c.seen = make(map[SyncFGATuple]struct{})
	}
	fresh := tuples[:0:0]
	for _, t := range tuples {
		st := SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}
		if _, dup := c.seen[st]; dup {
			continue
		}
		c.seen[st] = struct{}{}
		fresh = append(fresh, t)
	}
	return fresh
}

// flushDeletes emits the pass's DEFERRED tuple-deletes inside the writer-tx, AFTER
// every binding in the pass has reconciled (so the full pass write-set is known and
// every active binding's emitted-tuple ledger row is committed-in-tx). For each
// pending delete it subtracts (a) tuples WRITTEN by any member in THIS pass (a sibling
// binding re-materialized the identical tuple — col.seen) and (b) tuples still recorded
// in the ledger of an ACTIVE binding OTHER than the revoking one (cross-binding shared
// claim — TuplesStillClaimedByOtherBindings). The remainder — tuples no surviving claim
// keeps alive — is the only set safe to delete from the non-refcounted rights state.
// This makes the cross-binding shared-tuple revoke order-independent: a binding
// revoked before its sibling writes the same tuple no longer
// strips it. The per-binding ledger ForgetEmittedTuples already ran inline at revoke
// time (that bookkeeping is binding-local and correct); only the global FGA delete is
// gated here.
func (r *Reconciler) flushDeletes(ctx context.Context, s ReconcileStore, c *syncFGACollector) error {
	if c == nil || len(c.pendingDeletes) == 0 {
		return nil
	}
	for _, pd := range c.pendingDeletes {
		// Candidate tuples not re-written in this pass (a sibling binding's emit keeps
		// the live tuple — never delete what was just (re)written).
		var notRewritten []domain.MembershipTuple
		for _, t := range pd.tuples {
			if _, written := c.seen[SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}]; written {
				continue
			}
			notRewritten = append(notRewritten, t)
		}
		if len(notRewritten) == 0 {
			continue
		}
		// Subtract tuples still claimed by an OTHER active binding's ledger (a binding
		// not reconciled in this pass, or one whose member stayed ACTIVE unchanged).
		claimed, err := s.TuplesStillClaimedByOtherBindings(ctx, pd.binding, notRewritten)
		if err != nil {
			return fmt.Errorf("flush deletes: still-claimed lookup for %s: %w", pd.binding, err)
		}
		revoke := notRewritten[:0:0]
		for _, t := range notRewritten {
			if _, stillClaimed := claimed[t]; stillClaimed {
				continue
			}
			revoke = append(revoke, t)
		}
		if len(revoke) == 0 {
			continue
		}
		if err := s.EmitTupleDelete(ctx, revoke); err != nil {
			return fmt.Errorf("flush deletes: emit tuple delete for %s: %w", pd.binding, err)
		}
	}
	return nil
}

// ReconcileBinding recomputes the full desired membership of one binding from the
// mirror and diffs it against the materialized set (trigger (a) + sweep (c)).
func (r *Reconciler) ReconcileBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := r.reconcileBinding(ctx, s, bindingID, col); err != nil {
			return err
		}
		// Flush the deferred tuple-deletes with the cross-binding surviving-claims
		// subtraction (a tuple another active binding still holds is not stripped).
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// После коммита не применяется НИЧЕГО: откат выше возвращает управление раньше,
	// а прямой факт складывается из строки журнала триггером в той же транзакции —
	// значит незакоммиченный diff не материализуется by construction.
	return nil
}

// ReconcileObject re-evaluates every binding that has a member referencing the
// changed object (trigger (b) — a resource_mirror upsert/delete). For each such
// binding it re-derives THAT OBJECT's membership and diffs it against THAT OBJECT's
// materialized members, so a label flip or a parent change is reflected — including
// the delete-stale revoke and the PENDING→ACTIVE/REJECTED transition.
//
// COST — the pass is O(1) in the binding's scope size (the producer-cost fix). The
// event carries exactly ONE changed object, so exactly one object's membership can
// change; the pass therefore re-derives only that object's desired members
// (desiredMembersForObject) and reads only that object's current members
// (CurrentMembersForObject). It previously ran reconcileBinding — a FULL O(scope)
// desired recompute (MatchAllInScope over every mirror object of the scope) plus the
// binding's WHOLE materialized member set — for each fanned-out binding. Measured on
// the stand: the two hottest bindings carry 10 140 members each over a 10 132-object
// account and one object change fans out to 3.2 bindings on average, so a single
// re-register or label update read ~64 000 rows while holding the per-binding
// EXCLUSIVE advisory lock that every sibling registration in that account queues
// behind. That is what pushed grant materialisation past the clients' retry budgets
// under load.
//
// WHY NARROWING IS EXACT, not an approximation:
//
//   - Members are keyed BY OBJECT (binding, rule_fp, object_type, object_id), so a
//     change to object X cannot add, remove or re-status a member on object Y. The
//     desired verdict for X is derived by desiredMemberForObject — the SAME per-object
//     decision point the full recompute uses — so the two paths stay byte-identical.
//   - The within-binding survivingClaims subtraction (applyDiff) only ever involves
//     members that SHARE a ledger row, and the ledger PK is
//     (binding_id, fga_user, relation, object): a shared row implies the SAME object.
//     Restricting the desired set to one object therefore computes exactly the same
//     subtraction the full set would have.
//   - The CROSS-binding subtraction (flushDeletes → TuplesStillClaimedByOtherBindings)
//     reads the ledger directly and does not consult the desired set at all, so it is
//     unaffected by the narrowing.
//   - The fan-out itself was ALREADY object-narrowed (BindingsForObject ∪
//     SelectorBindingsMatchingObject) — only the per-binding recompute inside it was not.
//
// The binding-triggered passes (ReconcileBinding, ExpireBinding, the periodic sweep)
// keep the FULL O(scope) recompute: there the binding's role/selectors/scope changed,
// so the whole desired set genuinely has to be re-derived. They also remain the
// at-least-once backstop that re-converges anything an object pass could have missed.
func (r *Reconciler) ReconcileObject(ctx context.Context, objectType, objectID string) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		// (1) Bindings that ALREADY have a member row referencing the object — a
		// label flip / parent change / object-left-the-mirror is reflected by the
		// full recompute below.
		existing, err := s.BindingsForObject(ctx, objectType, objectID)
		if err != nil {
			return fmt.Errorf("bindings for object %s:%s: %w", objectType, objectID, err)
		}
		// (2) FAST-PATH: selector-bindings whose selector NOW
		// matches the object but which do NOT yet have a member row for it (a
		// brand-new matching object). Without this, a just-arrived object only
		// gets access on the next periodic sweep (≤30s lag); with it, the change
		// event materializes membership within ~2s. The sweep remains as defense-
		// in-depth. The match source is per feed-source: mirror-fed
		// objects probe resource_mirror; iam-direct objects (Project/Account
		// label change) probe the OWN table.
		var matching []domain.AccessBindingID
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			matching, err = s.IAMDirectSelectorBindingsMatchingObject(ctx, objectType, objectID)
		} else {
			matching, err = s.SelectorBindingsMatchingObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("selector bindings matching object %s:%s: %w", objectType, objectID, err)
		}
		// The changed object's projection, read ONCE for the whole fan-out (every
		// binding diffs the same object). Absent from its source — a mirror DELETE, or
		// an iam row that raced a delete — leaves an EMPTY desired set for every
		// binding, which is exactly what drives the delete-stale revoke below.
		var obj domain.MirrorObject
		objPresent := false
		if domain.FeedSourceForType(objectType) == domain.FeedIAMDirect {
			obj, objPresent, err = s.GetIAMDirectObject(ctx, objectType, objectID)
		} else {
			obj, objPresent, err = s.GetMirrorObject(ctx, objectType, objectID)
		}
		if err != nil {
			return fmt.Errorf("get object %s:%s: %w", objectType, objectID, err)
		}

		// Fan out over the de-duplicated union; the per-binding pass is an idempotent
		// diff of THIS OBJECT's membership, so reconciling a binding once is enough
		// regardless of which source it came from.
		//
		// DEADLOCK-CLASS: each reconcileBindingForObject takes
		// pg_advisory_xact_lock(hashtext(binding_id)) inside the ONE writer-tx of this
		// pass. The two source queries return binding ids in NON-deterministic order,
		// so locking in arrival order lets two concurrent ReconcileObject passes (on
		// different objects with overlapping binding-sets) acquire the shared locks in
		// DIFFERENT orders → ABBA deadlock (40P01). Sorting the deduped union ASC gives
		// every pass a GLOBALLY-consistent acquisition order, which is deadlock-free.
		union := dedupSortBindingIDs(existing, matching)
		for _, bID := range union {
			if err := r.reconcileBindingForObject(ctx, s, bID, objectType, objectID, obj, objPresent, col); err != nil {
				return err
			}
		}
		// Flush the pass's deferred tuple-deletes AFTER every binding reconciled, so
		// the cross-binding surviving-claims subtraction sees the full write-set + the
		// committed-in-tx ledger of every sibling binding (order-independent).
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	// AFTER commit only.
	return nil
}

// ExpireBinding eager-revokes a TTL-expired binding: inside one
// writer-tx it eager-revokes every ACTIVE member's per-object FGA tuple, then
// CAS-transitions the binding ACTIVE→REVOKED. The CAS (ban #10) serializes with a
// concurrent Delete/Activate: if 0 rows updated (already revoked) the tuple
// revokes are still safe (idempotent at the FGA drainer) but we skip them to keep
// the pass tight. binding-level status becomes REVOKED so a subsequent Check is
// denied; the materialized member rows are removed so the reconciler does not
// re-emit.
func (r *Reconciler) ExpireBinding(ctx context.Context, bindingID domain.AccessBindingID) error {
	col := &syncFGACollector{}
	if err := r.tx.WithTx(ctx, func(ctx context.Context, s ReconcileStore) error {
		if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
			return fmt.Errorf("expire: acquire binding lock %s: %w", bindingID, err)
		}
		bs, ok, err := s.LoadBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: load binding %s: %w", bindingID, err)
		}
		if !ok || !bs.Active {
			return nil // already gone / not ACTIVE — nothing to expire (idempotent)
		}
		// CAS ACTIVE→REVOKED first: if another path already revoked it, bail out
		// without touching tuples (they were revoked by that path).
		revoked, err := s.RevokeExpiredBinding(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: cas revoke %s: %w", bindingID, err)
		}
		if !revoked {
			return nil
		}
		members, err := s.CurrentMembers(ctx, bindingID)
		if err != nil {
			return fmt.Errorf("expire: current members %s: %w", bindingID, err)
		}
		for _, m := range members {
			if m.VerificationStatus == domain.VerificationActive {
				// Read the saved ledger and DEFER the FGA delete to flushDeletes. On
				// expiry EVERY member of THIS binding is revoked, so no member of this
				// binding survives (within-binding survivingClaims empty). But ANOTHER
				// active binding of the same subject may hold the identical tuple — the
				// flush's cross-binding subtraction keeps it alive (this binding's ledger
				// rows are still forgotten inline, binding-local).
				if err := r.revokeMemberTuples(ctx, s, bs, m, nil, col); err != nil {
					return fmt.Errorf("expire: %w", err)
				}
			}
			if err := s.DeleteMember(ctx, bindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
				return fmt.Errorf("expire: delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
			}
		}
		// Flush the deferred deletes with the cross-binding surviving-claims subtraction.
		return r.flushDeletes(ctx, s, col)
	}); err != nil {
		return err
	}
	return nil
}

// reconcileBinding is the core diff. It computes the desired member set for a
// binding and reconciles it against the materialized set within the caller's tx.
func (r *Reconciler) reconcileBinding(ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID, col *syncFGACollector) error {
	// Serialize concurrent reconcile passes of the same binding on the
	// xact-scoped advisory lock BEFORE any read/write, so the exactly-once
	// materialization invariant holds under N replicas.
	if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
		return fmt.Errorf("acquire binding lock %s: %w", bindingID, err)
	}
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Deleted or no longer ACTIVE — do not re-materialize.
		return nil
	}

	desired, err := r.desiredMembers(ctx, s, bs)
	if err != nil {
		return err
	}
	// Размер материализации привязки — до диффа: величина относится к тому, что
	// привязка ТРЕБУЕТ, а не к тому, сколько строк изменилось в этом проходе.
	// Иначе повторный проход по неизменившейся привязке докладывал бы ноль, и
	// «крупная привязка» стала бы неотличима от «привязка ничего не материализует».
	r.observeSize(desired)

	current, err := s.CurrentMembers(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("current members %s: %w", bindingID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, col)
}

// reconcileBindingForObject is the OBJECT-NARROWED twin of reconcileBinding: it diffs
// ONE binding's membership ON ONE OBJECT, instead of recomputing the binding's whole
// desired set over its whole scope. It is what an object-change event (a mirror
// upsert/delete, a label UPDATE) actually needs — see the ReconcileObject doc for why
// the narrowing is exact rather than an approximation.
//
// It keeps everything the full path does per object: the EXCLUSIVE advisory lock (so a
// concurrent pass of the same binding cannot interleave with this object's delete-stale
// diff), the ACTIVE/REJECTED verdict, the containment audit, the eager-revoke of a
// member that fell out, and the deferred cross-binding delete flush. Only the SIZE of
// the diffed set changes: O(1) in the scope instead of O(scope). Because the critical
// section is now a handful of indexed rows rather than a whole-scope recompute, the
// per-binding lock every sibling registration in the account queues behind is held for
// a fraction of the time — which is the throughput property this fix is after.
//
// objPresent=false (the object left its source — a mirror DELETE) yields an EMPTY
// desired set, which drives exactly the delete-stale revoke the full path produced when
// the object stopped appearing in MatchAllInScope.
func (r *Reconciler) reconcileBindingForObject(
	ctx context.Context, s ReconcileStore, bindingID domain.AccessBindingID,
	objectType, objectID string, obj domain.MirrorObject, objPresent bool, col *syncFGACollector,
) error {
	// Serialize concurrent passes of the same binding on the xact-scoped advisory lock
	// BEFORE any read/write (exactly-once materialization under N replicas), acquired in
	// the caller's globally-sorted binding order (deadlock-free).
	if err := s.AcquireBindingLock(ctx, bindingID); err != nil {
		return fmt.Errorf("acquire binding lock %s: %w", bindingID, err)
	}
	bs, ok, err := s.LoadBinding(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("load binding %s: %w", bindingID, err)
	}
	if !ok || !bs.Active {
		// Deleted or no longer ACTIVE — do not re-materialize.
		return nil
	}

	var desired []DesiredMember
	if objPresent {
		desired = desiredMembersForObject(r.cat.Facts(), bs, obj)
	}

	// The NARROW diff base: this binding's members ON THIS OBJECT only.
	current, err := s.CurrentMembersForObject(ctx, bindingID, objectType, objectID)
	if err != nil {
		return fmt.Errorf("current members for object %s %s:%s: %w", bindingID, objectType, objectID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, col)
}

// desiredMembersForObject derives the members ONE binding wants ON ONE OBJECT. It is
// the object-narrowed equivalent of desiredMembers/desiredRuleMembers, built from the
// SAME per-object decision points those use — selectorMatchesObject (the pure-Go mirror
// of the arm-match SQL), the per-object target intersection, desiredMemberForObject (the
// containment verdict + tuple derivation) and scopeSelfMember — so the narrow and full
// paths can never drift in what an object is granted.
//
// The full path resolves a candidate SET per arm (MatchAllInScope / MatchByIDs /
// MatchSelector) and then decides per candidate; here the candidate is given, so only
// the per-candidate half runs. The three arms map exactly:
//
//	ARM_ANCHOR → type membership (the scope push-down is subsumed: the object is the
//	             one that changed, and IsContainedIn re-verifies its scope as before)
//	ARM_NAMES  → id ∈ ResourceNames
//	ARM_LABELS → labels @> matchLabels
//
// The scope-self member (the binding's tier on account:<X>/project:<X>) belongs to this
// object's desired set exactly when the changed object IS the binding's own scope anchor
// — a project/account label update reaches it through the iam-direct feed. Suppressed for
// a per-object target, matching desiredRuleMembers (granting the whole scope anchor
// contradicts a least-priv per-object grant).
func desiredMembersForObject(cat *catalog.Facts, bs BindingScope, o domain.MirrorObject) []DesiredMember {
	subject := domain.FGASubjectRef(bs.SubjectType, bs.SubjectID)
	perObject := len(bs.Target.Resources) > 0

	var out []DesiredMember
	if len(bs.ScopeSelfVerbs) > 0 && !perObject &&
		o.ObjectType == "iam."+bs.Scope.Type && o.ObjectID == bs.Scope.ID {
		if sm, ok := scopeSelfMember(cat, subject, bs.Scope.Type, bs.Scope.ID, bs.ScopeSelfVerbs); ok {
			out = append(out, sm)
		}
	}
	// Per-object target least-priv (F8, IAM-1-21): a rule may only grant an object the
	// binding's target also lists. Uniform across all arms, exactly as
	// matchSelectorObjects intersects the matched set.
	if perObject && !bs.Target.Contains(o.ObjectType, o.ObjectID) {
		return out
	}
	for _, sel := range bs.Selectors {
		if !selectorMatchesObject(sel, o) {
			continue
		}
		dm, ok := desiredMemberForObject(cat, subject, sel, o, bs.Scope)
		if !ok {
			// A type the model has no FGA object for → no tuple → skip the object
			// (fail-closed: a typo'd type never grants).
			continue
		}
		out = append(out, dm)
	}
	return out
}

// desiredMembers computes the desired member set + containment verdict for a
// binding. The flat explicit RBAC model uses the UNIFIED materializer — the only
// dynamic membership source is the role's materializing rules (ARM_ANCHOR(all) +
// ARM_NAMES + ARM_LABELS). A binding whose role carries no materializing selectors
// is thin — no materialized members (a legacy permissions-only role's tier tuples
// are the Create-time concern, not here).
func (r *Reconciler) desiredMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	if len(bs.Selectors) > 0 {
		return r.desiredRuleMembers(ctx, s, bs)
	}
	return nil, nil // thin binding — no materialized members
}

// matchSelectorObjects resolves the candidate objects for ONE selector per its arm,
// across both feeds (mirror-fed + iam-direct, partitioned): ARM_ANCHOR(all) →
// MatchAllInScope; ARM_NAMES → MatchByIDs; ARM_LABELS → MatchSelector(labels @>).
// Containment is re-asserted by the caller (IsContainedIn); this only resolves the
// candidate set. The binding's `scope` is passed to the ANCHOR arm so the candidate set
// is pushed-down to O(scope) in SQL rather than scanned cluster-wide + narrowed in Go —
// the Go re-verify remains authoritative (the SQL predicate is a proven superset).
//
// PER-OBJECT TARGET (F8, IAM-1-21): when the binding carries a per-object target
// (target.Resources non-empty), the ANCHOR arm is resolved BY the target ids
// (MatchByIDs) instead of MatchAllInScope — so a least-priv grant never scans/materializes
// the whole scope — and the matched set of EVERY arm is finally INTERSECTED with the
// target (a role rule can only grant an object the target also lists).
func (r *Reconciler) matchSelectorObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	mirrorTypes, iamTypes := partitionByFeed(sel.ObjectTypes)
	var matched []domain.MirrorObject
	if len(mirrorTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, mirrorTypes, false, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (mirror): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	if len(iamTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, iamTypes, true, s, scope, target)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (iam-direct): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	// Per-object target intersection: keep ONLY objects the target lists (uniform across
	// all arms — anchor already resolves by target ids, but names/labels may match objects
	// the target does not list, so intersect them out; least-priv, IAM-1-21).
	if len(target.Resources) > 0 {
		matched = filterMatchedToTarget(matched, target)
	}
	return matched, nil
}

// matchByArm dispatches the per-arm match to the right feed (mirror vs iam-direct). The
// ANCHOR arm passes the binding's `scope` for the SQL scope push-down; the NAMES/LABELS arms
// are already narrow (specific ids / labels) AND a foreign-scope match is a wanted
// REJECTED-containment audit signal, so they are LEFT UNSCOPED (the reconciler re-verifies).
//
// For a PER-OBJECT target the ANCHOR arm resolves the candidate set BY the target ids
// (MatchByIDs) rather than MatchAllInScope: a least-priv grant materializes only the listed
// objects, never the whole scope (IAM-1-21). The NAMES/LABELS arms keep their own narrow
// resolution and are intersected with the target by the caller (matchSelectorObjects).
func (r *Reconciler) matchByArm(ctx context.Context, sel domain.RuleSelector, types []string, iamDirect bool, s ReconcileStore, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	switch sel.Arm {
	case domain.ArmNames:
		if iamDirect {
			return s.MatchByIDsIAMDirect(ctx, types, sel.ResourceNames)
		}
		return s.MatchByIDs(ctx, types, sel.ResourceNames)
	case domain.ArmLabels:
		if iamDirect {
			return s.MatchIAMDirect(ctx, types, sel.MatchLabels)
		}
		return s.MatchSelector(ctx, types, sel.MatchLabels)
	default: // ArmAnchor (all)
		if len(target.Resources) > 0 {
			// Per-object target: resolve the anchor candidates by the target ids of these
			// types (never the whole-scope scan). Empty ⇒ no candidate of these types.
			ids := target.ResourceIDsForTypes(types)
			if len(ids) == 0 {
				return nil, nil
			}
			if iamDirect {
				return s.MatchByIDsIAMDirect(ctx, types, ids)
			}
			return s.MatchByIDs(ctx, types, ids)
		}
		if iamDirect {
			return s.MatchAllInScopeIAMDirect(ctx, types, scope)
		}
		return s.MatchAllInScope(ctx, types, scope)
	}
}

// filterMatchedToTarget keeps only the matched objects listed in a per-object target
// (exact dotted-type + id). It is the uniform intersection applied to EVERY arm when the
// binding carries a per-object target, so a role rule (anchor/names/labels) can only grant
// an object the target also lists (least-priv, IAM-1-21). Never called for an
// AllInScope/empty target (the caller gates on len(target.Resources) > 0).
func filterMatchedToTarget(matched []domain.MirrorObject, target domain.AccessTarget) []domain.MirrorObject {
	out := matched[:0:0]
	for _, o := range matched {
		if target.Contains(o.ObjectType, o.ObjectID) {
			out = append(out, o)
		}
	}
	return out
}

// desiredRuleMembers computes the desired per-rule membership for a role.rules-
// driven binding (unified materializer). For EACH materializing selector
// (rule_fp) it resolves the candidate objects per its arm, applies containment,
// and emits the per-object tuple set DERIVED FROM THE RULE'S VERBS (per-verb v_* +
// tier — the same domain helpers the prior emit path used). A matched-but-foreign
// object is REJECTED (no tuple + audit, cross-scope defence). The SAME object
// matched by two rules yields two desired members keyed by distinct rule_fp.
func (r *Reconciler) desiredRuleMembers(ctx context.Context, s ReconcileStore, bs BindingScope) ([]DesiredMember, error) {
	subject := domain.FGASubjectRef(bs.SubjectType, bs.SubjectID)
	var out []DesiredMember

	// perObject — the binding carries a per-object target (Target.Resources non-empty):
	// the grant is restricted to EXACTLY the listed objects (least-priv, IAM-1-21). The
	// scope-self anchor grant is suppressed and every selector's matches are intersected
	// with the target set below.
	perObject := len(bs.Target.Resources) > 0

	// Scope-self member: the role's tier (+ verb-bearing v_*) ON
	// THE BINDING'S OWN SCOPE OBJECT (`account:<X>`/`project:<X>`). This is the
	// write-authz / no-access-loss anchor the removed binding-time scope-anchor emit
	// produced — now materialized by the SINGLE reconciler path. It is NOT a content
	// object matched by a selector: a `*.*` superuser role has empty selector
	// ObjectTypes (wildcard skipped), so without this the subject would lose the tier
	// on the scope entirely. Keyed by
	// a sentinel rule_fp so it has its own member row + ledger lineage (symmetric
	// revoke). The cluster super-admin path short-circuits and is not materialized here.
	//
	// SUPPRESSED for a per-object target: granting the tier on the WHOLE scope object
	// (account:<X>/project:<X>) contradicts a per-object least-priv grant — the target
	// lists specific content objects, not the scope anchor. So a per-object target never
	// materializes the scope-self member (over-grant guard, IAM-1-21).
	if len(bs.ScopeSelfVerbs) > 0 && !perObject {
		if sm, ok := scopeSelfMember(r.cat.Facts(), subject, bs.Scope.Type, bs.Scope.ID, bs.ScopeSelfVerbs); ok {
			out = append(out, sm)
		}
	}

	for _, sel := range bs.Selectors {
		// Pass the binding's scope + target so the ANCHOR arm resolves the candidate set
		// per the target (by-id when per-object; O(scope) push-down otherwise), and every
		// arm's matches are intersected with the target. IsContainedIn below stays the
		// authoritative containment re-verify.
		matched, err := r.matchSelectorObjects(ctx, s, sel, bs.Scope, bs.Target)
		if err != nil {
			return nil, err
		}
		for _, o := range matched {
			// Per-object verdict — SHARED with the forward fast-path
			// (desiredMemberForObject), so the full recompute and the forward path
			// derive BYTE-IDENTICAL tuples (idempotency: forward + async full both
			// emit the same set, and the read-delta FGA writer skips duplicates).
			dm, ok := desiredMemberForObject(r.cat.Facts(), subject, sel, o, bs.Scope)
			if !ok {
				// A type the model has no FGA object for → no tuple → skip the object
				// (fail-closed: a typo'd type never grants).
				continue
			}
			out = append(out, dm)
		}
	}
	return out, nil
}

// desiredMemberForObject computes the DesiredMember a materializing selector produces
// for ONE candidate object. It is the single per-object decision point SHARED by the
// full recompute (desiredRuleMembers) and the ADDITIVE forward fast-path
// (forwardObjectForBinding), so the two paths can never drift in what tuples an object
// grants (idempotency across forward + async-backstop).
//
//   - not contained in the binding's scope (cross-scope label-tampering / foreign parent)
//     → a REJECTED member (ok=true, no tuples). The full path records it + audits; the
//     forward path skips it (additive-only never writes a non-ACTIVE member).
//   - contained → an ACTIVE member with the per-object tuples derived from the RULE's
//     verbs (v_* + back-compat tier via ruleObjectTuples). ARM_LABELS/ANCHOR rules are
//     excluded from CompileRules, so the tuples come from the rule verbs, not RolePerms.
//   - the object's type has no FGA object type → ok=false (skip; a typo'd type never
//     grants, fail-closed).
func desiredMemberForObject(cat *catalog.Facts, subject string, sel domain.RuleSelector, o domain.MirrorObject, scope domain.ScopeAnchor) (DesiredMember, bool) {
	if !o.IsContainedIn(scope) {
		return DesiredMember{
			RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
			Status: domain.VerificationRejected,
		}, true
	}
	tuples, ok := ruleObjectTuples(cat, subject, sel.Verbs, o.ObjectType, o.ObjectID)
	if !ok {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
		Status: domain.VerificationActive, Tuples: tuples,
	}, true
}

// applyDiff reconciles the desired set against the current materialized set: it
// UPSERTs members whose status changed, emits/eager-revokes the per-object FGA
// tuple on ACTIVE transitions, writes the containment audit on REJECTED, and
// removes members no longer in the desired set (eager-revoke their tuple).
func (r *Reconciler) applyDiff(ctx context.Context, s ReconcileStore, bs BindingScope, desired []DesiredMember, current []domain.TargetMember, col *syncFGACollector) error {
	// Key by (rule_fp, object): a member is attributed to the role.rules rule that
	// produced it, so the SAME object under two rules is two members
	// and a removed rule eager-revokes ONLY its members.
	currentByKey := make(map[string]domain.TargetMember, len(current))
	for _, m := range current {
		currentByKey[memberRuleKey(m.RuleFP, m.ObjectType, m.ObjectID)] = m
	}
	desiredByKey := make(map[string]struct{}, len(desired))

	// survivingClaims — the set of FGA tuples STILL claimed by a desired ACTIVE member
	// after this pass (dual-member-same-object). The ledger PK is
	// (binding_id, fga_user, relation, object) WITHOUT rule_fp, so two desired members
	// of the SAME binding that target the IDENTICAL object with IDENTICAL tuples (e.g.
	// the owner scope-self member + the wildcard-expanded iam.account content member,
	// or two ARM_LABELS rules matching the same object with the same verbs) share ONE
	// ledger row. When ONE member falls out, the eager-revoke reads that shared row
	// (LedgerTuplesForObject keys only by binding+object) and would strip the SURVIVING
	// member's access. revokeMemberTuples subtracts this set so a shared tuple is
	// revoked ONLY once the LAST owning member is gone. Built from the FULL desired set
	// computed under the per-binding advisory lock (no concurrent pass of this binding),
	// so it is race-free.
	survivingClaims := desiredActiveTupleSet(desired)

	for _, d := range desired {
		key := memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)
		desiredByKey[key] = struct{}{}
		prev, existed := currentByKey[key]
		prevStatus := domain.VerificationStatus("")
		if existed {
			prevStatus = prev.VerificationStatus
		}
		if existed && prevStatus == d.Status {
			continue // no change — idempotent
		}

		// Persist the new member status (UPSERT keyed by the full rule coordinate).
		if err := s.UpsertMember(ctx, domain.TargetMember{
			BindingID: bs.BindingID, RoleID: domain.RoleID(bs.RoleID), RuleFP: d.RuleFP,
			ObjectType: d.ObjectType, ObjectID: d.ObjectID, VerificationStatus: d.Status,
		}); err != nil {
			return fmt.Errorf("upsert member %s/%s:%s: %w", d.RuleFP, d.ObjectType, d.ObjectID, err)
		}

		// The tuple set for this member: precomputed from the producing rule's verbs
		// (d.Tuples).
		tuples, tupleOK := r.memberTuples(d)
		switch d.Status {
		case domain.VerificationActive:
			if !tupleOK {
				return fmt.Errorf("membership tuple inconsistent for %s/%s:%s (role coverage desync)", d.RuleFP, d.ObjectType, d.ObjectID)
			}
			// Enqueue ONLY the tuples this pass has not already enqueued, and record the
			// same set in the pass collector — the set the deletion subtraction below
			// reads, so a tuple re-written here is never stripped by a sibling's revoke
			// in the same pass.
			if fresh := col.collectNew(tuples); len(fresh) > 0 {
				if err := s.EmitTupleWrite(ctx, fresh); err != nil {
					return fmt.Errorf("emit tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
				}
			}
			// Co-commit the emitted member-tuple into the ledger — the
			// symmetric revoke + Role.Update reconcile both rest on it (ban #10).
			if err := s.RecordEmittedTuples(ctx, bs.BindingID, tuples); err != nil {
				return fmt.Errorf("record emitted tuple %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationRejected:
			// Was it ACTIVE before? Then eager-revoke the now-stale tuple + forget it.
			// The revoke set is the member's SAVED ledger (d.Tuples is empty for a
			// REJECTED transition), NOT d.Tuples.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
			if err := s.EmitContainmentAudit(ctx, bs.BindingID, d.ObjectType, d.ObjectID, bs.Scope); err != nil {
				return fmt.Errorf("emit containment audit %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
		case domain.VerificationPending:
			// No tuple; if it was ACTIVE before (object left the mirror), revoke + forget.
			if prevStatus == domain.VerificationActive {
				if err := r.revokeMemberTuples(ctx, s, bs, prev, survivingClaims, col); err != nil {
					return err
				}
			}
		}
	}

	// Members that fell out of the desired set entirely (rule removed / label
	// removed): eager-revoke their tuple + remove the row. The fell-out
	// member's tuple set is read from the member's recorded ledger rows
	// (revokeTuplesFor) — a removed rule's verbs are gone, so the ledger is the only
	// authority.
	for key, m := range currentByKey {
		if _, stillDesired := desiredByKey[key]; stillDesired {
			continue
		}
		if m.VerificationStatus == domain.VerificationActive {
			if err := r.revokeMemberTuples(ctx, s, bs, m, survivingClaims, col); err != nil {
				return err
			}
		}
		if err := s.DeleteMember(ctx, bs.BindingID, m.RuleFP, m.ObjectType, m.ObjectID); err != nil {
			return fmt.Errorf("delete member %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
		}
	}
	return nil
}

// memberTuples returns the FGA tuple set for a DESIRED member. In the rules-based
// RBAC model every materialized member comes from a role.rules
// ARM_LABELS rule, so its tuples were precomputed from the rule's verbs (d.Tuples).
// A member with no tuples is an unknown-FGA-type ACTIVE member the caller already
// skipped in desiredRuleMembers — treated as a coverage desync (fail-closed).
func (r *Reconciler) memberTuples(d DesiredMember) ([]domain.MembershipTuple, bool) {
	if len(d.Tuples) > 0 {
		return d.Tuples, true
	}
	return nil, false
}

// revokeMemberTuples eager-revokes the live FGA tuples of a previously-ACTIVE
// member (ACTIVE→REJECTED/PENDING transition OR a fell-out member) and forgets them
// from the ledger, in lock-step (ban #10). The revoke set is the member's SAVED
// tuple-set, read by revokeTuplesFor — NOT re-derived from a possibly-mutated role
// (a removed rule's verbs are gone, so the only authority is the ledger).
//
// survivingClaims is the set of tuples STILL claimed by a desired ACTIVE member after
// this pass. Because the ledger PK has no rule_fp, two members of the same
// binding on the SAME object with IDENTICAL tuples share ONE ledger row; revoking the
// fell-out member must NOT strip a tuple another ACTIVE member of the SAME binding still
// claims. We forget ONLY the set-difference (member's ledger MINUS survivingClaims) — a
// shared tuple is revoked exactly when the LAST owning member is gone. survivingClaims is
// nil/empty when every member is being revoked (e.g. expiry), giving the original
// behaviour.
//
// The within-binding survivingClaims handles same-binding shared tuples; the FGA
// tuple-delete itself is DEFERRED into the collector (deferDelete) and emitted at the end
// of the pass by flushDeletes, which additionally subtracts the CROSS-binding still-claimed
// set (another active binding of the same subject holds the identical tuple — the
// non-refcounted rights state must keep it alive until the LAST binding releases it).
// The ledger ForgetEmittedTuples stays inline here because it
// is binding-local bookkeeping (this binding no longer claims the tuple); only the global
// FGA delete is cross-binding-sensitive and therefore deferred.
func (r *Reconciler) revokeMemberTuples(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember, survivingClaims map[domain.MembershipTuple]struct{}, col *syncFGACollector) error {
	tuples, ok := r.revokeTuplesFor(ctx, s, bs, m)
	if !ok || len(tuples) == 0 {
		return nil
	}
	// Subtract tuples still claimed by a surviving ACTIVE member of THIS binding.
	revoke := tuples[:0:0]
	for _, t := range tuples {
		if _, claimed := survivingClaims[t]; claimed {
			continue // another ACTIVE member of this binding keeps the shared tuple alive.
		}
		revoke = append(revoke, t)
	}
	if len(revoke) == 0 {
		return nil // every tuple is still claimed within this binding — nothing to revoke.
	}
	// Defer the FGA tuple-delete to the end-of-pass flush (cross-binding subtraction).
	col.deferDelete(bs.BindingID, revoke)
	// Forget this binding's ledger rows inline (binding-local — this binding no longer
	// claims the tuple even if a sibling binding does; the sibling keeps its OWN row).
	if err := s.ForgetEmittedTuples(ctx, bs.BindingID, revoke); err != nil {
		return fmt.Errorf("forget emitted tuple %s/%s:%s: %w", m.RuleFP, m.ObjectType, m.ObjectID, err)
	}
	return nil
}

// desiredActiveTupleSet collects, into a set, every FGA tuple that a desired ACTIVE
// member will (re)emit this pass. It is the "still-claimed" set the
// eager-revoke subtracts so a tuple shared by two members on the same object is not
// stripped while one of them is still ACTIVE. Only ACTIVE desired members carry
// precomputed Tuples (REJECTED/PENDING members carry none), so they are the exact set
// of live claims after the pass.
func desiredActiveTupleSet(desired []DesiredMember) map[domain.MembershipTuple]struct{} {
	out := make(map[domain.MembershipTuple]struct{})
	for _, d := range desired {
		if d.Status != domain.VerificationActive {
			continue
		}
		for _, t := range d.Tuples {
			out[t] = struct{}{}
		}
	}
	return out
}

// revokeTuplesFor returns the FGA tuples to revoke for a member. The authoritative
// tuple-set is the SAVED ledger (access_binding_emitted_tuples) — "revoke what was
// actually emitted, do NOT re-derive from the role", because the role may have been
// mutated out from under the member: a removed/downgraded role.rules rule whose
// verbs are gone. The ledger is recorded for every member on the ACTIVE
// transition (applyDiff.RecordEmittedTuples), so it is the uniform revoke source.
// Empty ledger ⇒ nothing to revoke (the legacy-arm re-derivation fallback is gone;
// all members are role.rules-driven).
func (r *Reconciler) revokeTuplesFor(ctx context.Context, s ReconcileStore, bs BindingScope, m domain.TargetMember) ([]domain.MembershipTuple, bool) {
	// Имя типа модели читается у ЖИВЫХ строк — тем же источником, каким его
	// раскрывает желаемая сторона прохода. Промах здесь означает члена по типу,
	// чья строка каталога снята в работающем процессе: снять его кортежи нечем,
	// потому что ключ реестра эмитированного собирается из этого имени. Молча
	// это остаться не вправе — иначе выданное по снятому типу переживает снятие,
	// и об этом не говорит ни одна полоса.
	fgaType, ok := r.cat.Facts().FGAObjectType(m.ObjectType)
	if !ok {
		r.logger.WarnContext(ctx, "reconcile: member object_type has no live catalog row; its emitted tuples cannot be revoked this pass",
			"binding_id", string(bs.BindingID),
			"object_type", m.ObjectType,
			"object_id", m.ObjectID,
			"rule_fp", m.RuleFP)
		return nil, false
	}
	object := fgaType + ":" + m.ObjectID
	tuples, err := s.LedgerTuplesForObject(ctx, bs.BindingID, object)
	if err != nil {
		// Surface as "no tuples" — the DeleteMember still runs; the symmetric revoke
		// (delete.go) / a later sweep re-converges. A hard error here would roll back
		// the whole pass for a single member's ledger read. Log it (the revoke is
		// retried by a later pass, but a silently-swallowed ledger read is otherwise
		// invisible — observability).
		r.logger.WarnContext(ctx, "reconcile: ledger read for member revoke failed; deferring tuple revoke to next pass",
			"binding_id", string(bs.BindingID),
			"object", object,
			"rule_fp", m.RuleFP,
			"error", err)
		return nil, false
	}
	if len(tuples) > 0 {
		return tuples, true
	}
	return nil, false
}

// partitionByFeed splits selector types into the mirror-fed set (compute/vpc/
// nlb) and the iam-direct set (iam.project/iam.account) by the pure-domain
// feed-source classifier. Order within each partition is preserved.
func partitionByFeed(types []string) (mirror, iamDirect []string) {
	for _, t := range types {
		switch domain.FeedSourceForType(t) {
		case domain.FeedIAMDirect:
			iamDirect = append(iamDirect, t)
		default:
			mirror = append(mirror, t)
		}
	}
	return mirror, iamDirect
}

// memberRuleKey joins (ruleFP, objectType, objectID) with NUL separators — the
// member identity. The rule_fp discriminates the SAME object selected
// by two different rules (distinct members at possibly distinct tiers), so the
// diff in applyDiff revokes exactly the removed rule's members. NUL never
// occurs in a hex fingerprint / dotted type / crockford id, so the join is
// unambiguous.
func memberRuleKey(ruleFP, objectType, objectID string) string {
	return ruleFP + "\x00" + objectType + "\x00" + objectID
}

// dedupSortBindingIDs merges the fan-out source id sets into a de-duplicated,
// sorted-ASC slice. The sort gives the ReconcileObject fan-out a GLOBALLY-consistent
// advisory-lock acquisition order across concurrent passes (deadlock-class fix):
// two passes on different objects with overlapping binding-sets
// acquire the shared locks in the SAME order, so they cannot deadlock (ABBA / 40P01).
func dedupSortBindingIDs(sets ...[]domain.AccessBindingID) []domain.AccessBindingID {
	seen := make(map[domain.AccessBindingID]struct{})
	for _, set := range sets {
		for _, id := range set {
			seen[id] = struct{}{}
		}
	}
	out := make([]domain.AccessBindingID, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
