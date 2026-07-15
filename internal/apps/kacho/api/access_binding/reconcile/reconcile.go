// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
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
	// deterministic and, together with the LoadBinding `SELECT … FOR UPDATE` row
	// lock + the ledger partial-UNIQUE backstop, guarantees exactly-once
	// materialization under N replicas.
	AcquireBindingLock(ctx context.Context, bindingID domain.AccessBindingID) error

	// LoadBinding loads the minimal scope/selector/role facts for a binding.
	// ok=false when the binding no longer exists (deleted — the reconciler then
	// does nothing; the CASCADE already dropped its members).
	LoadBinding(ctx context.Context, bindingID domain.AccessBindingID) (BindingScope, bool, error)

	// MatchSelector returns the MIRROR objects matching a selector's
	// types+matchLabels (labels @> matchLabels) — the consumer-owned feed
	// (compute/vpc/nlb, FeedMirror). Used to compute the desired set on a
	// ReconcileBinding pass.
	MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error)

	// MatchAllInScope returns EVERY mirror object of the given types (ARM_ANCHOR /
	// `all` — no label filter). Containment to
	// the binding's scope is re-asserted by the reconciler (IsContainedIn) so the
	// query may over-return; the scope filter narrows it. The consumer-owned feed
	// (FeedMirror). `types` contains ONLY mirror-fed types (the reconciler partitions
	// by feed-source before calling).
	MatchAllInScope(ctx context.Context, types []string) ([]domain.MirrorObject, error)

	// MatchByIDs returns the mirror objects of the given types whose object_id is in
	// `ids` (ARM_NAMES — exact-id selector). An id not
	// (yet) in the mirror is simply absent (PENDING until its RegisterResource lands,
	// then the forward path picks it up). The consumer-owned feed (FeedMirror).
	MatchByIDs(ctx context.Context, types []string, ids []string) ([]domain.MirrorObject, error)

	// MatchAllInScopeIAMDirect / MatchByIDsIAMDirect are the iam-direct
	// analogues for IAM's OWN objects (iam.project / iam.account) read SAME-DB from
	// the native tables. `types` contains ONLY iam-direct types.
	MatchAllInScopeIAMDirect(ctx context.Context, types []string) ([]domain.MirrorObject, error)
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

	// CurrentMembers returns the materialized members of a binding (the diff base).
	CurrentMembers(ctx context.Context, bindingID domain.AccessBindingID) ([]domain.TargetMember, error)

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
	// ledger rows for ONE non-refcounted OpenFGA tuple. The eager-revoke of one binding's
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
	// RecordEmittedTuples is INSERT … ON CONFLICT DO NOTHING (idempotent re-emit);
	// ForgetEmittedTuples removes exactly the supplied member rows (eager-revoke /
	// fell-out). A deleted binding's rows are dropped by the FK ON DELETE CASCADE.
	RecordEmittedTuples(ctx context.Context, bindingID domain.AccessBindingID, tuples []domain.MembershipTuple) error
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
	// syncFGA — OPTIONAL direct OpenFGA writer. When
	// wired (WithSyncFGA), a reconcile pass collects the per-object tuples it emits to
	// fga_outbox for ACTIVE members and — AFTER the writer-tx COMMITS — synchronously
	// applies them to OpenFGA, closing the create-path read-after-write race (a Check
	// immediately after Operation-done would otherwise miss the still-undrained tuple).
	// nil ⇒ async-only (the fga_outbox drainer is the sole applier — unchanged
	// behaviour). The durable fga_outbox enqueue ALWAYS happens in the writer-tx (ban
	// #10 preserved); the sync write is purely a read-after-write closer and the later
	// async drain of the SAME rows is an idempotent no-op (WriteTuples treats
	// already_exists as applied).
	syncFGA SyncFGAWriter
}

// SyncFGAWriter — the narrow direct-write port the reconciler uses for the create-path
// read-after-write closer. Satisfied by an adapter over
// clients.RelationStore (*clients.OpenFGAHTTPClient). Defined here so the reconcile
// use-case depends only on a local port (Clean Architecture — no clients import).
// WriteTuples must be idempotent (already_exists ⇒ applied) so the async drain of the
// SAME fga_outbox rows is a safe no-op.
type SyncFGAWriter interface {
	WriteTuples(ctx context.Context, tuples []SyncFGATuple) error
}

// SyncFGATuple — one FGA tuple for the direct sync write. Mirrors domain.MembershipTuple
// (and clients.RelationTuple) field-for-field so the wiring adapter is a trivial map.
type SyncFGATuple struct {
	User     string
	Relation string
	Object   string
}

// New constructs the reconciler.
func New(tx TxRunner, logger *slog.Logger) *Reconciler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{tx: tx, logger: logger}
}

// WithSyncFGA wires the OPTIONAL direct OpenFGA writer.
// nil-safe: a nil writer leaves the reconciler async-only (existing behaviour). The
// reconciler applies the collected ACTIVE-member tuples to it AFTER each writer-tx
// commits (never inside the tx — a rollback must not leave OpenFGA tuples).
func (r *Reconciler) WithSyncFGA(w SyncFGAWriter) *Reconciler {
	r.syncFGA = w
	return r
}

// syncFGACollector accumulates, across a single reconcile pass, the per-object tuples a
// reconcileBinding emitted to fga_outbox for ACTIVE members. It is applied to OpenFGA
// AFTER the pass's writer-tx commits. nil when sync-FGA
// is unwired (the collect calls are then cheap no-ops). Not concurrency-shared: one
// collector per WithTx pass, and a pass runs single-goroutine under the per-binding
// advisory lock.
type syncFGACollector struct {
	tuples []SyncFGATuple
	seen   map[SyncFGATuple]struct{}
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

// collect appends a member's ACTIVE-emit tuples, DE-DUPLICATED across the whole pass
// (skips when the collector is nil — i.e. sync-FGA unwired). De-dup is mandatory: one
// reconcile pass (esp. ReconcileObject fanning over many bindings, or the scope-self
// member plus a `*.*` content member that both target account:<X>) emits the SAME tuple
// more than once, and OpenFGA's batch Write rejects the WHOLE request on a duplicate
// (cannot_allow_duplicate_tuples_in_one_request) — distinct from the idempotent
// already_exists across requests. The fga_outbox enqueue is row-per-tuple so duplicates
// there are harmless; only the single batched sync Write needs the set. Called from
// applyDiff right where EmitTupleWrite enqueues them, so the sync write-set is the
// deduped fga_outbox write-set (no drift in CONTENT, only dups removed).
func (c *syncFGACollector) collect(tuples []domain.MembershipTuple) {
	if c == nil {
		return
	}
	if c.seen == nil {
		c.seen = make(map[SyncFGATuple]struct{})
	}
	for _, t := range tuples {
		st := SyncFGATuple{User: t.User, Relation: t.Relation, Object: t.Object}
		if _, dup := c.seen[st]; dup {
			continue
		}
		c.seen[st] = struct{}{}
		c.tuples = append(c.tuples, st)
	}
}

// flushDeletes emits the pass's DEFERRED tuple-deletes inside the writer-tx, AFTER
// every binding in the pass has reconciled (so the full pass write-set is known and
// every active binding's emitted-tuple ledger row is committed-in-tx). For each
// pending delete it subtracts (a) tuples WRITTEN by any member in THIS pass (a sibling
// binding re-materialized the identical tuple — col.seen) and (b) tuples still recorded
// in the ledger of an ACTIVE binding OTHER than the revoking one (cross-binding shared
// claim — TuplesStillClaimedByOtherBindings). The remainder — tuples no surviving claim
// keeps alive — is the only set safe to delete from the non-refcounted OpenFGA store.
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

// applyAfterCommit synchronously writes the collected tuples to OpenFGA after the
// writer-tx committed. Idempotent (WriteTuples treats
// already_exists as applied), so the later async drain of the SAME fga_outbox rows is a
// no-op. Best-effort: an error is logged, NOT returned — the durable fga_outbox + async
// drainer are the at-least-once backstop, so a transient OpenFGA blip degrades to the
// pre-fix async path rather than failing the create. The happy path completes the write
// before the caller returns, giving the create-path read-after-write guarantee.
func (r *Reconciler) applyAfterCommit(ctx context.Context, c *syncFGACollector) {
	if r.syncFGA == nil || c == nil || len(c.tuples) == 0 {
		return
	}
	if err := r.syncFGA.WriteTuples(ctx, c.tuples); err != nil {
		r.logger.WarnContext(ctx, "reconcile: synchronous FGA write failed; async drain will backstop",
			"tuple_count", len(c.tuples), "error", err)
	}
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
	// AFTER commit only: a rollback above returns early,
	// so OpenFGA is never written for an uncommitted diff.
	r.applyAfterCommit(ctx, col)
	return nil
}

// ReconcileObject re-evaluates every binding that has a member referencing the
// changed object (trigger (b) — a resource_mirror upsert/delete). For each such
// binding it recomputes the full desired set (idempotent diff), so a label flip
// or a parent change is reflected. It ALSO handles the PENDING→ACTIVE/REJECTED
// transition: a binding whose selector now matches a newly-arrived object picks
// it up because the full recompute re-runs MatchSelector.
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
		// Fan out over the de-duplicated union; reconcileBinding is a full
		// idempotent recompute (MatchSelector), so reconciling a binding once is
		// enough regardless of which source it came from.
		//
		// DEADLOCK-CLASS: each reconcileBinding takes
		// pg_advisory_xact_lock(hashtext(binding_id)) inside the ONE writer-tx of this
		// pass. The two source queries return binding ids in NON-deterministic order,
		// so locking in arrival order lets two concurrent ReconcileObject passes (on
		// different objects with overlapping binding-sets) acquire the shared locks in
		// DIFFERENT orders → ABBA deadlock (40P01). Sorting the deduped union ASC gives
		// every pass a GLOBALLY-consistent acquisition order, which is deadlock-free.
		union := dedupSortBindingIDs(existing, matching)
		for _, bID := range union {
			if err := r.reconcileBinding(ctx, s, bID, col); err != nil {
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
	r.applyAfterCommit(ctx, col)
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
	r.applyAfterCommit(ctx, col)
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

	current, err := s.CurrentMembers(ctx, bindingID)
	if err != nil {
		return fmt.Errorf("current members %s: %w", bindingID, err)
	}

	return r.applyDiff(ctx, s, bs, desired, current, col)
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
// Containment is re-asserted by the caller; this only resolves the candidate set.
func (r *Reconciler) matchSelectorObjects(ctx context.Context, s ReconcileStore, sel domain.RuleSelector) ([]domain.MirrorObject, error) {
	mirrorTypes, iamTypes := partitionByFeed(sel.ObjectTypes)
	var matched []domain.MirrorObject
	if len(mirrorTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, mirrorTypes, false, s)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (mirror): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	if len(iamTypes) > 0 {
		objs, err := r.matchByArm(ctx, sel, iamTypes, true, s)
		if err != nil {
			return nil, fmt.Errorf("match rule selector %s (iam-direct): %w", sel.RuleFP, err)
		}
		matched = append(matched, objs...)
	}
	return matched, nil
}

// matchByArm dispatches the per-arm match to the right feed (mirror vs iam-direct).
func (r *Reconciler) matchByArm(ctx context.Context, sel domain.RuleSelector, types []string, iamDirect bool, s ReconcileStore) ([]domain.MirrorObject, error) {
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
		if iamDirect {
			return s.MatchAllInScopeIAMDirect(ctx, types)
		}
		return s.MatchAllInScope(ctx, types)
	}
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

	// Scope-self member: the role's tier (+ verb-bearing v_*) ON
	// THE BINDING'S OWN SCOPE OBJECT (`account:<X>`/`project:<X>`). This is the
	// write-authz / no-access-loss anchor the removed binding-time scope-anchor emit
	// produced — now materialized by the SINGLE reconciler path. It is NOT a content
	// object matched by a selector: a `*.*` superuser role has empty selector
	// ObjectTypes (wildcard skipped), so without this the subject would lose the tier
	// on the scope entirely. Keyed by
	// a sentinel rule_fp so it has its own member row + ledger lineage (symmetric
	// revoke). The cluster super-admin path short-circuits and is not materialized here.
	if len(bs.ScopeSelfVerbs) > 0 {
		if sm, ok := scopeSelfMember(subject, bs.Scope.Type, bs.Scope.ID, bs.ScopeSelfVerbs); ok {
			out = append(out, sm)
		}
	}

	for _, sel := range bs.Selectors {
		matched, err := r.matchSelectorObjects(ctx, s, sel)
		if err != nil {
			return nil, err
		}
		for _, o := range matched {
			// Containment re-verify per object: a label-matched object NOT
			// under the binding's scope (cross-scope injection via label-tampering)
			// → REJECTED, never a tuple.
			if !o.IsContainedIn(bs.Scope) {
				out = append(out, DesiredMember{
					RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
					Status: domain.VerificationRejected,
				})
				continue
			}
			// ACTIVE: precompute the per-object tuples from the RULE's verbs (the
			// ARM_LABELS rule is excluded from CompileRules, so RolePerms cannot
			// supply the tier). ruleObjectTuples reuses the per-verb/tier
			// semantics. A type the model has no FGA object for → no tuple → skip the
			// object (fail-closed: a typo'd type never grants).
			tuples, ok := ruleObjectTuples(subject, sel.Verbs, o.ObjectType, o.ObjectID)
			if !ok {
				continue
			}
			out = append(out, DesiredMember{
				RuleFP: sel.RuleFP, ObjectType: o.ObjectType, ObjectID: o.ObjectID,
				Status: domain.VerificationActive, Tuples: tuples,
			})
		}
	}
	return out, nil
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
			if err := s.EmitTupleWrite(ctx, tuples); err != nil {
				return fmt.Errorf("emit tuple write %s:%s: %w", d.ObjectType, d.ObjectID, err)
			}
			// Collect the SAME tuples for the post-commit
			// synchronous OpenFGA write (read-after-write closer). no-op when unwired.
			col.collect(tuples)
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
// non-refcounted OpenFGA store must keep it alive until the LAST binding releases it).
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
	fgaType, ok := fgaObjectType(m.ObjectType)
	if !ok {
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
