// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource.go — RegisterResourceUseCase (Internal FGA-proxy).
//
// RegisterResource / UnregisterResource let a resource-owning module
// (vpc/compute/nlb) register or remove an owner-hierarchy FGA tuple *through
// IAM* — the module never writes FGA directly. The tuple intent is
// enqueued into kacho_iam.fga_outbox in ONE writer-tx (atomic emit-in-tx,
// ban #10) and applied asynchronously by the existing drainer
// (clients/fga_applier.go), whose idempotent classification makes the contract:
//
//	repeat register of the same tuple → OK  (already_exists → ErrAlreadyApplied)
//	unregister of an absent tuple     → OK  (cannot_delete  → ErrAlreadyApplied)
//
// so neither AlreadyExists nor NotFound ever surfaces (proto contract).
//
// Sync unary per the proto (RegisterResourceResponse is empty); the
// at-least-once retry guarantee is provided by the caller-side drainer,
// not by an LRO. The tuple is taken verbatim from the request: the
// payload already carries the pre-composed FGA strings ({subject_id, relation,
// object}), so this use-case is the generic owner-tuple relay, not a
// resource-type-aware composer.
package internal_iam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// relationOutboxEmitter — narrow write port: emit FGA tuple
// write/delete rows inside a caller-owned tx. Implemented by
// *repo/kacho/pg.FGAOutboxEmitter.
type relationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error
}

// resourceMirrorEmitter — narrow write port for the
// output-only mirror: UPSERT/DELETE a kacho_iam.resource_mirror row inside the
// caller-owned tx (atomic co-commit with the owner-tuple emit, ban #10).
// Implemented by *repo/kacho/pg.ResourceMirrorEmitter.
//
// UpsertTx reports whether it actually CHANGED a row. The mirror's monotonic guard
// applies a register only when its source_version is strictly newer than the stored one,
// so a redelivery of an already-applied registration updates zero rows — the signal the
// register path uses to skip re-materialising work the first delivery already did.
type resourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) (changed bool, err error)
	DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) error
}

// reconcileEventEmitter — narrow write port: enqueue a reconcile
// event into kacho_iam.resource_reconcile_outbox in the SAME writer-tx as the
// mirror UPSERT/DELETE (atomic co-commit, ban #10). The reconciler-worker
// drains these and re-evaluates every binding member referencing the changed
// object (selector + byName containment / PENDING→ACTIVE verify). Optional —
// nil-safe (a deployment without the reconciler still mirrors correctly; the
// periodic sweep then catches up).
type reconcileEventEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, eventType, objectType, objectID string) error
}

// accountResolver — narrow read port: resolve a project's account_id
// SAME-DB (IAM owns Project) so the mirror's parent_account_id is backfilled even
// when the owner (compute) only supplied parent_project_id. NO cross-service call
// (IAM reads its own projects table). Optional — nil-safe (the owner-supplied
// parent_account_id is used as-is when the resolver is unwired).
type accountResolver interface {
	AccountForProjectTx(ctx context.Context, tx service.Tx, projectID string) (accountID string, ok bool, err error)
}

// objectReconciler — narrow port (instant-visibility): drive a SYNCHRONOUS post-commit
// materialization so the freshly-registered object's owner v_get materializes BEFORE the
// consumer's create-Operation reports done (a create→immediate-GET resolves ALLOW without
// waiting for the async reconcile-outbox drain). Implemented by reconcile.Reconciler.
//
// The create-path uses the ADDITIVE forward fast-path (ReconcileObjectForward): it
// materializes ONLY the just-registered object's per-object tuples for each matching
// binding, WITHOUT the per-binding advisory lock / full O(scope) recompute — so N
// concurrent registrations in the same project/account (all sharing one editor/owner
// binding) do NOT serialize on that binding's lock (the throughput fix). The co-committed
// resource_reconcile_outbox event still drives the async worker's FULL ReconcileObject as
// the at-least-once backstop (delete-stale / audit / sweep), so a skipped or failed
// forward pass is re-converged.
//
// nil-safe + non-fatal: an unwired reconciler (or a reconcile error) never fails Register
// — the reconcile-outbox drain + periodic sweep are the backstop.
// hierarchyTupleApplier — the OPTIONAL direct-store applier for the tuple this use-case
// itself owns: the object→project containment pointer (and the public wildcard grant).
// The reconciler materialises the per-object verbs; nothing but this use-case writes the
// pointer, so nothing but this use-case can take it away promptly.
//
// WHY IT MATTERS MORE THAN ITS SIZE SUGGESTS. The account administrator reaches every
// object of the account THROUGH that pointer, not through a per-object grant. A
// withdrawal that strips the verbs and leaves the pointer queued therefore still answers
// ALLOW to the whole administrative tier on a resource the product already reports as
// gone — the removal that looks complete while a class of subject keeps its access.
//
// Both methods must be idempotent at the SET level (already-present ⇒ applied,
// already-absent ⇒ applied), because the durable fga_outbox row for the SAME tuple is
// drained afterwards and must be a no-op. nil ⇒ queue-only (the pre-existing behaviour).
type hierarchyTupleApplier interface {
	WriteTuples(ctx context.Context, tuples []service.RelationTuple) error
	DeleteTuples(ctx context.Context, tuples []service.RelationTuple) error
}

type objectReconciler interface {
	ReconcileObjectForward(ctx context.Context, objectType, objectID string) error
}

// RegisterResourceRequest / UnregisterResourceRequest fields the use-case
// consumes. We accept the proto messages directly at the handler boundary and
// pass a small value struct here to keep the use-case transport-agnostic.
type tupleIntent struct {
	subject  string
	relation string
	object   string
}

// objectType / objectID parse the FGA `<type>:<id>` object into the dotted
// closed-table key (resource_mirror.object_type) + opaque id. validateTuple has
// already enforced the `<type>:<id>` grammar, so colon split is safe here.
func (t tupleIntent) objectType() (string, string) {
	colon := strings.IndexByte(t.object, ':')
	fgaType := t.object[:colon]
	id := t.object[colon+1:]
	// Reverse-map known FGA types to the dotted key (e.g. compute_instance →
	// compute.instance); unknown types are kept verbatim (generic mirror).
	if dotted, ok := authzmap.DottedType(fgaType); ok {
		return dotted, id
	}
	return fgaType, id
}

// isPureGrant reports whether the intent only opens the object for anonymous
// read (`user:* #v_get`) instead of describing the object's own state.
//
// Such an intent carries no parent scope and no labels — nothing about the
// resource changed — yet it addresses the SAME object key as the resource's own
// registration. Feeding it through the projection path would overwrite the
// resource's parent scope with the empty one it carries and, on withdrawal,
// delete the projection of a resource that still exists. So a pure grant is
// applied as a tuple and nothing else.
func (t tupleIntent) isPureGrant() bool {
	return authzguard.IsPublicReadGrant(t.subject, t.relation)
}

// RegisterResourceUseCase orchestrates the FGA-proxy tuple relay + the
// resource_mirror co-commit (labels + parent-scope of the owner object) + the
// reconcile-event enqueue and parent_account_id backfill.
type RegisterResourceUseCase struct {
	emitter   relationOutboxEmitter
	mirror    resourceMirrorEmitter
	txb       service.TxBeginner
	reconcile reconcileEventEmitter // optional, nil-safe
	accounts  accountResolver       // optional, nil-safe
	objRecon  objectReconciler      // sync post-commit — optional, nil-safe
	tuples    hierarchyTupleApplier // sync post-commit containment pointer — optional, nil-safe
	logger    *slog.Logger
}

// NewRegisterResourceUseCase — constructor. `mirror` co-commits the
// resource_mirror row in the same writer-tx as the owner-tuple emit.
func NewRegisterResourceUseCase(emitter relationOutboxEmitter, mirror resourceMirrorEmitter, txb service.TxBeginner) *RegisterResourceUseCase {
	return &RegisterResourceUseCase{emitter: emitter, mirror: mirror, txb: txb}
}

// WithReconcile wires the reconcile-event emitter: a mirror change
// enqueues a resource_reconcile_outbox event in the same writer-tx.
func (uc *RegisterResourceUseCase) WithReconcile(r reconcileEventEmitter) *RegisterResourceUseCase {
	uc.reconcile = r
	return uc
}

// WithAccountResolver wires the same-DB parent_account_id backfill.
func (uc *RegisterResourceUseCase) WithAccountResolver(a accountResolver) *RegisterResourceUseCase {
	uc.accounts = a
	return uc
}

// WithObjectReconciler wires the sync post-commit ReconcileObject
// (instant visibility). nil-safe. An optional logger surfaces a non-fatal
// reconcile error (the outbox drain + sweep remain the backstop).
func (uc *RegisterResourceUseCase) WithObjectReconciler(r objectReconciler, logger *slog.Logger) *RegisterResourceUseCase {
	uc.objRecon = r
	uc.logger = logger
	return uc
}

// WithTupleApplier wires the OPTIONAL direct-store applier for the containment pointer
// (and the public wildcard grant) this use-case owns. nil-safe: without it both
// directions travel the durable queue alone, which is the pre-existing behaviour. The
// logger surfaces a non-fatal apply error — a fast revoke that has quietly stopped
// working must not look like nothing at all.
func (uc *RegisterResourceUseCase) WithTupleApplier(a hierarchyTupleApplier, logger *slog.Logger) *RegisterResourceUseCase {
	uc.tuples = a
	if logger != nil {
		uc.logger = logger
	}
	return uc
}

// Register validates the tuple + labels, then UPSERTs the mirror row AND enqueues
// an fga.tuple.write row in ONE writer-tx (atomic co-commit, ban #10).
func (uc *RegisterResourceUseCase) Register(ctx context.Context, in registerInput) error {
	t, err := validateTuple(in)
	if err != nil {
		return err
	}
	labels := in.GetLabels()
	// Minimal sanity-validation of the owner-supplied labels (defense-in-depth):
	// mirror the Kachō label-pattern so an arbitrary/oversized map
	// never lands. Reuses the corelib validator (key/value pattern, size).
	if err := corevalidate.Labels("labels", labels); err != nil {
		return err
	}
	objType, objID := t.objectType()
	if t.isPureGrant() {
		// Tuple only: no projection write, so no redelivery gate to consult and
		// no binding fan-out to drive (no binding's desired set depends on the
		// wildcard tuple).
		_, err = uc.emitGrant(ctx, t, true)
		return err
	}
	changed, err := uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:      objType,
		ObjectID:        objID,
		ParentProjectID: in.GetParentProjectId(),
		ParentAccountID: in.GetParentAccountId(),
		Labels:          labels,
		SourceVersion:   sourceVersion(in),
	}, true)
	if err != nil {
		return err
	}
	// REDELIVERY GATE. Every consumer delivers each registration TWICE — a synchronous
	// post-commit call plus the at-least-once register-drainer replaying the same durable
	// intent — and the two carry the SAME monotonic source_version lineage (the sync path
	// stamps wall-clock AFTER the commit, the drainer replays the version the DB stamped
	// INSIDE the writer-tx, i.e. strictly earlier). The mirror's monotonic guard therefore
	// already recognises the second delivery: it changes zero rows. When nothing changed
	// there is, by construction, nothing to materialise — the delivery that DID write the
	// row emitted the owner tuple and the reconcile event — so the expensive forward
	// reconcile fan-out is skipped. Before this, iam re-ran the whole materialisation on
	// every duplicate (measured: two byte-identical 27-row fga_outbox batches 6.7 ms apart
	// for one created network).
	//
	// This is keyed on APPLIED STATE via a MONOTONIC version, NOT on queue contents.
	// De-duplicating unsent outbox rows by (event type, payload) would silently drop a
	// re-grant — grant → revoke → grant folds into grant → revoke — whereas a genuine
	// re-registration always carries a newer version (and an unregister removes the mirror
	// row outright), so it can never be swallowed. The revoke path is deliberately NOT
	// gated at all: a swallowed revoke is an over-grant, so Unregister always materialises.
	//
	// UNVERSIONED PRODUCERS ARE NEVER GATED. A caller that sends no source_version maps to
	// '-infinity', which loses every monotonic comparison — so its writes report `changed
	// = false` for reasons that have NOTHING to do with redelivery, and gating them would
	// suppress REAL materialisation. (Measured: registry's synchronous registrar sends no
	// version, so every re-registration after the first would have lost its fast path and
	// fallen back to the async drain — a widened read-your-writes window, not a saving.)
	// The gate therefore requires positive proof of redelivery — a version to compare —
	// and fails OPEN into doing the work when it has none.
	if !changed && !sourceVersion(in).IsZero() {
		return nil
	}
	// Instant-visibility: after the owner-tuple + mirror + reconcile event COMMIT, drive
	// a SYNCHRONOUS ADDITIVE forward materialization so the creator's per-object v_get
	// materializes before the consumer's create-Operation reports done — a
	// create→immediate-GET resolves ALLOW without waiting for the async reconcile-outbox
	// drain. The forward path takes NO per-binding advisory lock, so N concurrent
	// registrations in the same scope do NOT serialize (throughput). nil-safe + NON-fatal:
	// the resource is already durably registered; the async worker's FULL ReconcileObject
	// (from the co-committed reconcile event) + the periodic sweep are the at-least-once
	// backstop, so a forward error here is logged, not propagated (Register stays
	// successful).
	uc.syncReconcile(ctx, objType, objID)
	return nil
}

// syncReconcile drives the optional post-commit ADDITIVE forward materialization
// (ReconcileObjectForward). nil-safe; a reconcile error is non-fatal (logged when a
// logger is wired) — the async full ReconcileObject backstop re-converges.
func (uc *RegisterResourceUseCase) syncReconcile(ctx context.Context, objType, objID string) {
	if uc.objRecon == nil {
		return
	}
	if err := uc.objRecon.ReconcileObjectForward(ctx, objType, objID); err != nil && uc.logger != nil {
		uc.logger.WarnContext(ctx, "register resource: post-commit forward reconcile failed (drain/sweep will retry)",
			slog.String("object_type", objType), slog.String("object_id", objID), slog.Any("err", err))
	}
}

// sourceVersion extracts the owner-stamped monotonic version from the request.
// Nil/zero proto Timestamp → zero time.Time, which the mirror
// emitter normalizes to '-infinity' (legacy producer, applies unconditionally).
func sourceVersion(in versionedInput) time.Time {
	ts := in.GetSourceVersion()
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// Unregister validates the tuple, then DELETEs the mirror row AND enqueues an
// fga.tuple.delete row in ONE writer-tx (symmetry). Labels/parent on the
// Unregister payload are ignored (the row is removed by its (type,id) PK).
func (uc *RegisterResourceUseCase) Unregister(ctx context.Context, in unregisterInput) error {
	t, err := validateTuple(in)
	if err != nil {
		return err
	}
	if t.isPureGrant() {
		// Withdrawing the public grant removes the wildcard tuple. The resource
		// itself is untouched and its projection must survive.
		_, err = uc.emitGrant(ctx, t, false)
		return err
	}
	objType, objID := t.objectType()
	// SourceVersion carries the unregister tombstone-version: the mirror DELETE
	// fires only if it is >= the stored register (Delete-after-Update reorder
	// cannot wipe a fresher row).
	//
	// The revoke path is NEVER gated on "did the mirror change": a swallowed revoke is a
	// standing over-grant, so the tuple-delete and the reconcile event are enqueued
	// unconditionally (fail-closed). The producer-cost saving is taken only on the grant
	// path, where a no-op is provably a redelivery of work already done.
	if _, err = uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:    objType,
		ObjectID:      objID,
		SourceVersion: sourceVersion(in),
	}, false); err != nil {
		return err
	}
	// SYMMETRY WITH Register. Registration drives its materialization in-process right
	// after the commit; withdrawal used to hand its materialization entirely to the
	// reconcile queue. The result was a product fast at granting and slow at revoking:
	// the object's per-object verbs appeared inside the create request and were still
	// answered ALLOW long after the resource itself had begun answering 404 (measured on
	// the stand: twelve seconds, bounded only by queue depth, not by anything the caller
	// could observe or wait for).
	//
	// The forward entry point is correct here even though it is named for the additive
	// fast path: its delete-stale guard routes an object that ALREADY has materialized
	// members to the FULL pass, and the mirror row was removed in the tx above, so that
	// pass derives an empty desired set and strips the object's tuples — which is exactly
	// the withdrawal. The co-committed reconcile event stays the at-least-once backstop,
	// so a failure here degrades to the previous latency rather than losing the revoke.
	uc.syncReconcile(ctx, objType, objID)
	return nil
}

// tupleInput — the minimal transport-agnostic shape both RPCs share. Satisfied
// by the proto Register/Unregister request messages (handler adapts them).
type tupleInput interface {
	GetSubjectId() string
	GetRelation() string
	GetObject() string
}

// versionedInput — carries the owner-stamped monotonic source_version
// (register: state-version; unregister: tombstone-version). Both proto request
// messages satisfy it.
type versionedInput interface {
	GetSourceVersion() *timestamppb.Timestamp
}

// registerInput — Register additionally consumes the mirror fields (labels +
// parent-scope) + the source_version. Satisfied by
// *iamv1.RegisterResourceRequest.
type registerInput interface {
	tupleInput
	versionedInput
	GetLabels() map[string]string
	GetParentProjectId() string
	GetParentAccountId() string
}

// unregisterInput — Unregister consumes the tuple + the tombstone source_version.
// Satisfied by *iamv1.UnregisterResourceRequest.
type unregisterInput interface {
	tupleInput
	versionedInput
}

func validateTuple(in tupleInput) (tupleIntent, error) {
	subject := strings.TrimSpace(in.GetSubjectId())
	relation := strings.TrimSpace(in.GetRelation())
	object := strings.TrimSpace(in.GetObject())

	if subject == "" {
		return tupleIntent{}, shared.InvalidArg("subject_id", "required")
	}
	if relation == "" {
		return tupleIntent{}, shared.InvalidArg("relation", "required")
	}
	if object == "" {
		return tupleIntent{}, shared.InvalidArg("object", "required")
	}
	// FGA object/subject grammar: `<type>:<id>`, no whitespace and no `#`
	// (the latter is the userset separator and would corrupt the tuple).
	if err := validateRelationString("subject_id", subject); err != nil {
		return tupleIntent{}, err
	}
	if err := validateRelationString("object", object); err != nil {
		return tupleIntent{}, err
	}
	if strings.ContainsAny(relation, " \t\n#:") {
		return tupleIntent{}, shared.InvalidArg("relation", "invalid relation")
	}
	return tupleIntent{subject: subject, relation: relation, object: object}, nil
}

// validateRelationString enforces the FGA `<type>:<id>` shape: exactly one ':',
// non-empty type and id, no whitespace, no '#'.
func validateRelationString(field, v string) error {
	if strings.ContainsAny(v, " \t\n#") {
		return shared.InvalidArg(field, "invalid "+field)
	}
	colon := strings.IndexByte(v, ':')
	if colon <= 0 || colon == len(v)-1 {
		return shared.InvalidArg(field, "invalid "+field)
	}
	// Exactly one ':' — a second colon is rejected. objectType() splits on the
	// FIRST colon, so a two-colon value would make the resource_mirror /
	// reconcile-outbox key ("a:b" from "type:a:b") diverge from the verbatim FGA
	// tuple object string ("type:a:b") — the mirror row and the tuple then
	// reference different objects.
	if strings.IndexByte(v[colon+1:], ':') >= 0 {
		return shared.InvalidArg(field, "invalid "+field)
	}
	return nil
}

// emitGrant enqueues ONLY the tuple write/delete, in its own writer-tx. Used for
// a pure grant (see tupleIntent.isPureGrant): there is no projection row to
// co-commit with, because the intent says nothing about the object's own state.
// The at-least-once contract is unchanged — the tuple enqueue is durable, and the
// drainer's idempotent classification makes a repeat a no-op.
func (uc *RegisterResourceUseCase) emitGrant(ctx context.Context, t tupleIntent, write bool) (bool, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		// Same opaque, no-leak contract as emit: retriable Unavailable.
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	tuples := []service.RelationTuple{{User: t.subject, Relation: t.relation, Object: t.object}}
	if write {
		err = uc.emitter.EmitWriteTx(ctx, tx, tuples)
	} else {
		err = uc.emitter.EmitDeleteTx(ctx, tx, tuples)
	}
	if err != nil {
		return false, fmt.Errorf("emit fga outbox: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	uc.applyTuplesAfterCommit(ctx, tuples, write)
	return true, nil
}

// applyTuplesAfterCommit applies the tuple this use-case owns DIRECTLY to the store,
// AFTER the writer-tx committed — never inside it, since a rollback must not leave the
// store holding a relationship no row justifies.
//
// It is an accelerator over a durable queue, not a replacement for it: the fga_outbox row
// was enqueued in the same tx and the drainer re-applies the identical tuple as a no-op.
// A failure here therefore costs latency, never the change itself — which is why it is
// logged rather than returned. It IS logged, though: a fast path that has quietly stopped
// working is indistinguishable from one that was never there.
//
// APPLYING A REMOVAL AHEAD OF ITS QUEUE CANNOT STRAND THE TUPLE. The withdrawal may run
// while the registration's own outbox row is still unsent; the drainer would then write
// the tuple back before removing it again. That ordering is guaranteed, not hoped for —
// fga_outbox is claimed head-first per tuple key, so the earlier write is always applied
// before the later delete, and the final state is the removed one. The only difference
// the early apply makes is which moments answer ALLOW, and those are strictly fewer than
// before it.
func (uc *RegisterResourceUseCase) applyTuplesAfterCommit(ctx context.Context, tuples []service.RelationTuple, write bool) {
	if uc.tuples == nil || len(tuples) == 0 {
		return
	}
	var err error
	if write {
		err = uc.tuples.WriteTuples(ctx, tuples)
	} else {
		err = uc.tuples.DeleteTuples(ctx, tuples)
	}
	if err != nil && uc.logger != nil {
		uc.logger.WarnContext(ctx,
			"register resource: post-commit tuple apply failed (drain will backstop)",
			slog.Bool("write", write), slog.Int("tuple_count", len(tuples)), slog.Any("err", err))
	}
}

// emit runs the owner-tuple fga_outbox emit AND the resource_mirror UPSERT/DELETE
// in ONE writer-tx — both commit together or roll back together (atomic
// co-commit, ban #10). write=true → register (UPSERT + tuple.write);
// write=false → unregister (DELETE + tuple.delete).
// It returns whether the mirror statement actually CHANGED a row. On the register path a
// false means the monotonic guard rejected the write as not-newer — a redelivery of a
// registration already applied — and the owner-tuple + reconcile-event enqueues are
// SKIPPED with it (they were performed by the delivery that did write the row). The
// unregister path always enqueues (a swallowed revoke would be an over-grant), so its
// flag is informational only.
func (uc *RegisterResourceUseCase) emit(ctx context.Context, t tupleIntent, row service.ResourceMirrorRow, write bool) (bool, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		// Backend-down at connection acquisition → retriable Unavailable (the
		// handler maps ErrUnavailable → codes.Unavailable; the caller's
		// transactional-outbox drainer then re-delivers). Fixed opaque message —
		// never surface the raw pgx driver text (host/port/user/db).
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	tuples := []service.RelationTuple{{User: t.subject, Relation: t.relation, Object: t.object}}
	changed := true
	if write {
		// Backfill parent_account_id SAME-DB from projects.account_id when the
		// owner supplied only parent_project_id (IAM owns Project — no peer-call, no
		// cycle). The owner-supplied value (if any) wins only when the project is not
		// resolvable (graceful: a not-yet-mirrored project keeps the owner's value).
		if uc.accounts != nil && row.ParentAccountID == "" && row.ParentProjectID != "" {
			accID, ok, rerr := uc.accounts.AccountForProjectTx(ctx, tx, row.ParentProjectID)
			if rerr != nil {
				return false, fmt.Errorf("resolve account for project: %w", rerr)
			}
			if ok {
				row.ParentAccountID = accID
			}
		}
		// The mirror UPSERT runs FIRST so its monotonic verdict can gate the two
		// enqueues below. Ordering within the tx is otherwise irrelevant — all three
		// statements still commit together or roll back together (ban #10).
		if changed, err = uc.mirror.UpsertTx(ctx, tx, row); err != nil {
			return false, fmt.Errorf("upsert resource mirror: %w", err)
		}
		// An UNVERSIONED producer ('-infinity') loses every monotonic comparison, so its
		// `changed = false` proves nothing about redelivery — treat it as changed so a
		// real registration is never suppressed (see the gate note in Register).
		if row.SourceVersion.IsZero() {
			changed = true
		}
		if changed {
			if err = uc.emitter.EmitWriteTx(ctx, tx, tuples); err != nil {
				return false, fmt.Errorf("emit fga outbox: %w", err)
			}
		}
	} else {
		if err = uc.emitter.EmitDeleteTx(ctx, tx, tuples); err != nil {
			return false, fmt.Errorf("emit fga outbox: %w", err)
		}
		if err = uc.mirror.DeleteTx(ctx, tx, row.ObjectType, row.ObjectID, row.SourceVersion); err != nil {
			return false, fmt.Errorf("delete resource mirror: %w", err)
		}
	}
	// Enqueue a reconcile event in the SAME writer-tx as the mirror
	// change (atomic co-commit, ban #10). The reconciler re-evaluates every
	// binding member referencing this object (selector membership / byName
	// containment / PENDING→ACTIVE verify). nil-safe when the reconciler is
	// unwired (the periodic sweep then catches up).
	//
	// Skipped on a no-op register (see the redelivery gate in Register): the mirror is
	// byte-for-byte what it already was, so re-running the reconciler over it would
	// re-derive an identical desired set and change nothing.
	if uc.reconcile != nil && changed {
		// NOTE: keep these literals in sync with reconcile_outbox.EventUpsert /
		// reconcile_outbox.EventDelete (the drainer reads them). They are inlined
		// here rather than imported because this use-case must not depend on the
		// repo (pg) package — clean-arch dependency rule.
		eventType := "mirror.upsert"
		if !write {
			eventType = "mirror.delete"
		}
		if err = uc.reconcile.EmitTx(ctx, tx, eventType, row.ObjectType, row.ObjectID); err != nil {
			return false, fmt.Errorf("emit reconcile event: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		// Backend-down at commit → retriable Unavailable (same opaque, no-leak
		// contract as Begin). The row/tuple did not durably land; the caller's
		// drainer re-delivers.
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	// The register direction applies only what was actually enqueued: a redelivery the
	// monotonic guard rejected (changed == false) enqueued nothing, so there is nothing
	// to accelerate. The revoke direction always enqueues, and always applies.
	if changed || !write {
		uc.applyTuplesAfterCommit(ctx, tuples, write)
	}
	return changed, nil
}
