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
type resourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) error
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

// objectReconciler — narrow port (instant-visibility): drive a
// SYNCHRONOUS post-commit ReconcileObject so the freshly-registered object's owner
// v_get materializes BEFORE the consumer's create-Operation reports done (a
// create→immediate-GET resolves ALLOW without waiting for the async reconcile-outbox
// drain). Implemented by reconcile.Reconciler. nil-safe + non-fatal: an unwired
// reconciler (or a reconcile error) never fails Register — the reconcile-outbox drain
// + periodic sweep are the at-least-once backstop.
type objectReconciler interface {
	ReconcileObject(ctx context.Context, objectType, objectID string) error
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
	if err := uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:      objType,
		ObjectID:        objID,
		ParentProjectID: in.GetParentProjectId(),
		ParentAccountID: in.GetParentAccountId(),
		Labels:          labels,
		SourceVersion:   sourceVersion(in),
	}, true); err != nil {
		return err
	}
	// Instant-visibility: after the owner-tuple + mirror + reconcile
	// event COMMIT, drive a SYNCHRONOUS ReconcileObject so the creator's per-object
	// v_get materializes before the consumer's create-Operation reports done — a
	// create→immediate-GET resolves ALLOW without waiting for the async
	// reconcile-outbox drain. nil-safe + NON-fatal: the resource is already durably
	// registered; the drain + periodic sweep are the at-least-once backstop, so a
	// reconcile error here is logged, not propagated (Register stays successful).
	uc.syncReconcile(ctx, objType, objID)
	return nil
}

// syncReconcile drives the optional post-commit ReconcileObject. nil-safe;
// a reconcile error is non-fatal (logged when a logger is wired).
func (uc *RegisterResourceUseCase) syncReconcile(ctx context.Context, objType, objID string) {
	if uc.objRecon == nil {
		return
	}
	if err := uc.objRecon.ReconcileObject(ctx, objType, objID); err != nil && uc.logger != nil {
		uc.logger.WarnContext(ctx, "register resource: post-commit reconcile failed (drain/sweep will retry)",
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
	objType, objID := t.objectType()
	// SourceVersion carries the unregister tombstone-version: the mirror DELETE
	// fires only if it is >= the stored register (Delete-after-Update reorder
	// cannot wipe a fresher row).
	return uc.emit(ctx, t, service.ResourceMirrorRow{
		ObjectType:    objType,
		ObjectID:      objID,
		SourceVersion: sourceVersion(in),
	}, false)
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

// emit runs the owner-tuple fga_outbox emit AND the resource_mirror UPSERT/DELETE
// in ONE writer-tx — both commit together or roll back together (atomic
// co-commit, ban #10). write=true → register (UPSERT + tuple.write);
// write=false → unregister (DELETE + tuple.delete).
func (uc *RegisterResourceUseCase) emit(ctx context.Context, t tupleIntent, row service.ResourceMirrorRow, write bool) error {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		// Backend-down at connection acquisition → retriable Unavailable (the
		// handler maps ErrUnavailable → codes.Unavailable; the caller's
		// transactional-outbox drainer then re-delivers). Fixed opaque message —
		// never surface the raw pgx driver text (host/port/user/db).
		return iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	tuples := []service.RelationTuple{{User: t.subject, Relation: t.relation, Object: t.object}}
	if write {
		if err = uc.emitter.EmitWriteTx(ctx, tx, tuples); err != nil {
			return fmt.Errorf("emit fga outbox: %w", err)
		}
		// Backfill parent_account_id SAME-DB from projects.account_id when the
		// owner supplied only parent_project_id (IAM owns Project — no peer-call, no
		// cycle). The owner-supplied value (if any) wins only when the project is not
		// resolvable (graceful: a not-yet-mirrored project keeps the owner's value).
		if uc.accounts != nil && row.ParentAccountID == "" && row.ParentProjectID != "" {
			accID, ok, rerr := uc.accounts.AccountForProjectTx(ctx, tx, row.ParentProjectID)
			if rerr != nil {
				return fmt.Errorf("resolve account for project: %w", rerr)
			}
			if ok {
				row.ParentAccountID = accID
			}
		}
		if err = uc.mirror.UpsertTx(ctx, tx, row); err != nil {
			return fmt.Errorf("upsert resource mirror: %w", err)
		}
	} else {
		if err = uc.emitter.EmitDeleteTx(ctx, tx, tuples); err != nil {
			return fmt.Errorf("emit fga outbox: %w", err)
		}
		if err = uc.mirror.DeleteTx(ctx, tx, row.ObjectType, row.ObjectID, row.SourceVersion); err != nil {
			return fmt.Errorf("delete resource mirror: %w", err)
		}
	}
	// Enqueue a reconcile event in the SAME writer-tx as the mirror
	// change (atomic co-commit, ban #10). The reconciler re-evaluates every
	// binding member referencing this object (selector membership / byName
	// containment / PENDING→ACTIVE verify). nil-safe when the reconciler is
	// unwired (the periodic sweep then catches up).
	if uc.reconcile != nil {
		// NOTE: keep these literals in sync with reconcile_outbox.EventUpsert /
		// reconcile_outbox.EventDelete (the drainer reads them). They are inlined
		// here rather than imported because this use-case must not depend on the
		// repo (pg) package — clean-arch dependency rule.
		eventType := "mirror.upsert"
		if !write {
			eventType = "mirror.delete"
		}
		if err = uc.reconcile.EmitTx(ctx, tx, eventType, row.ObjectType, row.ObjectID); err != nil {
			return fmt.Errorf("emit reconcile event: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		// Backend-down at commit → retriable Unavailable (same opaque, no-leak
		// contract as Begin). The row/tuple did not durably land; the caller's
		// drainer re-delivers.
		return iamerr.Wrapf(iamerr.ErrUnavailable, "iam datastore unavailable")
	}
	return nil
}
