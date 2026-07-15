// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// grant_admin.go — GrantAdminUseCase (InternalClusterService.GrantAdmin).
//
// Flow (synchronous within Execute):
//  1. Sync validations: subject_type USER only, subject_id format,
//     user exists in kacho_iam.users.
//  2. Persist Operation (done=false) so the returned id is always queryable.
//  3. Begin TX → Grant → if !created && !active → Reactivate →
//     EmitWriteTx (FGA outbox) → commit. On failure → MarkError the op.
//  4. MarkDone the Operation (done=true, full grant metadata) and return.
//
// Idempotency:
//   - Grant returns (row, false, nil) if ON CONFLICT fires.
//   - If the existing row IsActive → no further write, return it.
//   - If the existing row !IsActive (revoked history) → Reactivate within
//     the same TX (re-activates in-place, same id).
//
// Operation: persisted done=false BEFORE the mutation (mirroring the async
// mutations) then flipped to done=true — the caller receives a terminal (done)
// envelope, and the op row is durable even if the terminal write is retried.

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// GrantAdminUseCase — orchestrates GrantAdmin synchronously.
type GrantAdminUseCase struct {
	writer    grantWriter
	reader    grantReader
	relations relationOutboxEmitter
	txb       service.TxBeginner
	opsRepo   operations.Repo
	// userCheck — user-existence guard; nil = skip (tests without user table seed).
	userCheck userChecker
	// adminCheck — defense-in-depth ReBAC system_admin@cluster gate. nil →
	// fail-closed (requireClusterSystemAdmin denies). See admin_authz.go.
	adminCheck adminChecker
	// audit — durable audit_outbox emitter. nil → no audit row
	// (purely-additive; mutation contract unchanged). See WithAuditEmitter.
	audit auditEmitter
}

// NewGrantAdminUseCase — constructor (user-existence guard wired separately via WithUserChecker).
func NewGrantAdminUseCase(
	w grantWriter,
	r grantReader,
	relations relationOutboxEmitter,
	txb service.TxBeginner,
	opsRepo operations.Repo,
) *GrantAdminUseCase {
	return &GrantAdminUseCase{writer: w, reader: r, relations: relations, txb: txb, opsRepo: opsRepo}
}

// WithAuditEmitter — wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (uc *GrantAdminUseCase) WithAuditEmitter(a auditEmitter) *GrantAdminUseCase {
	uc.audit = a
	return uc
}

// WithUserChecker — wires the user-existence guard.
func (uc *GrantAdminUseCase) WithUserChecker(c userChecker) *GrantAdminUseCase {
	uc.userCheck = c
	return uc
}

// WithAdminChecker — wires the defense-in-depth ReBAC system_admin gate.
// Composition-root only (cmd/kacho-iam/wiring.go). nil checker stays
// fail-closed.
func (uc *GrantAdminUseCase) WithAdminChecker(c adminChecker) *GrantAdminUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — sync validation + sync domain mutation + Operation envelope.
func (uc *GrantAdminUseCase) Execute(
	ctx context.Context,
	subjectType iamv1.ClusterGrantSubjectType,
	subjectID string,
) (*operationpb.Operation, error) {
	// Defense-in-depth authZ FIRST (before any validation or DB access):
	// require an authenticated principal holding system_admin@cluster. Fail-
	// closed on empty principal / nil checker / backend error / not-allowed.
	if err := requireClusterSystemAdmin(ctx, uc.adminCheck); err != nil {
		return nil, err
	}
	// Only USER is supported in this version.
	if subjectType != iamv1.ClusterGrantSubjectType_USER {
		return nil, shared.InvalidArg("subject_type",
			"only 'user' supported in this version")
	}
	// subject_id: required.
	if subjectID == "" {
		return nil, shared.InvalidArg("subject_id", "required")
	}
	// subject_id: format validation.
	if !subjectIDRe.MatchString(subjectID) {
		return nil, shared.InvalidArg("subject_id",
			fmt.Sprintf("must match ^usr[0-9a-hjkmnp-tv-z]{17}$ (got %q)", subjectID))
	}
	sid := domain.SubjectID(subjectID)

	// User must exist in kacho_iam.users.
	if uc.userCheck != nil {
		if err := uc.userCheck.ExistsUser(ctx, subjectID); err != nil {
			return nil, shared.MapRepoErr(err)
		}
	}

	// Principal for granted_by field. The authZ gate above already proved a
	// non-empty authenticated principal — so granted_by is the verified caller,
	// never coerced to 'bootstrap' (that anonymous→bootstrap coercion silently
	// accepted unauthenticated callers and is removed). The legitimate bootstrap
	// startup grant runs via seed.RunBootstrapAdmin (DB-direct, granted_by=
	// 'bootstrap'), not through this use-case.
	principal := authzguard.PrincipalUserID(ctx)

	// Persist the Operation (done=false) BEFORE the mutation — mirroring every
	// async mutation in this service, so the operation id the caller receives is
	// ALWAYS durably queryable. The previous order (mutate → persist op, persist
	// failure non-fatal) left the committed grant with NO pollable Operation row →
	// OperationService.Get(id) returned NotFound forever (CWE-662). The grant.ID
	// is not yet known here, so the initial metadata carries only subject_id; the
	// full metadata (with grant.ID) is written on MarkDone.
	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Grant cluster admin to user %s", subjectID),
		&iamv1.GrantClusterAdminMetadata{SubjectId: subjectID},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	// Perform domain mutation synchronously.
	grant, err := uc.doGrant(ctx, sid, principal)
	if err != nil {
		// Record the terminal failure on the already-persisted op so a poll sees a
		// real error, not NotFound; still surface the gRPC error to the caller.
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	// Complete the Operation (done=true) with the full grant metadata as response.
	meta, merr := anypb.New(&iamv1.GrantClusterAdminMetadata{
		ClusterAdminGrantId: string(grant.ID),
		SubjectId:           subjectID,
	})
	if merr != nil {
		return nil, fmt.Errorf("marshal grant metadata: %w", merr)
	}
	if err := uc.opsRepo.MarkDone(ctx, op.ID, meta); err != nil {
		// Non-fatal: the grant committed and the op row exists (done=false) — a
		// poller keeps polling and the terminal-write is retriable, so this never
		// degrades to NotFound. Log for traceability (CWE-390: no silent swallow).
		slog.ErrorContext(ctx, "cluster GrantAdmin: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Response = meta

	return shared.OperationToProto(&op), nil
}

// doGrant — runs grant (and optional reactivate) within a single TX.
func (uc *GrantAdminUseCase) doGrant(
	ctx context.Context,
	subject domain.SubjectID,
	grantedBy string,
) (domain.ClusterAdminGrant, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	grant, created, gerr := uc.writer.Grant(ctx, tx, subject, grantedBy)
	if gerr != nil {
		return domain.ClusterAdminGrant{}, gerr
	}

	// changed — true iff this call actually committed a state change to the
	// cluster_admin_grants row (fresh INSERT or a reactivate of revoked
	// history). A repeat of an already-active grant changes nothing → no write,
	// and so MUST NOT emit an audit row (audit = log of committed changes, not
	// of RPC calls).
	changed := created
	if !created && !grant.IsActive() {
		// Reactivate: revoked history row — update in-place.
		grant, gerr = uc.writer.Reactivate(ctx, tx, subject, grantedBy)
		if gerr != nil {
			return domain.ClusterAdminGrant{}, gerr
		}
		changed = true
	}

	// Emit FGA outbox row (write in same TX for atomicity — запрет #10).
	if err := uc.relations.EmitWriteTx(ctx, tx, systemAdminTuples(string(subject))); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("fga emit write: %w", err)
	}

	// Emit the durable audit_outbox compliance row in the SAME tx (запрет #10)
	// — atomic with the grant + fga-outbox row. Reactivate emits the same
	// iam.cluster_admin.granted type as a fresh grant (compliance: "admin
	// granted again"); an idempotent no-op (already active) emits nothing.
	if changed && uc.audit != nil {
		if err := uc.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType: auditEventClusterAdminGranted,
			Payload: clusterAdminAuditPayload(
				grantedBy, string(subject), string(grant.ID)),
		}); err != nil {
			return domain.ClusterAdminGrant{}, fmt.Errorf("audit emit grant: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("commit: %w", err)
	}
	return grant, nil
}

// systemAdminTuples — FGA tuple shape for cluster system_admin grant.
func systemAdminTuples(subjectID string) []service.RelationTuple {
	return []service.RelationTuple{
		{
			User:     "user:" + subjectID,
			Relation: "system_admin",
			Object:   "cluster:" + domain.ClusterSingletonID,
		},
	}
}
