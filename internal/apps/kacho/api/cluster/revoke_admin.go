// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// revoke_admin.go — RevokeAdminUseCase (InternalClusterService.RevokeAdmin).
//
// Handles the self-revoke, last-admin, never-admin, already-revoked and
// happy-path cases.
//
// Flow (synchronous within Execute):
//  1. Sync validation: subject_type must be USER, subject_id format.
//  2. Begin TX → Revoke (CAS with self-revoke / last-admin / already-revoked guards) →
//     EmitDeleteTx (FGA outbox) → commit.
//  3. Map sentinel errors (ErrSelfRevoke → FailedPrecondition,
//     ErrLastAdmin → FailedPrecondition, ErrNotFound → NotFound).
//  4. Create Operation record (done=true) and return to caller.
//
// Synchronous pattern: same as GrantAdmin. The mutation is a single CAS UPDATE
// on one row and completes in milliseconds — no async worker needed. Tests
// check status.Code(err) on the direct handler return value, which requires
// synchronous execution.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// RevokeAdminUseCase — orchestrates RevokeAdmin synchronously.
type RevokeAdminUseCase struct {
	writer    grantWriter
	relations relationOutboxEmitter
	txb       service.TxBeginner
	opsRepo   operations.Repo
	// adminCheck — defense-in-depth ReBAC system_admin@cluster gate. nil →
	// fail-closed (requireClusterSystemAdmin denies). See admin_authz.go.
	adminCheck adminChecker
	// audit — durable audit_outbox emitter. nil → no audit row.
	audit auditEmitter
}

// NewRevokeAdminUseCase — constructor.
func NewRevokeAdminUseCase(
	w grantWriter,
	relations relationOutboxEmitter,
	txb service.TxBeginner,
	opsRepo operations.Repo,
) *RevokeAdminUseCase {
	return &RevokeAdminUseCase{writer: w, relations: relations, txb: txb, opsRepo: opsRepo}
}

// WithAuditEmitter — wires the durable audit_outbox emitter.
// Composition-root only. nil emitter → audit emit is skipped.
func (uc *RevokeAdminUseCase) WithAuditEmitter(a auditEmitter) *RevokeAdminUseCase {
	uc.audit = a
	return uc
}

// WithAdminChecker — wires the defense-in-depth ReBAC system_admin gate.
// Composition-root only (cmd/kacho-iam/wiring.go). nil checker stays
// fail-closed.
func (uc *RevokeAdminUseCase) WithAdminChecker(c adminChecker) *RevokeAdminUseCase {
	uc.adminCheck = c
	return uc
}

// Execute — sync validation + sync domain mutation + Operation envelope.
func (uc *RevokeAdminUseCase) Execute(
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
	// D-2: only USER is supported in this version.
	if subjectType != iamv1.ClusterGrantSubjectType_USER {
		return nil, shared.InvalidArg("subject_type",
			"only 'user' supported in this version")
	}
	if subjectID == "" {
		return nil, shared.InvalidArg("subject_id", "required")
	}
	if !subjectIDRe.MatchString(subjectID) {
		return nil, shared.InvalidArg("subject_id",
			fmt.Sprintf("must match ^usr[0-9a-hjkmnp-tv-z]{17}$ (got %q)", subjectID))
	}
	sid := domain.SubjectID(subjectID)

	// Principal (for D-5 self-revoke guard). The authZ gate above already
	// proved a non-empty authenticated principal — no anonymous→bootstrap
	// coercion (that silently accepted unauthenticated callers and is removed).
	principal := authzguard.PrincipalUserID(ctx)

	// Perform domain mutation synchronously.
	grant, err := uc.doRevoke(ctx, sid, principal)
	if err != nil {
		return nil, err
	}

	// Build and persist Operation (done=true immediately — sync mutation).
	meta, merr := anypb.New(&iamv1.RevokeClusterAdminMetadata{
		ClusterAdminGrantId: string(grant.ID),
		SubjectId:           subjectID,
	})
	if merr != nil {
		return nil, fmt.Errorf("marshal revoke metadata: %w", merr)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke cluster admin from user %s", subjectID),
		&iamv1.RevokeClusterAdminMetadata{
			ClusterAdminGrantId: string(grant.ID),
			SubjectId:           subjectID,
		},
	)
	if oerr != nil {
		return nil, oerr
	}
	op.Done = true
	op.Response = meta

	if err := uc.opsRepo.Create(ctx, op); err != nil {
		// Non-fatal: mutation already committed; return op without persisting.
		// Log so a later OperationService.Get(op.id) returning NotFound is
		// traceable to this persistence failure (CWE-390: no silent swallow).
		slog.ErrorContext(ctx, "cluster RevokeAdmin: operation persist failed",
			"operation_id", op.ID, "err", err.Error())
	}

	return shared.OperationToProto(&op), nil
}

// doRevoke — runs revoke (with D-5/D-6/D-12 guards) within a single TX.
func (uc *RevokeAdminUseCase) doRevoke(
	ctx context.Context,
	subject domain.SubjectID,
	principalID string,
) (domain.ClusterAdminGrant, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	grant, rerr := uc.writer.Revoke(ctx, tx, subject, principalID)
	if rerr != nil {
		// Map sentinel errors to gRPC codes before shared.MapRepoErr, because
		// ErrSelfRevoke and ErrLastAdmin are their own sentinels (not wrapped in
		// ErrFailedPrecondition) — shared.MapRepoErr does not recognise them.
		switch {
		case stderrors.Is(rerr, iamerr.ErrSelfRevoke):
			return domain.ClusterAdminGrant{}, shared.MapRepoErr(
				iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%s", iamerr.StripSentinel(rerr)))
		case stderrors.Is(rerr, iamerr.ErrLastAdmin):
			return domain.ClusterAdminGrant{}, shared.MapRepoErr(
				iamerr.Wrapf(iamerr.ErrFailedPrecondition, "%s", iamerr.StripSentinel(rerr)))
		default:
			return domain.ClusterAdminGrant{}, shared.MapRepoErr(rerr)
		}
	}

	// Emit FGA delete-tuple outbox row in same TX (запрет #10 — atomicity).
	if err := uc.relations.EmitDeleteTx(ctx, tx, systemAdminTuples(string(subject))); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("fga emit delete: %w", err)
	}

	// Emit the durable audit_outbox compliance row in the SAME tx (запрет #10).
	// A reached-here revoke is always a real committed CAS hit (an idempotent /
	// already-revoked path errors out above before this point), so emit
	// unconditionally on the success path. actor = the verified revoker.
	if uc.audit != nil {
		if err := uc.audit.EmitTx(ctx, tx, service.AuditEvent{
			EventType: auditEventClusterAdminRevoked,
			Payload: clusterAdminAuditPayload(
				principalID, string(subject), string(grant.ID)),
		}); err != nil {
			return domain.ClusterAdminGrant{}, fmt.Errorf("audit emit revoke: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("commit: %w", err)
	}
	return grant, nil
}
