// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// revoke_admin.go — RevokeAdminUseCase (InternalClusterService.RevokeAdmin).
//
// Handles the self-revoke, last-admin, never-admin, already-revoked and
// happy-path cases.
//
// Flow (synchronous within Execute):
//  1. Sync validation: subject_type (USER | SERVICE_ACCOUNT) + per-type
//     subject_id format.
//  2. Persist Operation (done=false) so the returned id is always queryable.
//  3. Begin TX → Revoke (CAS with self-revoke / last-admin / already-revoked guards) →
//     EmitDeleteTx (FGA outbox) → commit. On failure → MarkError the op.
//  4. Map sentinel errors (ErrSelfRevoke → FailedPrecondition,
//     ErrLastAdmin → FailedPrecondition, ErrNotFound → NotFound).
//  5. Complete the Operation (done=true) with the full metadata (the revoked
//     grant id) and the declared response (ClusterAdminGrant).
//
// Synchronous pattern: same as GrantAdmin. The mutation is a single CAS UPDATE
// on one row and completes in milliseconds — no async worker needed. Tests
// check status.Code(err) on the direct handler return value, which requires
// synchronous execution.
//
// «Synchronous» is about latency, NOT about skipping the persisted transition:
// the Operation row is created (done=false) and then flipped by a terminal
// write, exactly as in GrantAdmin. It used to be built in memory with
// done=true/response set and handed to Create — but Create writes `done` as the
// literal false and writes no response columns at all, so the RPC answered
// done:true over a row that said done=f, response_data=NULL, and a client
// following the documented poll protocol never finished.

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// RevokeAdminUseCase — orchestrates RevokeAdmin synchronously.
type RevokeAdminUseCase struct {
	writer    grantWriter
	relations relationOutboxEmitter
	txb       service.TxBeginner
	opsRepo   operationRepo
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
	opsRepo operationRepo,
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
	// Subject: USER or SERVICE_ACCOUNT, with a per-type id-format check.
	// A machine subject MUST be revocable — the platform seeds a permanent
	// cluster-admin grant for the bootstrap-admin ServiceAccount (migration
	// 0058), and refusing SERVICE_ACCOUNT here made that grant unrevocable
	// through the interface (see resolveSubject).
	styp, sid, err := resolveSubject(subjectType, subjectID)
	if err != nil {
		return nil, err
	}

	// Principal (for D-5 self-revoke guard). The authZ gate above already
	// proved a non-empty authenticated principal — no anonymous→bootstrap
	// coercion (that silently accepted unauthenticated callers and is removed).
	principal := authzguard.PrincipalUserID(ctx)

	// Persist the Operation (done=false) BEFORE the mutation — same reason as
	// GrantAdmin: the id handed to the caller must ALWAYS be queryable, and
	// persisting after the mutation left a committed revoke whose operation row
	// never existed when Create failed. The revoked grant.ID is not knowable
	// yet, so the initial metadata carries only subject_id; the terminal write
	// below replaces it with the full one.
	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke cluster admin from %s %s", styp, subjectID),
		&iamv1.RevokeClusterAdminMetadata{SubjectId: subjectID},
	)
	if oerr != nil {
		return nil, oerr
	}
	if err := uc.opsRepo.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	// Perform domain mutation synchronously.
	grant, err := uc.doRevoke(ctx, styp, sid, principal)
	if err != nil {
		// Record the terminal failure on the already-persisted op so a poll sees
		// a real error rather than a row that never completes. MapRepoErr is
		// idempotent on already-mapped sentinels and collapses any unmapped
		// error (begin tx / emit / commit) to the fixed opaque INTERNAL text, so
		// no pgx/SQL detail is persisted into op.error.
		gerr := shared.MapRepoErr(err)
		_ = uc.opsRepo.MarkError(ctx, op.ID, status.Convert(gerr).Proto())
		return nil, gerr
	}

	// Complete the Operation: done=true, metadata replaced by the full one (the
	// revoked grant id), response = the declared ClusterAdminGrant.
	meta, resp, merr := revokeOperationPayload(subjectID, grant)
	if merr != nil {
		return nil, merr
	}
	if err := uc.opsRepo.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
		// Non-fatal for the caller: the revoke committed and the row exists, so a
		// poll answers (done=false) and never NotFound. It is NOT self-healing —
		// the IAM orphan-resolver has no arm for cluster-admin metadata and skips
		// such rows — so this is logged loudly, never swallowed (CWE-390).
		slog.ErrorContext(ctx, "cluster RevokeAdmin: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// revokeOperationPayload — the terminal (metadata, response) pair declared by
// `InternalClusterService.RevokeAdmin` (metadata: RevokeClusterAdminMetadata,
// response: ClusterAdminGrant — the soft-revoked row, granted_until set).
func revokeOperationPayload(subjectID string, grant domain.ClusterAdminGrant) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.RevokeClusterAdminMetadata{
		ClusterAdminGrantId: string(grant.ID),
		SubjectId:           subjectID,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal revoke metadata: %w", err)
	}
	resp, err = anypb.New(clusterAdminGrantToProto(grant))
	if err != nil {
		return nil, nil, fmt.Errorf("marshal revoke response: %w", err)
	}
	return meta, resp, nil
}

// doRevoke — runs revoke (with D-5/D-6/D-12 guards) within a single TX.
func (uc *RevokeAdminUseCase) doRevoke(
	ctx context.Context,
	subjectType domain.GrantSubjectType,
	subject domain.SubjectID,
	principalID string,
) (domain.ClusterAdminGrant, error) {
	tx, err := uc.txb.Begin(ctx)
	if err != nil {
		return domain.ClusterAdminGrant{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after Commit

	grant, rerr := uc.writer.Revoke(ctx, tx, subjectType, subject, principalID)
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
	if err := uc.relations.EmitDeleteTx(ctx, tx, systemAdminTuples(subjectType, string(subject))); err != nil {
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
