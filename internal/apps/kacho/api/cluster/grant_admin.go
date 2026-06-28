// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// grant_admin.go — GrantAdminUseCase (InternalClusterService.GrantAdmin).
//
// Flow (synchronous within Execute):
//  1. Sync validations: subject_type USER only, subject_id format,
//     user exists in kacho_iam.users.
//  2. Begin TX → Grant → if !created && !active → Reactivate →
//     EmitWriteTx (FGA outbox) → commit.
//  3. Create Operation record (done=true) and return to caller.
//
// Idempotency:
//   - Grant returns (row, false, nil) if ON CONFLICT fires.
//   - If the existing row IsActive → no further write, return it.
//   - If the existing row !IsActive (revoked history) → Reactivate within
//     the same TX (re-activates in-place, same id).
//
// Operation: returned immediately with done=true (no async worker needed —
// the mutation is simple single-row and fast).

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho-corelib/operations"

	operationpb "github.com/PRO-Robotech/kacho-corelib/proto/gen/go/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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

	// Perform domain mutation synchronously.
	grant, err := uc.doGrant(ctx, sid, principal)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}

	// Build and persist Operation (done=true immediately — sync mutation).
	meta, merr := anypb.New(&iamv1.GrantClusterAdminMetadata{
		ClusterAdminGrantId: string(grant.ID),
		SubjectId:           subjectID,
	})
	if merr != nil {
		return nil, fmt.Errorf("marshal grant metadata: %w", merr)
	}

	op, oerr := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Grant cluster admin to user %s", subjectID),
		&iamv1.GrantClusterAdminMetadata{
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
		_ = err
	}

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
