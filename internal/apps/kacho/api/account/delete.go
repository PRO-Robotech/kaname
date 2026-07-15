// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// delete.go — DeleteAccountUseCase.
//
// Atomic DELETE-WHERE-NOT-EXISTS на уровне repo (см. accountWriter.Delete) —
// within-service инвариант на DB-уровне (запрет #10). Worker async, как и Create.

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// DeleteAccountUseCase.
type DeleteAccountUseCase struct {
	repo    Repo
	opsRepo operations.Repo
}

// NewDeleteAccountUseCase.
func NewDeleteAccountUseCase(r Repo, opsRepo operations.Repo) *DeleteAccountUseCase {
	return &DeleteAccountUseCase{repo: r, opsRepo: opsRepo}
}

// Execute — sync id-validate + create Operation + worker doDelete.
func (u *DeleteAccountUseCase) Execute(ctx context.Context, id domain.AccountID) (*operations.Operation, error) {
	// Anti-anon required + ownership check (account.owner_user_id == principal).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	// Account.Delete: only owner может удалить. Load existing account для проверки.
	// Если account не существует — return NotFound (no info leak).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	existing, err := rd.Accounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if err := authzguard.RequireOwnerMatchesPrincipal(ctx, string(existing.OwnerUserID)); err != nil {
		return nil, err
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Delete account %s", id),
		&iamv1.DeleteAccountMetadata{AccountId: string(id)},
	)
	if err != nil {
		return nil, err
	}
	if err := u.opsRepo.Create(ctx, op); err != nil {
		return nil, err
	}

	actor := authzguard.PrincipalUserID(ctx)
	operations.Run(ctx, u.opsRepo, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return u.doDelete(ctx, id, actor)
	})
	return &op, nil
}

func (u *DeleteAccountUseCase) doDelete(ctx context.Context, id domain.AccountID, actor string) (*anypb.Any, error) {
	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
		func(ctx context.Context, w Writer) error {
			// Symmetrically revoke the account's owner-tuples BEFORE deleting the
			// account row — otherwise the FGA `define admin: … or owner` derivation
			// leaves the ex-owner with standing admin on a deleted account.
			// access_bindings carry NO FK to accounts (cross-resource soft
			// ref), so the owner-binding row and its emitted-tuple ledger are NOT
			// cascade-dropped by the account DELETE — they must be revoked explicitly.
			if rerr := revokeAccountOwnerTuples(ctx, w, id); rerr != nil {
				return rerr
			}
			if derr := w.AccountsW().Delete(ctx, id); derr != nil {
				return derr
			}
			// Audit row atomic with the DELETE (запрет #10): a rolled-back
			// delete leaves no audit row claiming the account was removed.
			return w.EmitAuditEvent(ctx, service.AuditEvent{
				EventType:       auditEventAccountDeleted,
				TenantAccountID: string(id),
				Payload: map[string]any{
					"actor":         actor,
					"resource_type": "account",
					"resource_id":   string(id),
				},
			})
		}); err != nil {
		return nil, err
	}
	// DeleteOperation.response = Empty (parity с kacho-vpc/internal/apps/.../delete.go).
	return anypb.New(&emptypb.Empty{})
}

// revokeAccountOwnerTuples performs the symmetric FGA-tuple revoke for an account
// being deleted, all inside the caller's writer-tx (atomic with the account
// DELETE, ban #10):
//
//  1. For every account-scoped AccessBinding (resource_type='account',
//     resource_id=<A>) — the owner-binding co-committed by Account.Create plus any
//     other binding granted directly on the account — read its PERSISTED emitted-
//     tuple ledger (SelectEmittedTuples) and EmitFGARelationDelete on EXACTLY that
//     set, then DELETE the binding row (so the ledger rows cascade-drop). This is
//     the SAME byte-symmetric revoke AccessBinding.Delete performs, applied to every
//     binding the deleted account anchors.
//  2. Emit the delete of the cluster pointer
//     (cluster:cluster_kacho_root#cluster@account:<A>) — an ACCOUNT-lifecycle tuple
//     deliberately excluded from the owner-binding ledger (it must survive an
//     owner-binding revoke) but which MUST go when the account itself is deleted.
//
// FGA tuple deletes are idempotent (the drainer maps cannot_delete→success), so a
// re-run (at-least-once drain) is safe. Reads run BEFORE the account DELETE and the
// binding DELETE so the ledger rows are still present.
func revokeAccountOwnerTuples(ctx context.Context, w Writer, id domain.AccountID) error {
	const pageLimit = 1000 // account-scoped bindings are few (owner + a handful of grants)
	bindings, _, err := w.AccessBindings().ListByScope(
		ctx, domain.ResourceType("account"), string(id),
		abrepo.PageFilter{PageSize: pageLimit},
	)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	var fgaDeletes []service.RelationTuple
	for _, b := range bindings {
		stored, serr := w.AccessBindings().SelectEmittedTuples(ctx, b.ID)
		if serr != nil {
			return shared.MapRepoErr(serr)
		}
		for _, tp := range stored {
			fgaDeletes = append(fgaDeletes, service.RelationTuple{
				User: tp.User, Relation: tp.Relation, Object: tp.Object,
			})
		}
		// DELETE the binding row (its emitted-tuple ledger cascade-drops on the FK).
		if derr := w.AccessBindingsW().Delete(ctx, b.ID); derr != nil {
			return shared.MapRepoErr(derr)
		}
	}
	// Cluster pointer — account-lifecycle, not in any binding ledger.
	fgaDeletes = append(fgaDeletes, service.RelationTuple{
		User:     "cluster:cluster_kacho_root",
		Relation: "cluster",
		Object:   "account:" + string(id),
	})
	if emitErr := w.EmitFGARelationDelete(ctx, fgaDeletes); emitErr != nil {
		return shared.MapRepoErr(emitErr)
	}
	return nil
}
