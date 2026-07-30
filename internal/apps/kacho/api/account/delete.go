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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	// Anti-anon floor (defence-in-depth against a mis-wired listener). WHO may
	// delete this account is decided by the MODEL, not here: the api-gateway
	// resolves account_id and Checks `v_delete@account:<id>` before iam is
	// dialed (permission catalog). The former in-service
	// `RequireOwnerMatchesPrincipal(existing.OwnerUserID)` re-decided that from
	// a DB column — narrower than the model, unrevocable, invisible to audit,
	// and unsatisfiable by any machine principal — see security.md
	// «Авторизация живёт в МОДЕЛИ, а не в самодельных проверках».
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, err
	}
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	// Existence pre-check (NOT authz): a well-formed-but-absent id resolves to a
	// sync NotFound here instead of an async Operation error (api-conventions:
	// well-formed-но-нет → NotFound через repo.Get).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	_, err = rd.Accounts().Get(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
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
//
// Step 1 reads PAGES until the scope is empty; see the loop for why it re-reads the
// first page instead of following a cursor.

// accountBindingRevokePageSize / accountBindingRevokeMaxPasses — the drain bounds.
// The page size is the platform maximum for a list; the pass ceiling turns a
// pathological account into a REFUSAL naming the situation, never into a silent
// partial delete.
const (
	accountBindingRevokePageSize  = 1000
	accountBindingRevokeMaxPasses = 50
)

func revokeAccountOwnerTuples(ctx context.Context, w Writer, id domain.AccountID) error {
	var fgaDeletes []service.RelationTuple
	// Drain, do not sample. The read used to take ONE page and drop the continuation
	// token, then delete exactly what it had read — so on an account carrying more
	// bindings than a page, everything past the page kept its row AND its emitted
	// tuples while the operation reported complete success: no error, no counter, no
	// line. Nothing repairs that afterwards. access_bindings carry no foreign key to
	// accounts, so no cascade reaches them; the periodic reconcile keeps
	// re-materializing the survivors precisely because their rows are still active;
	// and a surviving binding pins the subject it names, which then cannot be deleted
	// either.
	//
	// The page was also not the "handful" the dropped token was taken to mean: the
	// query filters by scope alone, so every revoked and expired binding ever
	// recorded on the account occupies it, oldest first — and the page size is the
	// platform maximum, so raising it is not an option.
	//
	// Re-reading the FIRST page each pass rather than following the token is
	// deliberate: this runs inside the writer-tx, so rows deleted by the previous
	// pass are already invisible to the next read, and a cursor would have to be
	// carried across deletions of the very rows it points at.
	for pass := 0; ; pass++ {
		if pass >= accountBindingRevokeMaxPasses {
			// Refuse loudly rather than report success on partial work — the whole
			// defect being fixed here is a truncation nobody could see.
			return status.Errorf(codes.FailedPrecondition,
				"Account %s carries more than %d access bindings; delete them before deleting the account",
				id, accountBindingRevokeMaxPasses*accountBindingRevokePageSize)
		}
		bindings, _, err := w.AccessBindings().ListByScope(
			ctx, domain.ResourceType("account"), string(id),
			abrepo.PageFilter{PageSize: accountBindingRevokePageSize},
		)
		if err != nil {
			return shared.MapRepoErr(err)
		}
		if len(bindings) == 0 {
			break
		}
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
