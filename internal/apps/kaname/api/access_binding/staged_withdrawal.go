// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"google.golang.org/protobuf/types/known/anypb"
)

// kaname#1034: тот же actual LRO worker, но полный ledger обнаруживается до
// authority fences. Публичные prechecks/делегированный путь не подменяются.
func (u *DeleteAccessBindingUseCase) WithBindingWithdrawal(p kaname.BindingWithdrawalRunner) *DeleteAccessBindingUseCase {
	u.withdrawal = p
	return u
}
func (u *RevokeAccessBindingUseCase) WithBindingWithdrawal(p kaname.BindingWithdrawalRunner) *RevokeAccessBindingUseCase {
	u.withdrawal = p
	return u
}
func (h *Handler) WithBindingWithdrawal(p kaname.BindingWithdrawalRunner) *Handler {
	h.delete.WithBindingWithdrawal(p)
	h.revoke.WithBindingWithdrawal(p)
	return h
}
func (u *DeleteAccessBindingUseCase) withdrawStaged(ctx context.Context, id domain.AccessBindingID, actor string) error {
	_, err := u.withdrawal.WithdrawBinding(ctx, id, kaname.BindingWithdrawalDelete, actor, stagedRemovalAuthority(u.delegated), func(ctx context.Context, w Writer, b domain.AccessBinding) error {
		if err := w.EmitReconcileEvent(ctx, shared.ReconcileEventDelete, "iam.accessBinding", string(id)); err != nil {
			return err
		}
		if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, b.Subjects, "binding_revoke", "binding_delete"); err != nil {
			return err
		}
		revoker := actor
		if revoker == "" {
			revoker = string(b.GrantedByUserID)
		}
		return revokedAuditFor(ctx, w, b.Subjects, revoker, b)
	})
	return err
}
func (u *RevokeAccessBindingUseCase) withdrawStaged(ctx context.Context, id domain.AccessBindingID, actor string) (*anypb.Any, error) {
	out, err := u.withdrawal.WithdrawBinding(ctx, id, kaname.BindingWithdrawalRevoke, actor, stagedRemovalAuthority(u.delegated), func(ctx context.Context, w Writer, b domain.AccessBinding) error {
		if err := emitSubjectChangeFor(ctx, w.AccessBindingsW().EmitSubjectChangeEvent, b.Subjects, "binding_revoke", "binding_delete"); err != nil {
			return err
		}
		revoker := actor
		if revoker == "" {
			revoker = string(b.GrantedByUserID)
		}
		if revoker == "" {
			revoker = "system:revoke"
		}
		return revokedAuditFor(ctx, w, b.Subjects, revoker, b)
	})
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return marshalAB(out)
}

// Каждый Reader этого адаптера — тот же transaction snapshot. Закрытие
// короткого read scope не откатывает transaction владельца runner.
type bindingScopedRepo struct {
	Repo
	writer Writer
}
type bindingScopedReader struct{ Reader }

func (bindingScopedReader) Rollback(context.Context) error { return nil }
func (r bindingScopedRepo) Reader(context.Context) (Reader, error) {
	return bindingScopedReader{Reader: r.writer}, nil
}
func (bindingScopedRepo) Writer(context.Context) (Writer, error) {
	return nil, errors.New("nested binding writer is forbidden")
}
func stagedRemovalAuthority(delegated *DelegatedGrantPath) func(context.Context, Writer, clients.RelationStore, domain.AccessBinding) error {
	return func(ctx context.Context, w Writer, native clients.RelationStore, b domain.AccessBinding) error {
		repo := bindingScopedRepo{writer: w}
		var path *DelegatedGrantPath
		if delegated != nil {
			path = NewDelegatedGrantPath(repo, native)
		}
		return removalAuthority(ctx, repo, native, path, b)
	}
}
