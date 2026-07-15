// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — txworker.go: generic Write-TX scaffolding для worker'ов
// async-операций (doCreate / doUpdate / doDelete / etc).
//
// Заменяет ~12 LOC boilerplate'а begin→commit→rollback→committed flag,
// повторяющегося в 15+ worker'ах через все 7 ресурсных пакетов
// (account / project / user / sa / group / role / access_binding).
package shared

import (
	"context"

	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// DoWithWriteTx оборачивает стандартный writer-tx паттерн вокруг одной
// мутации: Begin → action → Commit (если action вернул nil) или Rollback
// (если action вернул err / panic — defer-Rollback срабатывает на любом
// not-committed возврате).
//
// Использование (account/create.go::doCreate):
//
//	created, err := shared.DoWithWriteTx(ctx, u.repo,
//	    func(ctx context.Context, w kachorepo.Writer) (domain.Account, error) {
//	        return w.AccountsW().Insert(ctx, a)
//	    })
//	if err != nil { return nil, err }
//	// post-commit hooks here (e.g. relationhook)
//	return marshalAccount(created)
//
// Generic T — domain-тип, возвращаемый action'ом. Go infer'ит его из closure.
//
// Все ошибки из репо (action error + Writer/Commit) маппятся через
// MapRepoErr — caller получает уже gRPC-status.
func DoWithWriteTx[T any](
	ctx context.Context,
	repo kachorepo.Repository,
	action func(ctx context.Context, w kachorepo.Writer) (T, error),
) (T, error) {
	var zero T
	w, err := repo.Writer(ctx)
	if err != nil {
		return zero, MapRepoErr(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()

	result, err := action(ctx, w)
	if err != nil {
		return zero, MapRepoErr(err)
	}
	if err := w.Commit(ctx); err != nil {
		return zero, MapRepoErr(err)
	}
	committed = true
	return result, nil
}

// DoWithWriteTxVoid — вариант для action'ов без возвращаемого domain-объекта
// (например, doDelete). Возвращает только error.
//
// Использование (account/delete.go::doDelete):
//
//	if err := shared.DoWithWriteTxVoid(ctx, u.repo,
//	    func(ctx context.Context, w kachorepo.Writer) error {
//	        return w.AccountsW().Delete(ctx, id)
//	    }); err != nil {
//	    return nil, err
//	}
//	return anypb.New(&emptypb.Empty{})
func DoWithWriteTxVoid(
	ctx context.Context,
	repo kachorepo.Repository,
	action func(ctx context.Context, w kachorepo.Writer) error,
) error {
	_, err := DoWithWriteTx(ctx, repo, func(ctx context.Context, w kachorepo.Writer) (struct{}, error) {
		return struct{}{}, action(ctx, w)
	})
	return err
}
