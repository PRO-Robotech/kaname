// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package shared — txworker.go: generic Write-TX scaffolding для worker'ов
// async-операций (doCreate / doUpdate / doDelete / etc).
//
// Заменяет ~12 LOC boilerplate'а begin→commit→rollback→committed flag,
// повторяющегося в 15+ worker'ах через все 7 ресурсных пакетов
// (account / project / user / sa / group / role / access_binding).
package shared

import (
	"context"
	"reflect"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"

	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// DoWithWriteTx оборачивает стандартный writer-tx паттерн вокруг одной
// мутации: Begin → action → Commit (если action вернул nil) или Rollback
// (если action вернул err / panic — defer-Rollback срабатывает на любом
// not-committed возврате).
//
// Использование (account/create.go::doCreate):
//
//	created, err := shared.DoWithWriteTx(ctx, u.repo,
//	    func(ctx context.Context, w kanamerepo.Writer) (domain.Account, error) {
//	        return w.AccountsW().Insert(ctx, a)
//	    })
//	if err != nil { return nil, err }
//	// post-commit hooks here
//	return marshalAccount(created)
//
// Generic T — domain-тип, возвращаемый action'ом. Go infer'ит его из closure.
//
// Все ошибки из репо (action error + Writer/Commit) маппятся через
// MapRepoErrAt на контексте, на котором шли вызовы, — caller получает уже
// gRPC-status, и отказ хранилища на кончившемся контексте приходит
// недоступностью, а не поломкой (kaname#383).
func DoWithWriteTx[T any](
	ctx context.Context,
	repo kanamerepo.Repository,
	action func(ctx context.Context, w kanamerepo.Writer) (T, error),
) (T, error) {
	var zero T
	if prepared, ok := repo.(kanamerepo.PreparedWriteRepository); ok {
		var result T
		err := prepared.RunPreparedWrite(ctx, func(attempt context.Context, w kanamerepo.Writer) error {
			result = zero
			value, err := action(attempt, w)
			if err == nil { result = value }
			return err
		})
		if err != nil { return zero, MapRepoErrAt(ctx, err) }
		return result, nil
	}
	w, err := repo.Writer(ctx)
	if err != nil {
		return zero, MapRepoErrAt(ctx, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()

	result, err := action(ctx, w)
	if err != nil {
		return zero, MapRepoErrAt(ctx, err)
	}
	if err := w.Commit(ctx); err != nil {
		return zero, MapRepoErrAt(ctx, err)
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
//	    func(ctx context.Context, w kanamerepo.Writer) error {
//	        return w.AccountsW().Delete(ctx, id)
//	    }); err != nil {
//	    return nil, err
//	}
//	return anypb.New(&emptypb.Empty{})
func DoWithWriteTxVoid(
	ctx context.Context,
	repo kanamerepo.Repository,
	action func(ctx context.Context, w kanamerepo.Writer) error,
) error {
	_, err := DoWithWriteTx(ctx, repo, func(ctx context.Context, w kanamerepo.Writer) (struct{}, error) {
		return struct{}{}, action(ctx, w)
	})
	return err
}

// ExecuteConfiguredPreparedWrite не выбирает legacy при отсутствующей capability.
// Ошибки до конца executor остаются исходными; публичный mapper вызывается снаружи.
func ExecuteConfiguredPreparedWrite(ctx context.Context, factory any, open func(context.Context) (kanamerepo.Writer, error), action func(context.Context, kanamerepo.Writer) error) error {
	if err := ctx.Err(); err != nil { return err }
	executor, ok := factory.(kanamerepo.PreparedWriteExecutor)
	if !ok || executor == nil { return iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared transaction executor unavailable") }
	value := reflect.ValueOf(executor)
	if value.Kind() == reflect.Pointer && value.IsNil() { return iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared transaction executor unavailable") }
	return executor.ExecutePreparedWrite(ctx, func(attempt context.Context) (kanamerepo.Writer, error) {
		w, err := open(attempt)
		if err != nil { return w, err }
		if w == nil { return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared writer unavailable") }
		value := reflect.ValueOf(w)
		if value.Kind() == reflect.Pointer && value.IsNil() { return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared writer unavailable") }
		return w, nil
	}, func(attempt context.Context, w kanamerepo.Writer) error {
		return action(context.WithValue(attempt, preparedBodyContextKey{}, true), w)
	})
}

type preparedBodyContextKey struct{}
func mapPreparedBodyError(ctx context.Context, err error) error {
	if ctx.Value(preparedBodyContextKey{}) == true { return err }
	return MapRepoErr(err)
}
