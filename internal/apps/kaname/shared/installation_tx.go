// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"context"
	"errors"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// DoWithInstallationWriteTxVoid сохраняет прежнее отображение отказов репозитория.
// Отсутствие typed factory закрывает вход; ошибочный Commit не повторяет тело.
func DoWithInstallationWriteTxVoid(ctx context.Context, repo kaname.Repository, kind kaname.AuthorityOperation, fn func(context.Context, kaname.Writer) error) error {
	return DoWithObservedInstallationWriteTxVoid(ctx, repo, kind, fn, nil)
}

// DoWithObservedInstallationWriteTxVoid передаёт наблюдателю первичную ошибку, сохранённую до RPC-преобразования.
// Наблюдатель может использовать её тип для диагностики. Текст может содержать данные хранилища.
func DoWithObservedInstallationWriteTxVoid(ctx context.Context, repo kaname.Repository, kind kaname.AuthorityOperation, fn func(context.Context, kaname.Writer) error, observeFailure func(error)) error {
	var primaryErr error
	err := func() (err error) {
		if err := ctx.Err(); err != nil {
			return err
		}
		factory, ok := repo.(kaname.InstallationAuthorityWriterFactory)
		if !ok {
			return kaname.ErrInvalidAuthorityFencePlan
		}
		w, err := factory.InstallationAuthorityWriter(ctx, kind)
		if err != nil {
			return err
		}
		committed := false
		defer func() {
			if !committed {
				primaryErr = err
				err = errors.Join(err, w.Rollback(ctx))
			}
		}()
		if err = fn(ctx, w); err != nil {
			return err
		}
		if err = w.Commit(ctx); err != nil {
			return err
		}
		committed = true
		return nil
	}()
	if err != nil {
		mappedErr := MapRepoErrAt(ctx, err)
		if observeFailure != nil {
			if primaryErr == nil {
				primaryErr = err
			}
			observeFailure(primaryErr)
		}
		return mappedErr
	}
	return nil
}
