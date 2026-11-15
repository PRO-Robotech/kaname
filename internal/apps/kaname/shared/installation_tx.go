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
		return MapRepoErrAt(ctx, err)
	}
	return nil
}
