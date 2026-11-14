// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type lifecycleWriterSelection struct {
	configured bool
	factory    kaname.GroupLifecycleWriterFactory
}

func (s lifecycleWriterSelection) run(ctx context.Context, repo Repo, kind kaname.GroupMutation, g domain.Group, body func(context.Context, Writer) error) (result error) {
	defer func() {
		if result != nil {
			if errors.Is(result, kaname.ErrAuthorityClassificationChanged) {
				result = iamerr.Wrapf(iamerr.ErrAborted, "authority ownership changed during bounded writer entry")
			}
			result = shared.MapRepoErrAt(ctx, result)
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	var w Writer
	var err error
	if s.configured {
		if s.factory == nil || (reflect.ValueOf(s.factory).Kind() == reflect.Pointer && reflect.ValueOf(s.factory).IsNil()) {
			return errors.New("group lifecycle participant is not wired")
		}
		w, err = s.factory.GroupLifecycleWriter(ctx, kind, g)
	} else {
		w, err = repo.Writer(ctx)
	}
	if err != nil {
		return err
	}
	if w == nil || (reflect.ValueOf(w).Kind() == reflect.Pointer && reflect.ValueOf(w).IsNil()) {
		return errors.New("group lifecycle writer is absent")
	}
	// Отмена операции не должна оставлять TX/pool slot после выхода worker.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = body(ctx, w); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// kaname#1034: direct mutation и postcommit reconcile имеют разные TX.
func withGroupLifecycleTx[T any](ctx context.Context, s lifecycleWriterSelection, repo Repo, kind kaname.GroupMutation, g domain.Group, body func(context.Context, Writer) (T, error)) (out T, err error) {
	err = s.run(ctx, repo, kind, g, func(ctx context.Context, w Writer) error { var e error; out, e = body(ctx, w); return e })
	if err != nil {
		var zero T
		return zero, err
	}
	return out, nil
}
func (u *CreateGroupUseCase) WithLifecycleWriter(f kaname.GroupLifecycleWriterFactory) *CreateGroupUseCase {
	u.lifecycleWriter = lifecycleWriterSelection{true, f}
	return u
}
func (u *UpdateGroupUseCase) WithLifecycleWriter(f kaname.GroupLifecycleWriterFactory) *UpdateGroupUseCase {
	u.lifecycleWriter = lifecycleWriterSelection{true, f}
	return u
}
func (u *DeleteGroupUseCase) WithLifecycleWriter(f kaname.GroupLifecycleWriterFactory) *DeleteGroupUseCase {
	u.lifecycleWriter = lifecycleWriterSelection{true, f}
	return u
}
func (h *Handler) WithLifecycleWriter(f kaname.GroupLifecycleWriterFactory) *Handler {
	h.create.WithLifecycleWriter(f)
	h.update.WithLifecycleWriter(f)
	h.delete.WithLifecycleWriter(f)
	return h
}
