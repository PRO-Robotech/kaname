// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package group

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type additionPolicySelection struct {
	configured bool
	factory    kaname.GroupAdditionAuthorityWriterFactory
}

func (u *AddMemberUseCase) WithGroupAdditionAuthorityWriter(f kaname.GroupAdditionAuthorityWriterFactory) *AddMemberUseCase {
	u.policy = additionPolicySelection{true, f}
	return u
}
func (h *Handler) WithGroupAdditionAuthorityWriter(f kaname.GroupAdditionAuthorityWriterFactory) *Handler {
	h.addMember.WithGroupAdditionAuthorityWriter(f)
	return h
}
func (u *AddMemberUseCase) runAddition(ctx context.Context, m domain.GroupMember, body func(context.Context, Writer) error) (result error) {
	if !u.policy.configured {
		return u.membershipWriter.run(ctx, u.repo, m, body)
	}
	defer func() {
		if errors.Is(result, kaname.ErrAuthorityClassificationChanged) {
			result = iamerr.Wrapf(iamerr.ErrAborted, "Authority classification changed")
		}
		if result != nil {
			// На проводе остаётся прежний закрытый статус; причину внутреннего
			// отказа сохраняет общий серверный журнал ошибок хранилища.
			result = shared.LogMappedErr(ctx, slog.Default(), "group.addMember.authority", result, shared.MapRepoErrAt(ctx, result))
		}
	}()
	if u.policy.factory == nil {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "Group addition authority writer unavailable")
	}
	actor := grantpolicy.Actor(ctx)
	w, err := u.policy.factory.GroupAdditionAuthorityWriter(ctx, m, actor)
	if err != nil {
		return err
	}
	if w == nil {
		return iamerr.Wrapf(iamerr.ErrUnavailable, "Group addition authority writer unavailable")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	}()
	if err = grantpolicy.RequireGroupAddition(ctx, w, actor, m); err != nil {
		return err
	}
	if err = body(ctx, w); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return w.Commit(ctx)
}
