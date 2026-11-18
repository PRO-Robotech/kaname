// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package group

import (
	"context"
	"errors"
	"log/slog"

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
		if errors.Is(result, kaname.ErrAuthorityClassificationChanged) && !errors.Is(result, iamerr.ErrAborted) {
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
	return shared.ExecuteConfiguredPreparedWrite(ctx, u.policy.factory, func(attempt context.Context) (kaname.Writer, error) {
		return u.policy.factory.GroupAdditionAuthorityWriter(attempt, m, actor)
	}, func(attempt context.Context, w kaname.Writer) error {
		if err := grantpolicy.RequireGroupAddition(attempt, w, actor, m); err != nil { return err }
		return body(attempt, w)
	})
}
