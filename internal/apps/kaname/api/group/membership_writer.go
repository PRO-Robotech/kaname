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

type membershipWriterSelection struct {
	configured bool
	factory    kaname.GroupMembershipWriterFactory
}

func (s membershipWriterSelection) run(ctx context.Context, repo Repo, m domain.GroupMember, body func(context.Context, Writer) error) (result error) {
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
			return errors.New("group membership participant is not wired")
		}
		w, err = s.factory.GroupMembershipWriter(ctx, m)
	} else {
		w, err = repo.Writer(ctx)
	}
	if err != nil {
		return err
	}
	if w == nil || (reflect.ValueOf(w).Kind() == reflect.Pointer && reflect.ValueOf(w).IsNil()) {
		return errors.New("group membership writer is absent")
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
func (u *AddMemberUseCase) WithMembershipWriter(f kaname.GroupMembershipWriterFactory) *AddMemberUseCase {
	u.membershipWriter = membershipWriterSelection{configured: true, factory: f}
	return u
}
func (u *RemoveMemberUseCase) WithMembershipWriter(f kaname.GroupMembershipWriterFactory) *RemoveMemberUseCase {
	u.membershipWriter = membershipWriterSelection{configured: true, factory: f}
	return u
}

// WithMembershipWriter подключает реальные LRO workers. kaname#1034: выбор
// protocol не заменяет существующий R3 и не включает semantic gates.
func (h *Handler) WithMembershipWriter(f kaname.GroupMembershipWriterFactory) *Handler {
	h.addMember.WithMembershipWriter(f)
	h.removeMember.WithMembershipWriter(f)
	return h
}
