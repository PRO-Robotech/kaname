// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"reflect"
)

type identityWriterSelection struct {
	configured bool
	factory    kaname.IdentityLifecycleWriterFactory
}

// Reader и остальные порты остаются исходными; меняется только открытие Writer.
// Тело, commit и отображение ошибок по-прежнему принадлежат shared.DoWithWriteTx.
func (s identityWriterSelection) repository(repo Repo, kind kaname.IdentityMutation, id domain.UserID) Repo {
	return identityWriterRepository{Repository: repo, selection: s, kind: kind, id: id}
}

type identityWriterRepository struct {
	kaname.Repository
	selection identityWriterSelection
	kind      kaname.IdentityMutation
	id        domain.UserID
}

func identityNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	default:
		return false
	}
}
func (r identityWriterRepository) Writer(ctx context.Context) (kaname.Writer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !r.selection.configured {
		return r.Repository.Writer(ctx)
	}
	if identityNil(r.selection.factory) {
		return nil, errors.New("identity lifecycle participant is not wired")
	}
	w, err := r.selection.factory.IdentityLifecycleWriter(ctx, r.kind, r.id)
	if err != nil {
		return nil, err
	}
	if identityNil(w) {
		return nil, errors.New("identity lifecycle writer is absent")
	}
	return w, nil
}
func (u *UpdateUserUseCase) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *UpdateUserUseCase {
	u.identityWriter = identityWriterSelection{true, f}
	return u
}
func (u *DeleteUserUseCase) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *DeleteUserUseCase {
	u.identityWriter = identityWriterSelection{true, f}
	return u
}
func (u *BlockUserUseCase) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *BlockUserUseCase {
	u.identityWriter = identityWriterSelection{true, f}
	return u
}
func (u *UnblockUserUseCase) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *UnblockUserUseCase {
	u.identityWriter = identityWriterSelection{true, f}
	return u
}
func (u *RemoveFromAccountUseCase) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *RemoveFromAccountUseCase {
	u.identityWriter = identityWriterSelection{true, f}
	return u
}
func (h *Handler) WithIdentityLifecycleWriter(f kaname.IdentityLifecycleWriterFactory) *Handler {
	h.update.WithIdentityLifecycleWriter(f)
	h.delete.WithIdentityLifecycleWriter(f)
	h.block.WithIdentityLifecycleWriter(f)
	h.unblock.WithIdentityLifecycleWriter(f)
	if h.remove != nil {
		h.remove.WithIdentityLifecycleWriter(f)
	}
	return h
}
