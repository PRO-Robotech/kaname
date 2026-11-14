// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

type identitySelectionRepo struct {
	Repo
	opened int
}

func (r *identitySelectionRepo) Writer(context.Context) (Writer, error) {
	r.opened++
	return nil, errors.New("legacy route reached")
}

type identitySelectionFactory struct {
	called int
	kind   kaname.IdentityMutation
	id     domain.UserID
	writer Writer
	err    error
}

func (f *identitySelectionFactory) IdentityLifecycleWriter(_ context.Context, k kaname.IdentityMutation, id domain.UserID) (Writer, error) {
	f.called++
	f.kind = k
	f.id = id
	return f.writer, f.err
}

type identityNilWriter struct{ Writer }

func TestIdentityLifecycleSelectionFailsClosed(t *testing.T) {
	var typedNil *identitySelectionFactory
	var absentWriter *identityNilWriter
	for name, f := range map[string]kaname.IdentityLifecycleWriterFactory{
		"nil": nil, "typed-nil": typedNil, "nil-writer": &identitySelectionFactory{}, "typed-nil-writer": &identitySelectionFactory{writer: absentWriter},
	} {
		t.Run(name, func(t *testing.T) {
			r := &identitySelectionRepo{}
			w, err := (identityWriterSelection{true, f}).repository(r, kaname.IdentityUpdate, domain.UserID(updUserID)).Writer(context.Background())
			require.Error(t, err)
			require.Nil(t, w)
			require.Zero(t, r.opened)
		})
	}
	r := &identitySelectionRepo{}
	f := &identitySelectionFactory{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (identityWriterSelection{true, f}).repository(r, kaname.IdentityUpdate, domain.UserID(updUserID)).Writer(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, f.called)
	require.Zero(t, r.opened)
}

// Каждый настоящий Handler -> Execute -> асинхронный worker достигает нужного
// intent и сохраняет ошибку Operation. Неверная провязка вызвала бы legacy Writer.
func TestIdentityLifecycleHandlerRoutesAllFourWorkers(t *testing.T) {
	for _, kind := range []kaname.IdentityMutation{kaname.IdentityUpdate, kaname.IdentityDelete, kaname.IdentityBlock, kaname.IdentityUnblock} {
		t.Run(string(kind), func(t *testing.T) {
			repo := &identitySelectionRepo{Repo: newUpdUserRepo()}
			ops := newUpdOpsRepo()
			factory := &identitySelectionFactory{err: errors.New("selected participant failure")}
			h := NewHandler(nil, nil, NewUpdateUserUseCase(repo, ops), NewDeleteUserUseCase(repo, ops), nil, NewBlockUserUseCase(repo, ops), NewUnblockUserUseCase(repo, ops), nil).WithIdentityLifecycleWriter(factory)
			ctx := ownerCtx()
			var op *operationpb.Operation
			var err error
			switch kind {
			case kaname.IdentityUpdate:
				op, err = h.Update(ctx, &iamv1.UpdateUserRequest{UserId: updUserID, Labels: map[string]string{"tier": "gold"}})
			case kaname.IdentityDelete:
				op, err = h.Delete(ctx, &iamv1.DeleteUserRequest{UserId: updUserID})
			case kaname.IdentityBlock:
				op, err = h.Block(ctx, &iamv1.BlockUserRequest{UserId: updUserID})
			case kaname.IdentityUnblock:
				op, err = h.Unblock(ctx, &iamv1.UnblockUserRequest{UserId: updUserID})
			}
			require.NoError(t, err)
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			require.NoError(t, operations.Wait(wait))
			got, err := ops.Get(ctx, op.GetId())
			require.NoError(t, err)
			require.True(t, got.Done)
			require.NotNil(t, got.Error)
			require.Equal(t, 1, factory.called)
			require.Equal(t, kind, factory.kind)
			require.Equal(t, domain.UserID(updUserID), factory.id)
			require.Zero(t, repo.opened)
		})
	}
}
