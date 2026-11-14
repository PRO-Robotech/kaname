// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

// Публичный Handler провязывает настоящий асинхронный worker. Отсутствующий
// participant не должен возвращать снятие членства на прежний Writer.
func TestIdentityRemoveHandlerUsesParticipantWithoutLegacyFallback(t *testing.T) {
	var typedNil *identitySelectionFactory
	selected := &identitySelectionFactory{err: errors.New("selected remove participant failure")}
	for name, factory := range map[string]kaname.IdentityLifecycleWriterFactory{
		"selected": selected, "nil": nil, "typed-nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			repo := &identitySelectionRepo{Repo: newUpdUserRepo()}
			ops := newUpdOpsRepo()
			h := NewHandler(nil, nil, NewUpdateUserUseCase(repo, ops), NewDeleteUserUseCase(repo, ops), nil,
				NewBlockUserUseCase(repo, ops), NewUnblockUserUseCase(repo, ops),
				NewRemoveFromAccountUseCase(repo, ops)).WithIdentityLifecycleWriter(factory)
			ctx := ownerCtx()
			op, err := h.RemoveFromAccount(ctx, &iamv1.RemoveUserFromAccountRequest{UserId: updUserID, AccountId: updAccountID})
			require.NoError(t, err)
			wait, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			require.NoError(t, operations.Wait(wait))
			got, err := ops.Get(ctx, op.GetId())
			require.NoError(t, err)
			require.True(t, got.Done)
			require.NotNil(t, got.Error)
			require.Zero(t, repo.opened)
			if name == "selected" {
				require.Equal(t, 1, selected.called)
				require.Equal(t, kaname.IdentityRemoveFromAccount, selected.kind)
				require.Equal(t, domain.UserID(updUserID), selected.id)
			}
		})
	}
}
