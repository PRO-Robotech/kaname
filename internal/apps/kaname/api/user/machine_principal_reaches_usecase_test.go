// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// machine_principal_reaches_usecase_test.go — UserService Update / Delete must
// not re-decide authorization in-service.
//
// The model gates both: the api-gateway Checks `v_update` / `v_delete` on
// `iam_user:<user_id>` (permission catalog; locked by
// gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go). The
// removed `authzguard.RequireOwnerMatchesPrincipal` re-decided them from the
// owning account's `owner_user_id`, which no machine principal can satisfy and
// which voided owner-granted delegation.
//
// NOTE — обе оставшиеся здесь самодельные развилки Delete с тех пор сняты.
// Гейт RPC ушёл с `v_delete` на `identity_remover` (#1131), а вслед за ним
// снята и «безаккаунтный удаляет только сам себя» (#1174): у неё не осталось
// предмета, а работала она отказом надзору облака. Предмет и пара утверждений —
// `account_less_delete_test.go`.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func usrNonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
		"delegated_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000dlgt"}),
	}
}

func TestUpdateUser_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range usrNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewUpdateUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
			op, err := uc.Execute(ctx, UpdateUserInput{
				ID:         domain.UserID(updUserID),
				Labels:     domain.Labels{"team": "payments"},
				UpdateMask: []string{"labels"},
			})
			require.NoError(t, err,
				"UserService.Update is gated by record_writer@iam_user at the gateway; "+
					"the use-case must not re-decide access from accounts.owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

// Delete of ANOTHER user (not self) — the branch the owner-equality guard sat
// in. A model-admitted non-owner must now get through it.
func TestDeleteUser_NonSelfNonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range usrNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
			op, err := uc.Execute(ctx, domain.UserID(updUserID))
			require.NoError(t, err,
				"UserService.Delete is gated by identity_remover@iam_user at the gateway "+
					"(#1131 — the verb v_delete named here before is gone from the type, #1189); "+
					"deleting someone else's user must not require being the account owner")
			assert.NotNil(t, op)
		})
	}
}

func TestUserMutations_AnonymousStillRejected(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		uc := NewUpdateUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
		_, err := uc.Execute(context.Background(), UpdateUserInput{
			ID: domain.UserID(updUserID), UpdateMask: []string{"labels"},
		})
		require.Error(t, err)
	})
	t.Run("delete", func(t *testing.T) {
		uc := NewDeleteUserUseCase(newUpdUserRepo(), newUpdOpsRepo())
		_, err := uc.Execute(context.Background(), domain.UserID(updUserID))
		require.Error(t, err)
	})
}
