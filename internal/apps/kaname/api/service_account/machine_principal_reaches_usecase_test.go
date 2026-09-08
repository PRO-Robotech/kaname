// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// machine_principal_reaches_usecase_test.go — ServiceAccountService Update /
// Delete must not re-decide authorization in-service.
//
// The model gates both: the api-gateway Checks `v_update` / `v_delete` on
// `iam_service_account:<service_account_id>` (permission catalog; locked by
// gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go). The
// removed `authzguard.RequireOwnerMatchesPrincipal` re-decided them from the
// owning account's `owner_user_id`.
//
// This pair is the sharpest case of the class: managing service accounts is
// exactly the work an automation principal is provisioned for, and the guard
// made it unreachable for one by construction.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func saNonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
		"delegated_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000dlgt"}),
	}
}

func TestUpdateServiceAccount_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range saNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewUpdateServiceAccountUseCase(newLcsRepo(domain.Labels{"team": "billing"}), newLcsOps())
			op, err := uc.Execute(ctx, UpdateServiceAccountInput{
				ID:         lcsSaID,
				Labels:     domain.Labels{"team": "payments"},
				UpdateMask: []string{"labels"},
			})
			require.NoError(t, err,
				"ServiceAccountService.Update is gated by v_update@iam_service_account at "+
					"the gateway; the use-case must not re-decide access from accounts.owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

func TestDeleteServiceAccount_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range saNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
			op, err := uc.Execute(ctx, lcsSaID)
			require.NoError(t, err,
				"ServiceAccountService.Delete is gated by v_delete@iam_service_account at the gateway")
			assert.NotNil(t, op)
		})
	}
}

func TestServiceAccountMutations_AnonymousStillRejected(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		uc := NewUpdateServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
		_, err := uc.Execute(context.Background(), UpdateServiceAccountInput{
			ID: lcsSaID, UpdateMask: []string{"labels"},
		})
		require.Error(t, err)
	})
	t.Run("delete", func(t *testing.T) {
		uc := NewDeleteServiceAccountUseCase(newLcsRepo(nil), newLcsOps())
		_, err := uc.Execute(context.Background(), lcsSaID)
		require.Error(t, err)
	})
}
