// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// machine_principal_reaches_usecase_test.go — RoleService Update / Delete must
// not re-decide authorization in-service.
//
// The model gates both: the api-gateway Checks `v_update` / `v_delete` on
// `iam_role:<role_id>` (permission catalog; locked by
// gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go). The
// removed `authzguard.RequireOwnerMatchesPrincipal` re-decided them from the
// owning account's `owner_user_id`.
//
// NOTE — the system-role refusals (`Update` → FailedPrecondition, `Delete` →
// writer-side) are resource-STATE checks, not authz, and are untouched.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

func roleNonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
		"delegated_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000dlgt"}),
	}
}

func TestUpdateRole_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range roleNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{"team": "billing"}), newRlFakeOps(), catalogfixture.Source())
			op, err := uc.Execute(ctx, UpdateRoleInput{
				ID:         rlUpdRoleID,
				Labels:     domain.Labels{"team": "payments"},
				UpdateMask: []string{"labels"},
			})
			require.NoError(t, err,
				"RoleService.Update is gated by v_update@iam_role at the gateway; "+
					"the use-case must not re-decide access from accounts.owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

func TestDeleteRole_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range roleNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteRoleUseCase(newRlUpdRepo(nil), newRlFakeOps())
			op, err := uc.Execute(ctx, rlUpdRoleID)
			require.NoError(t, err,
				"RoleService.Delete is gated by v_delete@iam_role at the gateway")
			assert.NotNil(t, op)
		})
	}
}

func TestRoleMutations_AnonymousStillRejected(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		uc := NewUpdateRoleUseCase(newRlUpdRepo(nil), newRlFakeOps(), catalogfixture.Source())
		_, err := uc.Execute(context.Background(), UpdateRoleInput{
			ID: rlUpdRoleID, UpdateMask: []string{"labels"},
		})
		require.Error(t, err)
	})
	t.Run("delete", func(t *testing.T) {
		uc := NewDeleteRoleUseCase(newRlUpdRepo(nil), newRlFakeOps())
		_, err := uc.Execute(context.Background(), rlUpdRoleID)
		require.Error(t, err)
	})
}
