// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// machine_principal_reaches_usecase_test.go — ProjectService.Delete must not
// re-decide authorization in-service.
//
// The model gates it: the api-gateway Checks `v_delete` on
// `project:<project_id>` (permission catalog; locked by
// gateway/internal/middleware/authz_iam_owner_guard_model_gate_test.go). The
// removed `authzguard.RequireOwnerMatchesPrincipal` re-decided it from the
// OWNING ACCOUNT's `owner_user_id` — a coarser criterion than the per-object
// relation the model resolves, and one no machine principal can ever satisfy.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func projNonOwnerCtxs() map[string]context.Context {
	return map[string]context.Context{
		"service_account": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "service_account", ID: "sva0000000000000bot1"}),
		"delegated_user": operations.WithPrincipal(context.Background(),
			operations.Principal{Type: "user", ID: "usr0000000000000dlgt"}),
	}
}

func TestDeleteProject_NonOwnerPrincipal_NotRejectedInService(t *testing.T) {
	for name, ctx := range projNonOwnerCtxs() {
		t.Run(name, func(t *testing.T) {
			uc := NewDeleteProjectUseCase(newLcpRepo(nil), newFakeOpsRepoProj())
			op, err := uc.Execute(ctx, domain.ProjectID(lcpProjID))
			require.NoError(t, err,
				"ProjectService.Delete is gated by v_delete@project at the gateway; "+
					"the use-case must not re-decide access from the owning account's owner_user_id")
			assert.NotNil(t, op)
		})
	}
}

func TestDeleteProject_AnonymousStillRejected(t *testing.T) {
	uc := NewDeleteProjectUseCase(newLcpRepo(nil), newFakeOpsRepoProj())
	_, err := uc.Execute(context.Background(), domain.ProjectID(lcpProjID))
	require.Error(t, err)
}
