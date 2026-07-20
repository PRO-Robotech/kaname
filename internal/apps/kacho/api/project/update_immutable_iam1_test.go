// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// update_immutable_iam1_test.go — redesign-2026 F3 (IAM-1-08): Project.accountId
// is hard-immutable. Update(update_mask=["accountId"]) → sync INVALID_ARGUMENT
// with the exact contract text "accountId is immutable after Project.Create"
// (immutable-switch fires BEFORE corevalidate.UpdateMask; camelCase field name
// per api-conventions.md JSON surface). There is NO Move RPC — the only path to
// change account_id is absent by construction.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

func TestProject_IAM_1_08_AccountIDImmutable_ExactText(t *testing.T) {
	repo := &authzProjRepo{ownerUserID: authzOwnerID}
	uc := NewUpdateProjectUseCase(repo, newFakeOpsRepoProj()).WithRelationStore(newStubFGA(), nil)
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOwnerID})

	for _, field := range []string{"accountId", "account_id"} {
		op, err := uc.Execute(ctx, UpdateProjectInput{
			ID:         authzProjID,
			UpdateMask: []string{field},
		})
		require.Error(t, err, "mask=[%q] must reject", field)
		assert.Nil(t, op)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code(), "mask=[%q]", field)
		// Contract text (api-conventions.md): camelCase field, exact phrasing.
		assert.Equal(t, "accountId is immutable after Project.Create", st.Message(),
			"mask=[%q] contract text", field)
	}
}
