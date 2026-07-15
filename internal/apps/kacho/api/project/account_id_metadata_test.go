// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// account_id_metadata_test.go — Project Create/Update/Delete must stamp the
// owning account_id into the emitted *Metadata so corelib's exact-name
// extractAccountID denormalizes it into the operations.account_id column → the
// account-scoped module list (AccountService.ListAllOperations) includes the
// project's operations.
//
// These assert the *emitted Metadata* (captured in the fake ops repo) carries
// account_id, NOT the worker — account_id is stamped at op-build time and
// extracted in the single synchronous Create-INSERT path.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

const testAcc = "acc0000000000000abcd"

// projCreateMetaAccountID returns the account_id carried by the single
// CreateProjectMetadata captured in the fake ops repo.
func projCreateMetaAccountID(t *testing.T, opsRepo *fakeOpsRepoProj) string {
	t.Helper()
	opsRepo.mu.Lock()
	defer opsRepo.mu.Unlock()
	require.Len(t, opsRepo.ops, 1, "exactly one operation must be created")
	for _, op := range opsRepo.ops {
		md := &iamv1.CreateProjectMetadata{}
		require.NoError(t, op.Metadata.UnmarshalTo(md))
		return md.GetAccountId()
	}
	return ""
}

// Project.Create stamps account_id directly from the input AccountID.
// Update/Delete propagation (account from the loaded project) is proven
// end-to-end in the corelib-denormalization integration test (real
// repo) since the use-cases load the owning Account synchronously for authz.
func TestCreateProject_StampsAccountID(t *testing.T) {
	opsRepo := newFakeOpsRepoProj()
	uc := NewCreateProjectUseCase(newFakeProjRepo(), opsRepo)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "p"})

	op, err := uc.Execute(ctx, domain.Project{AccountID: testAcc, Name: "prj-ok"})
	require.NoError(t, err)
	require.NotNil(t, op)

	assert.Equal(t, testAcc, projCreateMetaAccountID(t, opsRepo),
		"CreateProjectMetadata.account_id must equal the input AccountID")
}
