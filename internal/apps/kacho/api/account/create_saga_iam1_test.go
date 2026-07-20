// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// create_saga_iam1_test.go — redesign-2026 F2 (IAM-1-04): Account.Create is a
// one-shot saga. In a single writer-tx it co-commits the Account, a default
// "default" Project, and the owner AccessBinding (account-scoped,
// deletionProtection=true). The Operation.metadata (CreateAccountMetadata)
// carries BOTH accountId AND defaultProjectId, available before done (so the
// client does not have to List the default project).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestAccount_IAM_1_04_CreateSaga_DefaultProjectAndMetadata(t *testing.T) {
	repo := newFakeRepo()
	uc := NewCreateAccountUseCase(repo, newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: iam1Principal})

	op, err := uc.Execute(ctx, domain.Account{Name: "acme-prod"})
	require.NoError(t, err)
	require.NotNil(t, op)

	// metadata carries BOTH ids, available BEFORE done (client does not List).
	require.NotNil(t, op.Metadata)
	md := &iamv1.CreateAccountMetadata{}
	require.NoError(t, op.Metadata.UnmarshalTo(md))
	assert.NotEmpty(t, md.GetAccountId(), "metadata.accountId present before done")
	assert.NotEmpty(t, md.GetDefaultProjectId(), "metadata.defaultProjectId present before done")
	assert.True(t, len(md.GetAccountId()) >= 3 && md.GetAccountId()[:3] == domain.PrefixAccount)
	assert.True(t, len(md.GetDefaultProjectId()) >= 3 && md.GetDefaultProjectId()[:3] == domain.PrefixProject)

	// Wait for the async saga worker.
	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	// default Project co-committed: name=="default", accountId==metadata.accountId.
	projects := repo.projectInsertsSnapshot()
	require.Len(t, projects, 1, "exactly one default project co-committed by the saga")
	assert.Equal(t, domain.ProjectName("default"), projects[0].Name)
	assert.Equal(t, domain.AccountID(md.GetAccountId()), projects[0].AccountID,
		"default project belongs to the created account")
	assert.Equal(t, domain.ProjectID(md.GetDefaultProjectId()), projects[0].ID,
		"default project id matches metadata.defaultProjectId")

	// owner AccessBinding still co-committed, account-scoped, deletion-protected.
	bindings := repo.ownerBindingsSnapshot()
	require.Len(t, bindings, 1)
	assert.Equal(t, domain.SubjectID(iam1Principal), bindings[0].SubjectID)
	assert.Equal(t, domain.ScopeAccount, bindings[0].Scope)
	assert.True(t, bindings[0].DeletionProtection, "owner binding is deletion-protected")
}
