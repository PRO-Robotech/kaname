// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// account_owner_binding_e2e_integration_test.go — use-case-level integration
// (testcontainers PG16) for RBAC explicit-model 2026 P6 C-01: Account.Create
// auto-creates the owner AccessBinding via the SAME writer-tx (co-commit) and the
// reconciler materializes its scope-self membership post-commit.
//
// Traces: C-01 (owner-binding present, deletion_protection=true, role=owner,
// scope=ACCOUNT, subject=creator) + reconcile scope-self verb-bearing tuple on
// account:<A>. Lives in the access_binding external test pkg to reuse the
// testcontainers + reconciler helpers.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repoacct "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestAccountCreate_P6_OwnerBinding_CoCommit_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	// Seed the creator user (needs a home account for the owner FK on its own
	// account; the NEW account created below is owned by this user).
	creator := mustSeedUser(t, ctx, pool, "p6own")

	createUC := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)

	// Owner-create: ownerUserId° is derived from the caller (redesign-2026 F1 —
	// output-only, NOT accepted in the Create body). The principal in octx becomes
	// the owner.
	octx := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(creator)})
	op, err := createUC.Execute(octx, domain.Account{
		Name: "acme-p6-own",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	// Await the async worker (deterministic, not time.Sleep).
	require.NoError(t, operations.Wait(ctx))

	// Resolve the new account id from the Operation metadata response.
	doneOp, err := opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, doneOp.Done)
	require.Nil(t, doneOp.Error, "Account.Create operation must succeed")

	// Find the owner-binding: list account-scoped bindings for the creator's new
	// account. The account id is in the create metadata; resolve via the account
	// row owned by the creator (newest).
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	accs, _, err := rd.Accounts().List(ctx, repoacct.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	_ = rd.Rollback(ctx)
	var newAccID domain.AccountID
	for _, a := range accs {
		if a.OwnerUserID == creator && a.Name == "acme-p6-own" {
			newAccID = a.ID
		}
	}
	require.NotEmpty(t, newAccID, "new account must exist")

	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd2.Rollback(ctx) }()
	rows, _, err := rd2.AccessBindings().ListByScope(ctx, "account", string(newAccID), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)

	var owner *domain.AccessBinding
	for i := range rows {
		if rows[i].RoleID == domain.OwnerRoleID {
			owner = &rows[i]
			break
		}
	}
	require.NotNil(t, owner, "owner AccessBinding must be co-committed on Account.Create (C-01)")
	assert.True(t, owner.DeletionProtection, "owner-binding deletion_protection=true (D-8/D-10)")
	assert.Equal(t, domain.SubjectID(creator), owner.SubjectID, "subject = creator")
	assert.Equal(t, domain.ScopeAccount, owner.Scope, "scope = ACCOUNT")
}
