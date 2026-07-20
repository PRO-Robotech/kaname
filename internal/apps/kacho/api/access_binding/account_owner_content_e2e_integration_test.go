// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// account_owner_content_e2e_integration_test.go — end-to-end (testcontainers PG16)
// proof of the BUG #2 chain through the REAL use-cases: an account owner
// (owner@ACCOUNT) must materialise per-object access on the account's iam-native
// CONTENT created AFTER the account — here an iam.serviceAccount — via the
// ServiceAccount.Create → reconcileObject("iam.serviceAccount", …) forward path,
// NOT only on the vpc/compute content nested in its projects (8d44019).
//
// This drives the SAME wiring the composition root uses (Account.Create with the
// owner-binding reconciler + ServiceAccount.Create with the object reconciler), so
// it exercises the actual trigger, not a hand-called ReconcileObject. It asserts on
// the emitted-tuple ledger (the observable the fga_outbox drainer applies to FGA).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	saapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/service_account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	repoacct "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ledgerHas(t *testing.T, ctx context.Context, pool *pgxpool.Pool, binding, user, relation, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND fga_user=$2 AND relation=$3 AND object=$4`,
		binding, user, relation, object).Scan(&n))
	return n > 0
}

func TestAccountOwner_MaterializesOnServiceAccountContent_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	rec := reconcile.New(kachopg.NewReconcileAdapter(pool), nil)

	owner := mustSeedUser(t, ctx, pool, "aoc-own")
	octx := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(owner)})

	// 1) Account.Create → co-committed owner-binding + reconcile. ownerUserId° is
	// derived from the caller (redesign-2026 F1 — not accepted in the body); the
	// principal in octx (owner) becomes the account owner.
	accUC := accountapp.NewCreateAccountUseCase(repo, opsRepo).WithReconciler(rec)
	accOp, err := accUC.Execute(octx, domain.Account{Name: "acme-aoc"})
	require.NoError(t, err)
	require.NoError(t, operations.Wait(ctx))
	doneAcc, err := opsRepo.Get(ctx, accOp.ID)
	require.NoError(t, err)
	require.Nil(t, doneAcc.Error, "Account.Create must succeed")

	// Resolve the new account id + the owner binding.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	accs, _, err := rd.Accounts().List(ctx, repoacct.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	_ = rd.Rollback(ctx)
	var accID domain.AccountID
	for _, a := range accs {
		if a.OwnerUserID == owner && a.Name == "acme-aoc" {
			accID = a.ID
		}
	}
	require.NotEmpty(t, accID)

	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	rows, _, err := rd2.AccessBindings().ListByScope(ctx, "account", string(accID), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	_ = rd2.Rollback(ctx)
	var ownerBindingID string
	for i := range rows {
		if rows[i].RoleID == domain.OwnerRoleID {
			ownerBindingID = string(rows[i].ID)
		}
	}
	require.NotEmpty(t, ownerBindingID, "owner binding must exist")

	// 2) ServiceAccount.Create in that account (AFTER the account) — the real forward
	//    materialisation trigger. Reconciler wired exactly as the composition root.
	saUC := saapp.NewCreateServiceAccountUseCase(repo, opsRepo).WithObjectReconciler(rec)
	saOp, err := saUC.Execute(octx, domain.ServiceAccount{AccountID: accID, Name: "sa-aoc-content"})
	require.NoError(t, err)
	require.NoError(t, operations.Wait(ctx))
	doneSA, err := opsRepo.Get(ctx, saOp.ID)
	require.NoError(t, err)
	require.Nil(t, doneSA.Error, "ServiceAccount.Create must succeed")
	var saID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.service_accounts WHERE account_id=$1 AND name=$2`,
		string(accID), "sa-aoc-content").Scan(&saID))
	require.NotEmpty(t, saID)

	u := "user:" + string(owner)
	obj := "iam_service_account:" + saID
	assert.True(t, ledgerHas(t, ctx, pool, ownerBindingID, u, "v_update", obj),
		"BUG #2: account-owner must materialise v_update on an iam.serviceAccount of its account (issue-sakey path)")
	assert.True(t, ledgerHas(t, ctx, pool, ownerBindingID, u, "admin", obj),
		"BUG #2: account-owner must carry the admin tier on the account's service_account")
}
