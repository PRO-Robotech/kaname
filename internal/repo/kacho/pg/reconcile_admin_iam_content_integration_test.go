// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_admin_iam_content_integration_test.go — rbac-contract-a-fix closure.
//
// Coverage gap closed (Contract-A flat model): the existing owner-iam-content
// integration suite only exercises the ACCOUNT OWNER path (BackfillOwnerBindings →
// the `account#owner` `*.*` binding) and only the SYNCHRONOUS ReconcileObject call.
// The e2e suites that stayed red (iam-access-binding / iam-rbac-subjects) act as an
// ACCOUNT-ADMIN that is NOT the account owner, and they GET the object right after
// the async Operation reports done — i.e. they exercise (a) the non-owner
// admin-grantee containment path and (b) the ASYNC drain timing. This file pins
// both, so the fix is proven on the exact shape the e2e exercises.
//
//	(a) TestAdminIamContent_NonOwner_ForwardMaterializes — an account-admin (an
//	    `admin`-tier rules-role bound to a NON-owner user, scope=account) gets the
//	    per-object admin tuple on a binding/group created in the account, via the
//	    SAME ReconcileObject path. Proves IAMDirectSelectorBindingsMatchingObject
//	    finds the non-owner admin-binding (arm='anchor') AND IsContainedIn(account)
//	    passes for the new object.
//	(b) TestAdminIamContent_AsyncDrain_Materializes — the object's per-object tuple
//	    is materialized by DRAINING the reconcile event through the worker queue
//	    (ClaimReconcileEvents → ReconcileObject → MarkReconcileEventSent), NOT a
//	    direct call — the timing path the e2e races. The freshly-created object's
//	    co-committed reconcile event is enough; the drain converges it.
//
// RED before the sync-ReconcileObject + containment fix; GREEN after.
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedAdminRulesRole inserts an ACCOUNT-scoped custom rules-role whose single
// ARM_ANCHOR rule grants admin (verbs `*`) over the supplied iam-native content
// resources (e.g. "accessBinding", "group"). Returns the role id. This models the
// account-admin role an account-admin user is bound to (NOT the owner `*.*` role).
func seedAdminRulesRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kachopg.Repository, acc domain.AccountID, name string, resources ...string) domain.RoleID {
	t.Helper()
	rule := domain.Rule{Module: "iam", Resources: resources, Verbs: []string{"*"}}
	return seedAccountRulesRole(t, ctx, pool, repo, acc, name, domain.Rules{rule})
}

// TestAdminIamContent_NonOwner_ForwardMaterializes — (a): an account-admin that is
// NOT the account owner forward-materializes admin on an access_binding / group
// created in the account. This is the non-owner-grantee containment path the e2e
// exercises (account-admin-A is not necessarily the owner of account A).
func TestAdminIamContent_NonOwner_ForwardMaterializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "aic-own")
	acc := seedAccount(t, ctx, repo, "acc-aic-fwd", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	// A SEPARATE admin user (NOT the owner) bound to an account-scoped admin
	// rules-role over iam.accessBinding + iam.group.
	admin := mustSeedUser(t, ctx, pool, "aic-adm")
	adminRole := seedAdminRulesRole(t, ctx, pool, repo, acc.ID, "aic_adminrole", "accessBinding", "group")
	adminBID := insertThinBindingScope(t, ctx, repo, admin, adminRole,
		"account", string(acc.ID), domain.ScopeAccount)
	adminUser := "user:" + string(admin)

	rec, _ := newReconciler(pool)

	// A group created in the account → admin forward-materializes on iam_group.
	gid := seedNativeGroup(t, ctx, pool, acc.ID, "aic-grp")
	require.NoError(t, rec.ReconcileObject(ctx, "iam.group", gid))
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, adminBID, adminUser, "admin", "iam_group:"+gid),
		"account-admin (non-owner) must FORWARD-materialize admin on a group created in the account")

	// A second access_binding created in the account (subject = the admin itself on
	// a content role) → admin forward-materializes on iam_access_binding.
	contentRole := seedNativeRole(t, ctx, pool, acc.ID, "aic_contentrole")
	grantBID := insertThinBindingScope(t, ctx, repo, owner, domain.RoleID(contentRole),
		"account", string(acc.ID), domain.ScopeAccount)
	require.NoError(t, rec.ReconcileObject(ctx, "iam.accessBinding", string(grantBID)))
	assert.True(t,
		ledgerHasTuple(t, ctx, pool, adminBID, adminUser, "admin", "iam_access_binding:"+string(grantBID)),
		"account-admin (non-owner) must FORWARD-materialize admin on a binding created in the account (so GET works)")
}

// TestAdminIamContent_AsyncDrain_Materializes — (b): the per-object tuple is
// materialized by DRAINING the co-committed reconcile event through the worker
// queue (ClaimReconcileEvents → ReconcileObject → MarkReconcileEventSent), proving
// the async path the e2e races converges to the same per-object tuple WITHOUT a
// direct ReconcileObject call.
func TestAdminIamContent_AsyncDrain_Materializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "aic-drain-own")
	acc := seedAccount(t, ctx, repo, "acc-aic-drain", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingFor(t, ctx, pool, acc.ID)
	ownerUser := "user:" + string(owner)

	// Create a group AND co-commit its reconcile event in the SAME writer-tx — the
	// exact shape group.Create produces (insert + EmitReconcileEvent). No direct
	// ReconcileObject here: the drain must converge it.
	gid := seedNativeGroupWithReconcileEvent(t, ctx, pool, acc.ID, "aic-drain-grp")

	// The drain pipeline: claim the unsent event, ReconcileObject it, mark sent.
	rec, adapter := newReconciler(pool)
	events, err := adapter.ClaimReconcileEvents(ctx, 64)
	require.NoError(t, err)
	require.NotEmpty(t, events, "the group Create must have enqueued a reconcile event")
	drained := false
	for _, e := range events {
		if e.ObjectType == "iam.group" && e.ObjectID == gid {
			require.NoError(t, rec.ReconcileObject(ctx, e.ObjectType, e.ObjectID))
			require.NoError(t, adapter.MarkReconcileEventSent(ctx, e.ID))
			drained = true
		}
	}
	require.True(t, drained, "the group's reconcile event must be present in the drain batch")

	assert.True(t,
		ledgerHasTuple(t, ctx, pool, ownerBID, ownerUser, "admin", "iam_group:"+gid),
		"owner must materialize admin on the group via the ASYNC drain path (not a direct call)")
}

// seedNativeGroupWithReconcileEvent inserts an account-scoped group AND co-commits
// the reconcile event in the SAME writer-tx — mirroring group.Create's doCreate
// (insert + EmitReconcileEvent), so the async-drain test exercises the real event
// the production path enqueues. Returns the group id.
func seedNativeGroupWithReconcileEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, name string) string {
	t.Helper()
	repo := kachopg.New(pool, nil)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	inserted, err := w.GroupsW().Insert(ctx, domain.Group{
		ID:        domain.GroupID(ids.NewID(domain.PrefixGroup)),
		AccountID: acc,
		Name:      domain.GroupName(name),
	})
	require.NoError(t, err, "insert group")
	require.NoError(t,
		w.EmitReconcileEvent(ctx, "mirror.upsert", "iam.group", string(inserted.ID)),
		"co-commit reconcile event")
	require.NoError(t, w.Commit(ctx))
	return string(inserted.ID)
}
