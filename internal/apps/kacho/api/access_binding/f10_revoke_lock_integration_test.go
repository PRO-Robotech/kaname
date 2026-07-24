// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding_test

// f10_revoke_lock_integration_test.go — redesign-2026 F10 (IAM-1-28) revoke
// critical-section, END-TO-END on testcontainers PG16.
//
// The soft-revoke reads the binding's emitted-tuple ledger and removes exactly that
// set. A concurrent ReconcileBindingForward pass materializes NEW members under a
// SHARE advisory lock (pg_advisory_xact_lock_shared(hashtext(binding_id))) and
// appends their tuples to the same ledger. If the revoke writer-tx takes no lock at
// all, the two txs never conflict: the forward row lands after the revoke's snapshot
// and is never in the delete-set — and because a REVOKED binding short-circuits
// `!bs.Active` in reconcileBinding AND in both forward paths, nothing ever reclaims
// it. The revoked subject keeps that object's verbs forever.
//
// This test stands in for the forward pass with a raw tx that holds the SHARE lock
// and inserts the ledger row, and asserts the revoke (a) BLOCKS while that tx is
// open (proving the EXCLUSIVE lock is really taken on the same hashtext key) and
// (b) removes the racing tuple once it proceeds.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// recordingRelations — RelationStore capturing the post-commit synchronous
// tuple-removal set. Check denies everything, so grant-authority must come from the
// account-owner path (Path 1), not the cluster short-circuit.
type recordingRelations struct {
	deleted []clients.RelationTuple
}

func (r *recordingRelations) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (r *recordingRelations) WriteTuples(context.Context, []clients.RelationTuple) error { return nil }
func (r *recordingRelations) DeleteTuples(_ context.Context, tuples []clients.RelationTuple) error {
	r.deleted = append(r.deleted, tuples...)
	return nil
}

var _ clients.RelationStore = (*recordingRelations)(nil)

func (r *recordingRelations) has(user, relation, object string) bool {
	for _, t := range r.deleted {
		if t.User == user && t.Relation == relation && t.Object == object {
			return true
		}
	}
	return false
}

// TestAB_IAM_1_28_Revoke_SerializesWithConcurrentForwardPass — the failing scenario
// of the missing advisory lock, end-to-end.
func TestAB_IAM_1_28_Revoke_SerializesWithConcurrentForwardPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	owner := mustSeedUser(t, ctx, pool, "rvlk")
	acc := seedAccountByOwner(t, ctx, pool, "acc-rvlk", owner)
	member := mustSeedUser(t, ctx, pool, "rvlkm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "rvlk_role")

	// One ACTIVE binding with a two-tuple ledger (the grant-time emitted set).
	abID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: abID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: role, ResourceType: "account", ResourceID: string(acc),
	})
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abID, []abrepo.RelationTuple{
		{User: "user:" + string(member), Relation: "v_get", Object: "vpc_network:net-1"},
		{User: "user:" + string(member), Relation: "v_update", Object: "vpc_network:net-1"},
	}))
	require.NoError(t, w.Commit(ctx))

	// A concurrent forward pass: SHARE lock on hashtext(binding_id) + a NEW ledger
	// row, not yet committed.
	fwd, err := pool.Begin(ctx)
	require.NoError(t, err)
	fwdDone := false
	defer func() {
		if !fwdDone {
			_ = fwd.Rollback(ctx)
		}
	}()
	_, err = fwd.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtext($1))`, string(abID))
	require.NoError(t, err)
	_, err = fwd.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
		VALUES ($1, $2, $3, $4, 'member')`,
		string(abID), "user:"+string(member), "v_get", "vpc_network:net-race")
	require.NoError(t, err)

	rec := &recordingRelations{}
	uc := accessbindingapp.NewRevokeAccessBindingUseCase(repo, opsRepo).WithRelationStore(rec, nil)

	op, err := uc.Execute(asUser(ctx, owner), abID)
	require.NoError(t, err, "the sync path (authz + protection) must pass for the account owner")

	// (1) The revoke writer-tx must BLOCK on the EXCLUSIVE binding lock while the
	// forward tx holds SHARE. Without the lock it races to completion here.
	require.False(t, opDoneWithin(t, ctx, opsRepo, op.ID, 1500*time.Millisecond),
		"the revoke writer-tx must WAIT for the concurrent forward pass "+
			"(EXCLUSIVE pg_advisory_xact_lock(hashtext(binding_id)) ⊥ its SHARE lock)")

	// (2) Release the forward pass; the revoke now sees the full ledger.
	require.NoError(t, fwd.Commit(ctx))
	fwdDone = true

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "revoke must succeed after the forward pass commits")

	assert.True(t, rec.has("user:"+string(member), "v_get", "vpc_network:net-race"),
		"the tuple a racing forward pass added must be in the revoke's delete-set — "+
			"a REVOKED binding is skipped by every reconcile path, so nothing else would ever reclaim it")

	// The binding is REVOKED and no ledger row survives unrevoked in FGA terms:
	// every stored tuple was handed to the removal.
	var remaining int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(abID)).Scan(&remaining))
	assert.Equal(t, remaining, len(rec.deleted),
		"every ledger row of the binding is covered by the removal set (byte-symmetric revoke)")
}

// opDoneWithin polls the operation for at most d and reports whether it completed.
func opDoneWithin(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
