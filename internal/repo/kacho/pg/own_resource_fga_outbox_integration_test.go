// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// own_resource_fga_outbox_integration_test.go — integration tests for the
// in-tx fga_outbox emit contract on the SHARED writer-tx (100%
// tuple↔resource-create guarantee).
//
// Scenarios:
//
//   - positive: an own-resource Create (Project/Group/SA/Role + the
//     account-owner self-grant) co-commits its FGA hierarchy/owner-tuple INTENT
//     into kacho_iam.fga_outbox in the SAME writer-tx as the resource INSERT
//     (event_type='fga.tuple.write', sent_at IS NULL), next to the audit row.
//   - atomicity (запрет #10): if the writer-tx rolls back, NEITHER the
//     resource row NOR the fga_outbox intent row remain — all-or-nothing, no
//     window "resource exists, tuple intent lost".
//   - idempotent double-delivery: a re-delivered already-applied tuple
//     → FGA 409 → applier ErrAlreadyApplied → drainer marks success (covered at
//     the applier level by clients/fga_applier_integration_test.go; this file
//     asserts the EMIT side that feeds it).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// hierarchyTuple builds the parent-pointer tuple shape the create use-cases
// co-commit (mirrors relationhook.WriteHierarchyTuple → fga_outbox payload).
func hierarchyTuple(parentType, parentID, relation, childType, childID string) service.RelationTuple {
	return service.RelationTuple{
		User:     parentType + ":" + parentID,
		Relation: relation,
		Object:   childType + ":" + childID,
	}
}

// TestOwnResource_FGAOutbox_ProjectCreateEmitsHierarchyIntent — in-tx hierarchy-intent emit.
// A Project INSERT + its project→account hierarchy-intent emit + audit emit all
// commit together; the fga_outbox row is present, pending, with the right
// payload.
func TestOwnResource_FGAOutbox_ProjectCreateEmitsHierarchyIntent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "s2p10")
	acc := seedAccount(t, ctx, repo, "acc-s2-proj10", uid)

	projID := domain.ProjectID(ids.NewID(domain.PrefixProject))
	p := domain.Project{
		ID:          projID,
		AccountID:   acc.ID,
		Name:        domain.ProjectName("proj-s2-10"),
		Description: domain.Description("integration s2-10"),
		Labels:      domain.Labels{},
	}
	tup := hierarchyTuple("account", string(acc.ID), "account", "project", string(projID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ProjectsW().Insert(ctx, p)
	require.NoError(t, err)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{tup}))
	require.NoError(t, w.Commit(ctx))

	// fga_outbox row present, pending (sent_at NULL), correct payload.
	var et, payloadRaw string
	var sentAtNull bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload::text, sent_at IS NULL
		   FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = $1
		  ORDER BY id DESC LIMIT 1`,
		"project:"+string(projID)).Scan(&et, &payloadRaw, &sentAtNull))
	require.Equal(t, "fga.tuple.write", et)
	require.True(t, sentAtNull, "intent must be pending (sent_at IS NULL) until drainer applies")
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, "account:"+string(acc.ID), payload["user"])
	require.Equal(t, "account", payload["relation"])
	require.Equal(t, "project:"+string(projID), payload["object"])
}

// TestOwnResource_FGAOutbox_RollbackDiscardsBothRowAndIntent — запрет
// #10. Rolling back the writer-tx MUST discard BOTH the resource row AND the
// fga_outbox intent row — atomic all-or-nothing, no orphan intent visible to
// the drainer and no resource row without a tuple intent.
func TestOwnResource_FGAOutbox_RollbackDiscardsBothRowAndIntent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "s2rb")
	acc := seedAccount(t, ctx, repo, "acc-s2-rollback", uid)

	projID := domain.ProjectID(ids.NewID(domain.PrefixProject))
	p := domain.Project{
		ID:          projID,
		AccountID:   acc.ID,
		Name:        domain.ProjectName("proj-s2-rb"),
		Description: domain.Description("integration s2-rb"),
		Labels:      domain.Labels{},
	}
	tup := hierarchyTuple("account", string(acc.ID), "account", "project", string(projID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.ProjectsW().Insert(ctx, p)
	require.NoError(t, err)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{tup}))
	require.NoError(t, w.Rollback(ctx)) // explicit rollback — simulates failed tx

	var projCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.projects WHERE id = $1`,
		string(projID)).Scan(&projCount))
	require.Equal(t, 0, projCount, "project row must be rolled back")

	var intentCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox WHERE payload->>'object' = $1`,
		"project:"+string(projID)).Scan(&intentCount))
	require.Equal(t, 0, intentCount,
		"fga_outbox intent must be rolled back atomically with the project row (запрет #10)")
}

// TestOwnResource_FGAOutbox_AccountOwnerSelfGrantEmittedInTx — the
// account-owner self-grant tuple (`user:<owner>#owner@account:<id>`) — which the
// reconciler cannot reconstruct — is co-committed in the SAME
// writer-tx as the Account INSERT, so it can never be lost on an FGA outage.
func TestOwnResource_FGAOutbox_AccountOwnerSelfGrantEmittedInTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "s2own")

	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	a := domain.Account{
		ID:          accID,
		Name:        domain.AccountName("acc-s2-owner"),
		Description: domain.Description("integration s2-owner"),
		Labels:      domain.Labels{},
		OwnerUserID: uid,
	}
	owner := hierarchyTuple("user", string(uid), "owner", "account", string(accID))
	clusterPtr := hierarchyTuple("cluster", "cluster_kacho_root", "cluster", "account", string(accID))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, a)
	require.NoError(t, err)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{owner, clusterPtr}))
	require.NoError(t, w.Commit(ctx))

	var ownerCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type='fga.tuple.write'
		    AND payload->>'user' = $1 AND payload->>'relation' = 'owner'
		    AND payload->>'object' = $2`,
		"user:"+string(uid), "account:"+string(accID)).Scan(&ownerCnt))
	require.Equal(t, 1, ownerCnt, "owner self-grant intent must be co-committed in-tx")
}
