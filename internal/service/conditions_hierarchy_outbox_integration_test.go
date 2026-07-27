// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_test

// conditions_hierarchy_outbox_integration_test.go — the parent pointer that
// makes a Condition reachable from the cloud administrator.
//
// The authorization model derives the top tier of super-access on a Condition
// structurally, over the condition's own pointer at its project:
//
//	type iam_condition
//	  define project: [project]
//	  define super_admin: super_admin from project
//
// and `project.super_admin` in turn resolves `admin from account or any_admin
// from cluster` — the three cascading tiers (cloud administrator, bootstrap
// identity, account administrator). None of that resolves to anything unless
// something writes the pointer tuple
//
//	iam_condition:<id> # project @ project:<projectID>
//
// Every sibling IAM resource emits its pointer in the same writer-transaction
// as the row (role/create.go, group/create.go, project/create.go). Conditions
// did not emit one at all, so the cascade was declared and dead: the cloud
// administrator could not reach a Condition through the model, and the item-RPC
// Checks the gateway makes against `iam_condition:<id>` had nothing to resolve.
//
// These tests assert the tuple INTENT lands in the outbox in the same
// transaction as the mutation — the durable, at-least-once contract the
// siblings use. They assert the exact triple the model accepts, not merely
// "some tuple was emitted": a pointer carrying the wrong relation or the wrong
// object type is rejected by the authorization model and would leave the
// cascade just as dead while a weaker assertion stayed green.
//
// Scenarios:
//   - Create emits exactly one project pointer, with the model's relation.
//   - Delete emits the symmetric removal, so a deleted Condition does not leave
//     a live pointer behind.
//   - A rolled-back Create leaves no pointer intent (atomicity, ban #10).

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// buildCondSvcWithHierarchy wires a ConditionsCRUDService exactly as the
// composition root does — audit emitter, worker-tx beginner and the fga_outbox
// relation emitter that carries the hierarchy pointer.
func buildCondSvcWithHierarchy(pool *pgxpool.Pool) *service.ConditionsCRUDService {
	repo := kachopg.NewConditionsRepo(pool)
	opsRepo := operations.NewRepo(pool, "kacho_iam")
	eval := service.NewBuiltinEvaluator()
	svc := service.NewConditionsCRUDService(repo, opsRepo, eval)
	svc.WithRelationStore(allowAllRelations{})
	svc.WithAuditEmitter(kachopg.NewAuditOutboxEmitter(pool), kachopg.NewPoolTxBeginner(pool))
	svc.WithRelationOutbox(kachopg.NewFGAOutboxEmitter())
	return svc
}

// condOutboxRows returns the fga_outbox rows of the given event type addressing
// the given condition object.
func condOutboxRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, condID string) []map[string]string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT payload->>'user', payload->>'relation', payload->>'object'
		   FROM kacho_iam.fga_outbox
		  WHERE event_type = $1 AND payload->>'object' = $2
		  ORDER BY id ASC`,
		eventType, "iam_condition:"+condID)
	require.NoError(t, err)
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var u, rel, obj string
		require.NoError(t, rows.Scan(&u, &rel, &obj))
		out = append(out, map[string]string{"user": u, "relation": rel, "object": obj})
	}
	require.NoError(t, rows.Err())
	return out
}

func awaitCondOutbox(ctx context.Context, t *testing.T, pool *pgxpool.Pool, eventType, condID string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(condOutboxRows(ctx, t, pool, eventType, condID)) > 0
	}, 5*time.Second, 20*time.Millisecond,
		"no %s intent for iam_condition:%s — the project pointer was never emitted, "+
			"so `super_admin from project` resolves to nothing and the cloud "+
			"administrator cannot reach this Condition", eventType, condID)
}

// ── Create emits the project pointer ─────────────────────────────────────────

func TestConditionsHierarchy_CreateEmitsProjectPointer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	projectID := ids.NewID(domain.PrefixProject)
	svc := buildCondSvcWithHierarchy(pool)

	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		ProjectID:  projectID,
		Name:       "hierarchy-create",
		Expression: "non_expired",
	})
	require.NoError(t, err)

	condID := findCreatedCondID(ctx, t, pool, projectID)
	awaitCondOutbox(ctx, t, pool, "fga.tuple.write", condID)

	got := condOutboxRows(ctx, t, pool, "fga.tuple.write", condID)
	require.Len(t, got, 1, "Create must emit exactly one hierarchy tuple for the condition object")
	require.Equal(t, map[string]string{
		"user":     "project:" + projectID,
		"relation": "project",
		"object":   "iam_condition:" + condID,
	}, got[0],
		"the emitted triple must be the one `type iam_condition { define project: [project] }` "+
			"accepts — a different relation or object type is rejected by the model and "+
			"leaves the super-admin cascade dead")
}

// ── Delete emits the symmetric removal ───────────────────────────────────────

func TestConditionsHierarchy_DeleteRemovesProjectPointer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	projectID := ids.NewID(domain.PrefixProject)
	svc := buildCondSvcWithHierarchy(pool)

	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		ProjectID:  projectID,
		Name:       "hierarchy-delete",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	condID := findCreatedCondID(ctx, t, pool, projectID)
	awaitConditionStatus(ctx, t, pool, condID, "ACTIVE")

	_, err = svc.Delete(withCondPrincipal(ctx, uid), domain.ConditionID(condID))
	require.NoError(t, err)

	awaitCondOutbox(ctx, t, pool, "fga.tuple.delete", condID)
	got := condOutboxRows(ctx, t, pool, "fga.tuple.delete", condID)
	require.Len(t, got, 1, "Delete must retract exactly the pointer Create wrote")
	require.Equal(t, map[string]string{
		"user":     "project:" + projectID,
		"relation": "project",
		"object":   "iam_condition:" + condID,
	}, got[0],
		"a deleted Condition must not leave a live pointer — the retraction is the "+
			"exact triple Create emitted")

	// The hard-delete and the retraction commit together.
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.conditions WHERE id = $1`, condID).Scan(&n))
	require.Equal(t, 0, n)
}

// ── A rolled-back Create leaves no pointer intent ────────────────────────────

func TestConditionsHierarchy_RollbackLeavesNoPointer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupCondAuditDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	uid := ids.NewID(domain.PrefixUser)
	projectID := ids.NewID(domain.PrefixProject)
	svc := buildCondSvcWithHierarchy(pool)

	_, err = svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		ProjectID:  projectID,
		Name:       "dup-pointer",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	firstID := findCreatedCondID(ctx, t, pool, projectID)
	awaitCondOutbox(ctx, t, pool, "fga.tuple.write", firstID)

	// Same (project, name) — the INSERT hits conditions_project_name_uniq and the
	// worker-tx rolls back.
	dupOp, err := svc.Create(withCondPrincipal(ctx, uid), service.CreateConditionRequest{
		ProjectID:  projectID,
		Name:       "dup-pointer",
		Expression: "non_expired",
	})
	require.NoError(t, err)
	awaitOpError(ctx, t, operations.NewRepo(pool, "kacho_iam"), dupOp.ID)

	// Scoped to condition objects — the migrations seed unrelated bootstrap
	// tuples into the same table.
	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type = 'fga.tuple.write'
		    AND payload->>'object' LIKE 'iam_condition:%'`).Scan(&total))
	require.Equal(t, 1, total,
		"a rolled-back Create must leave no orphan pointer intent (atomicity, ban #10)")
}
