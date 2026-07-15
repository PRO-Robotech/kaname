// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_fga_outbox_integration_test.go — integration tests for the
// fga_outbox emit-in-tx contract on the access_bindings writer.
//
// Covers atomic emit + rollback:
//
// - CREATE-EMIT: AccessBindingsW().Insert + EmitRelationWrite + Commit
// leaves N grant rows in kacho_iam.fga_outbox (event_type=fga.tuple.write).
// - DELETE-EMIT: AccessBindingsW().Delete + EmitRelationDelete + Commit
// leaves N revoke rows in kacho_iam.fga_outbox (event_type=fga.tuple.delete).
// - ROLLBACK: rollback of the writer-tx removes both the binding
// row AND the fga_outbox rows (ban #10).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestAB_FGAOutboxTx_FGAOutbox_CreateEmitsWriteRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15cr")
	acc := seedAccount(t, ctx, repo, "acc-w15-create", uid)

	binding := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer",
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.Commit(ctx))

	// Verify fga_outbox row present.
	var et string
	var payloadRaw string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload::text
		 FROM kacho_iam.fga_outbox
		 ORDER BY id DESC LIMIT 1`).Scan(&et, &payloadRaw))
	require.Equal(t, "fga.tuple.write", et)
	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, "user:"+string(uid), payload["user"])
	require.Equal(t, "viewer", payload["relation"])
	require.Equal(t, "account:"+string(acc.ID), payload["object"])
}

func TestAB_FGAOutboxTx_FGAOutbox_DeleteEmitsDeleteRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15dl")
	acc := seedAccount(t, ctx, repo, "acc-w15-delete", uid)
	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer",
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, binding.ID))
	require.NoError(t, w.AccessBindingsW().EmitRelationDelete(ctx, tuples))
	require.NoError(t, w.Commit(ctx))

	var et string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kacho_iam.fga_outbox WHERE event_type = $1 LIMIT 1`,
		"fga.tuple.delete").Scan(&et))
	require.Equal(t, "fga.tuple.delete", et)
}

// TestAB_FGAOutboxTx_FGAOutbox_RollbackDiscardsBothRowAndEmit verifies ban #10:
// rolling back the writer-tx MUST also discard the fga_outbox emit row. Confirms
// atomic emit-in-tx pattern (no orphan rows visible to drainer).
func TestAB_FGAOutboxTx_FGAOutbox_RollbackDiscardsBothRowAndEmit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "w15rb")
	acc := seedAccount(t, ctx, repo, "acc-w15-rollback-test", uid)

	candidateID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:           candidateID,
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol000000000sysviewer",
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.Rollback(ctx)) // explicit rollback

	// Neither the binding row nor the fga_outbox row should be visible.
	var bindingCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE id = $1`,
		string(candidateID)).Scan(&bindingCount))
	require.Equal(t, 0, bindingCount, "binding row must be rolled back")

	var fgaCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		 WHERE payload->>'user' = $1 AND payload->>'object' = $2`,
		"user:"+string(uid), "account:"+string(acc.ID)).Scan(&fgaCount))
	require.Equal(t, 0, fgaCount, "fga_outbox row must be rolled back atomically with binding row")
}

// TestAB_FGAOutboxTx_FGAOutbox_EmitWriteTx_EmptyTuplesNoop confirms 0 tuples is a
// safe no-op (caller decides whether 0 emit is acceptable).
func TestAB_FGAOutboxTx_FGAOutbox_EmitWriteTx_EmptyTuplesNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Snapshot the baseline outbox size: seed migrations enqueue relation-tuples
	// (0009 fga_writer@iam_fgaproxy, 0010 operator system_viewer@cluster, 0014
	// reader system_viewer@cluster). Assert this empty-emit adds ZERO rows
	// (delta-based, robust to any current/future seed — a static "== 0" filter
	// silently broke each time a new cluster-root seed landed).
	var before int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&before))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, nil))
	require.NoError(t, w.AccessBindingsW().EmitRelationDelete(ctx, []repoab.RelationTuple{}))
	require.NoError(t, w.Commit(ctx))

	var after int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox`).Scan(&after))
	require.Equal(t, before, after, "empty tuples → no emit, no new row")
}
