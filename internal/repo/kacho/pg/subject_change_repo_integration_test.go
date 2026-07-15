// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_repo_integration_test.go — integration tests for SubjectChangeRepo.
// Verifies PollSubjectChanges returns ascending rows, honours limit, and
// reports headID correctly. Uses testcontainers Postgres (same pattern as
// sibling integration tests). Skipped under testing.Short().
//
// .3.
package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestSubjectChangeRepo_PollSubjectChanges verifies:
// 1. Returns rows with id > since_id, ascending order.
// 2. Honours limit (requests 2 of 3 → receives 2).
// 3. headID = MAX(id) regardless of cursor position.
// 4. Continuing cursor returns the remaining row.
func TestSubjectChangeRepo_PollSubjectChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	ctx := context.Background()
	dsn := kachopg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	repo := kachopg.NewSubjectChangeRepo(pool)

	// Seed 3 rows.
	var id1, id2, id3 int64
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO kacho_iam.subject_change_outbox (subject_id, op)
		 VALUES ('usr_a', 'binding_upsert') RETURNING id`).Scan(&id1))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO kacho_iam.subject_change_outbox (subject_id, op)
		 VALUES ('usr_b', 'binding_delete') RETURNING id`).Scan(&id2))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO kacho_iam.subject_change_outbox (subject_id, op)
		 VALUES ('usr_c', 'binding_upsert') RETURNING id`).Scan(&id3))

	// ── Poll 1: since=0, limit=2 → first 2 rows; headID=id3 ─────────────────
	changes, headID, err := repo.PollSubjectChanges(ctx, 0, 2)
	require.NoError(t, err)
	require.Len(t, changes, 2, "expected 2 changes (limit=2)")
	require.Equal(t, id1, changes[0].ID)
	require.Equal(t, "usr_a", changes[0].SubjectID)
	require.Equal(t, "binding_upsert", changes[0].Op)
	require.Equal(t, id2, changes[1].ID)
	require.Equal(t, "usr_b", changes[1].SubjectID)
	require.Equal(t, "binding_delete", changes[1].Op)
	require.Equal(t, id3, headID, "headID should be MAX(id)=id3")

	// ── Poll 2: since=id2, limit=256 → only third row; headID=id3 ────────────
	changes2, headID2, err := repo.PollSubjectChanges(ctx, id2, 256)
	require.NoError(t, err)
	require.Len(t, changes2, 1, "expected 1 remaining change")
	require.Equal(t, id3, changes2[0].ID)
	require.Equal(t, "usr_c", changes2[0].SubjectID)
	require.Equal(t, "binding_upsert", changes2[0].Op)
	require.Equal(t, id3, headID2)
}
