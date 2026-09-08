// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_subject_change_integration_test.go — Verifies WS-2.3:
// AccessBinding writer emits a subject_change_outbox row in the SAME
// transaction as the binding mutation (atomic — a rolled-back binding must
// not leave an orphan outbox row).
//
// .3.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestAccessBindingWriter_EmitSubjectChange_InTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	repo := kanamepg.New(pool, nil)

	// Happy path: emit + commit → row visible.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccessBindingsW().EmitSubjectChangeEvent(ctx, access_binding.SubjectChangeEvent{
		SubjectID: "usr_test_subject", Op: "binding_delete",
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	var op string
	err = pool.QueryRow(ctx,
		`SELECT op FROM kaname.subject_change_outbox WHERE subject_id = 'usr_test_subject'`).
		Scan(&op)
	require.NoError(t, err, "expected exactly one outbox row for usr_test_subject")
	require.Equal(t, "binding_delete", op)

	// Rollback path: no orphan row.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().EmitSubjectChangeEvent(ctx, access_binding.SubjectChangeEvent{
		SubjectID: "usr_rollback", Op: "binding_upsert",
	}))
	require.NoError(t, w2.Rollback(ctx))

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.subject_change_outbox WHERE subject_id='usr_rollback'`).Scan(&cnt))
	require.Equal(t, 0, cnt)
}
