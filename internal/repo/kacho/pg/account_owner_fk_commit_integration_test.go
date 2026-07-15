// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// account_owner_fk_commit_integration_test.go — end-to-end coverage for the
// DEFERRABLE INITIALLY DEFERRED accounts_owner_fk (migration 0001) firing at
// COMMIT.
//
// accounts_owner_fk is deferred (order-independence — the owner user may be
// inserted in the same tx, migration 0009), so an account whose owner_user_id
// references a non-existent user is NOT rejected by the INSERT statement: the
// 23503 surfaces only at COMMIT. Before the fix the raw *pgconn.PgError from
// Commit bypassed the constraint-aware SQLSTATE→sentinel bridge and hit
// shared.MapRepoErr's sentinel-only INTERNAL fallback, misclassifying a
// tenant-precondition failure ("owner does not exist") as codes.Internal.
//
// writeTx.Commit now routes the commit error through the same bridge with the
// owner-id hint recorded by accountWriter.Insert, so the failure maps to
// FailedPrecondition with the canonical "User <id> not found" text.
//
// testcontainers Postgres — skipped under `testing.Short()`.

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestAccountOwnerFK_CommitTime_FailedPrecondition — inserting an account with a
// non-existent owner defers the FK to COMMIT; the commit-time 23503 must map to
// FailedPrecondition "User <id> not found", never INTERNAL.
func TestAccountOwnerFK_CommitTime_FailedPrecondition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	missingOwner := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)

	// INSERT itself does NOT fail — accounts_owner_fk is deferred.
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID:          accID,
		Name:        domain.AccountName("owner-fk-commit"),
		OwnerUserID: missingOwner,
		Labels:      domain.Labels{},
	})
	require.NoError(t, err, "INSERT must not fail (FK deferred to COMMIT)")

	// COMMIT fires the deferred FK; writeTx.Commit maps it to the canonical text.
	cerr := w.Commit(ctx)
	require.Error(t, cerr, "COMMIT must fail — owner user does not exist")
	_ = w.Rollback(ctx)

	assert.True(t, stderrors.Is(cerr, iamerr.ErrFailedPrecondition),
		"commit-time 23503 must map to ErrFailedPrecondition, got %v", cerr)
	assert.False(t, stderrors.Is(cerr, iamerr.ErrInternal),
		"commit-time 23503 must NOT map to ErrInternal")
	got := iamerr.StripSentinel(cerr)
	assert.Equal(t, "User "+string(missingOwner)+" not found", got)
	// No raw pgx/schema fragments leak through the client-facing text.
	for _, frag := range []string{"accounts_owner_fk", "constraint", "kacho_iam", "SQLSTATE"} {
		assert.NotContains(t, strings.ToLower(got), strings.ToLower(frag),
			"client-facing text must not leak pgx fragment %q", frag)
	}
}
