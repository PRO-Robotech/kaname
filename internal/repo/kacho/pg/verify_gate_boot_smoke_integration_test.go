// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// verify_gate_boot_smoke_integration_test.go — review #14: the contract-phase gate
// must actually EXERCISE the live forward-smoke at boot, not only the
// active_members-derived Verify. VerifyGate.RunBootForwardSmoke discovers an ACTIVE
// account-scoped owner-binding (the bounded-scope owner-content path), seeds a
// synthetic vpc.network mirror row in that account, drives the forward path, and
// asserts the owner's per-object content tuple materialized — the assertion Verify
// provably cannot make (КФ-БАГ-1/#224). Non-fatal: a cluster with no owner-binding
// reports ran=false.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestReview14_VerifyGate_BootForwardSmoke_OwnerBinding — RunBootForwardSmoke drives
// a live ForwardSmoke against the seeded owner-binding: a fresh vpc.network in the
// account materializes the owner's content tuple via the forward path (D-4). passed
// && ran are both true once an owner-binding exists.
func TestReview14_VerifyGate_BootForwardSmoke_OwnerBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "r14boot")
	acc := seedAccount(t, ctx, repo, "acc-r14-boot", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	_, gate := newBackfill(pool)

	passed, ran, serr := gate.RunBootForwardSmoke(ctx)
	require.NoError(t, serr)
	assert.True(t, ran, "an owner-binding exists → the boot forward-smoke must run")
	assert.True(t, passed,
		"boot forward-smoke must materialize owner content on a fresh resource (review #14 КФ-4/H-06)")

	// The synthetic mirror object is removed by ForwardSmoke (no lingering row in the
	// real account).
	var leftover int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.resource_mirror
		  WHERE object_type = 'vpc.network' AND parent_account_id = $1`,
		string(acc.ID)).Scan(&leftover))
	assert.Equal(t, 0, leftover, "boot forward-smoke must clean up its synthetic mirror object")
}

// TestReview14_SmokeOwnerBindingCandidate_DiscoversBinding — the pg adapter's
// SmokeOwnerBindingCandidate returns ONE active account-scoped owner-binding with
// its account id (the discovery RunBootForwardSmoke uses). A freshly-migrated DB
// already carries the kacho-system anchor account's owner-binding (migration 0009 +
// 0036), so a candidate is always discoverable post-migrate.
func TestReview14_SmokeOwnerBindingCandidate_DiscoversBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "r14cand")
	acc := seedAccount(t, ctx, repo, "acc-r14-cand", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	adapter := kachopg.NewBackfillAdapter(pool)
	bindingID, accountID, ok, cerr := adapter.SmokeOwnerBindingCandidate(ctx)
	require.NoError(t, cerr)
	require.True(t, ok, "an owner-binding exists post-backfill → a candidate is discoverable")
	assert.NotEmpty(t, bindingID, "candidate binding id is non-empty")
	assert.NotEmpty(t, accountID, "candidate account id is non-empty")

	// The discovered binding is a real ACTIVE account-scoped owner-binding.
	var (
		roleID  string
		resType string
		status  string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT role_id, resource_type, status FROM kacho_iam.access_bindings WHERE id = $1`,
		string(bindingID)).Scan(&roleID, &resType, &status))
	assert.Equal(t, domain.OwnerRoleID, roleID, "candidate is an owner-role binding")
	assert.Equal(t, "account", resType, "candidate is account-scoped")
	assert.Equal(t, "ACTIVE", status, "candidate is ACTIVE")
	_ = acc
}
