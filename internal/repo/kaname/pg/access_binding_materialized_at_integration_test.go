// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_materialized_at_integration_test.go — the read side of the
// materialization signal (finding: "deferred grant materialization is not
// observable").
//
// The reconciler records what it materialized in
// kaname.access_binding_target_members, stamping updated_at on every status
// transition. That ledger already answers "has this binding's per-object access
// gone live, and when" — it was simply never surfaced. This locks the batch read
// that projects it onto the resource.
//
// Coverage:
//   MA-1  a binding with an ACTIVE member reports MAX(updated_at) of its ACTIVE
//         members.
//   MA-2  a binding whose members are all still PENDING_VERIFICATION reports
//         NOTHING (unset ⇒ "not live yet") — a pending member must never be
//         mistaken for materialized access.
//   MA-3  a binding with no members at all is absent from the map (unset).
//   MA-4  the read is batched — one call answers for many bindings, and never
//         attributes one binding's members to another.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestAB_MA_MaterializedAtFromMemberLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "ma0o")
	acc := seedAccount(t, ctx, repo, "acc-ma0", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "ma0m")
	proj := seedProject(t, ctx, repo, acc.ID, "proj-ma0")
	role := seedCustomRole(t, ctx, repo, acc.ID, "ma0_role")

	live := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: role.ID, ResourceType: "project", ResourceID: string(proj.ID),
		GrantedByUserID: owner,
	})
	pending := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: role.ID, ResourceType: "account", ResourceID: string(acc.ID),
		GrantedByUserID: owner,
	})
	// The cluster scope admits SYSTEM roles only — an account-tier custom role is not
	// assignable there, so binding `role` here described a state the product refuses.
	// This case is about a binding with no member ledger; the role's tier is incidental.
	bare := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: systemRoleID("view"), ResourceType: "cluster", ResourceID: "cluster_root",
		GrantedByUserID: owner,
	})

	// `live` — two ACTIVE members at distinct instants (the later one wins) plus a
	// PENDING one that must NOT raise the answer.
	older := time.Date(2026, 7, 20, 8, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 7, 21, 9, 30, 0, 0, time.UTC)
	future := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	seedTargetMember(t, ctx, pool, string(live.ID), string(role.ID), "rule-a", "compute.instance", "ins-1", "ACTIVE", older)
	seedTargetMember(t, ctx, pool, string(live.ID), string(role.ID), "rule-b", "compute.instance", "ins-2", "ACTIVE", newer)
	seedTargetMember(t, ctx, pool, string(live.ID), string(role.ID), "rule-c", "compute.instance", "ins-3", "PENDING_VERIFICATION", future)

	// `pending` — nothing ACTIVE yet.
	seedTargetMember(t, ctx, pool, string(pending.ID), string(role.ID), "rule-a", "vpc.network", "net-1", "PENDING_VERIFICATION", future)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	got, err := rd.AccessBindings().ListMaterializedAtForBindings(ctx,
		[]domain.AccessBindingID{live.ID, pending.ID, bare.ID})
	require.NoError(t, err)

	// MA-1 — latest ACTIVE member wins; the PENDING one is ignored.
	liveAt, ok := got[live.ID]
	require.True(t, ok, "MA-1: a binding with ACTIVE members must report a materialization instant")
	assert.True(t, liveAt.UTC().Equal(newer),
		"MA-1: want MAX(updated_at) over ACTIVE members (%s), got %s", newer, liveAt.UTC())

	// MA-2 — PENDING is not materialized.
	_, pendingPresent := got[pending.ID]
	assert.False(t, pendingPresent,
		"MA-2: a PENDING_VERIFICATION member is NOT live access — reporting it would tell the admin the grant works when it does not")

	// MA-3 — no members at all → unset.
	_, barePresent := got[bare.ID]
	assert.False(t, barePresent, "MA-3: a binding with no materialized members reports nothing")

	// MA-4 — batch call, exactly one entry.
	assert.Len(t, got, 1, "MA-4: one batched read, no cross-attribution between bindings")
}

// seedTargetMember inserts one reconciler-ledger row with a controlled updated_at
// so the MAX/status semantics are observable without running the reconciler.
func seedTargetMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	bindingID, roleID, ruleFP, objectType, objectID, status string, at time.Time,
) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.access_binding_target_members
		  (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		bindingID, roleID, ruleFP, objectType, objectID, status, at)
	require.NoError(t, err, "seed target member")
}
