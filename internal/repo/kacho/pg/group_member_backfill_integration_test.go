// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// group_member_backfill_integration_test.go — integration proof of migration
// 0029 (backfill the FGA `group:<gid>#member` userset member-tuples for EXISTING
// group_members rows). Mirrors the migration's INSERT body so the test exercises
// the EXACT backfill statement against real Postgres.
//
//   GM-BF1  a LEGACY group_members row (inserted WITHOUT the use-case FGA emit —
//           the pre-fix data state) gets a `fga.tuple.write` member-tuple intent
//           with payload {user:<type>:<id>, member, group:<gid>}. service_account
//           members map to the service_account FGA prefix.
//   GM-BF2  IDEMPOTENT — re-running the backfill emits NOTHING for a member whose
//           write-tuple intent already exists (NOT EXISTS guard).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// backfillGroupMemberTuplesSQL is migration 0029's Up INSERT body (single source
// of truth — kept byte-identical to internal/migrations/0029_*.sql so the test
// proves the migration statement, not a paraphrase).
const backfillGroupMemberTuplesSQL = `
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
SELECT
  'fga.tuple.write',
  jsonb_build_object(
    'user',     gm.member_type || ':' || gm.member_id,
    'relation', 'member',
    'object',   'group:' || gm.group_id
  ),
  now()
FROM kacho_iam.group_members gm
WHERE NOT EXISTS (
  SELECT 1
    FROM kacho_iam.fga_outbox o
   WHERE o.event_type = 'fga.tuple.write'
     AND o.payload->>'user'     = gm.member_type || ':' || gm.member_id
     AND o.payload->>'relation' = 'member'
     AND o.payload->>'object'   = 'group:' || gm.group_id
)`

func TestGroupMember_Backfill_GM_BF1_LegacyRowEmitsMemberTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gmbf1")
	acc := seedAccount(t, ctx, repo, "acc-gmbf1", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-gmbf1")

	// LEGACY membership row inserted by raw SQL — NO use-case FGA emit (the pre-fix
	// data state). The seed already ran migration 0029 (group_members empty then),
	// so this row has no member-tuple intent.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id) VALUES ($1, 'user', $2)`,
		string(g.ID), string(uid))
	require.NoError(t, err)

	// Sanity: no member-tuple intent yet (legacy bug state).
	var pre int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox WHERE payload->>'object' = $1`,
		"group:"+string(g.ID)).Scan(&pre))
	require.Equal(t, 0, pre, "legacy member row has NO FGA tuple (the bug)")

	// Run the backfill.
	_, err = pool.Exec(ctx, backfillGroupMemberTuplesSQL)
	require.NoError(t, err)

	var et, user, relation, object string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload->>'user', payload->>'relation', payload->>'object'
		   FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = $1
		  ORDER BY id DESC LIMIT 1`,
		"group:"+string(g.ID)).Scan(&et, &user, &relation, &object))
	assert.Equal(t, "fga.tuple.write", et)
	assert.Equal(t, "user:"+string(uid), user)
	assert.Equal(t, "member", relation)
	assert.Equal(t, "group:"+string(g.ID), object,
		"backfilled member-tuple object must be FGA type `group`, NOT iam_group")
}

func TestGroupMember_Backfill_GM_BF2_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gmbf2")
	uid2 := mustSeedUser(t, ctx, pool, "gmbf2b")
	acc := seedAccount(t, ctx, repo, "acc-gmbf2", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-gmbf2")

	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id) VALUES
		   ($1, 'user', $2), ($1, 'user', $3)`,
		string(g.ID), string(uid), string(uid2))
	require.NoError(t, err)

	// First backfill — two intents.
	_, err = pool.Exec(ctx, backfillGroupMemberTuplesSQL)
	require.NoError(t, err)
	// Second backfill — must add NOTHING (NOT EXISTS guard).
	_, err = pool.Exec(ctx, backfillGroupMemberTuplesSQL)
	require.NoError(t, err)

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type='fga.tuple.write' AND payload->>'relation'='member' AND payload->>'object' = $1`,
		"group:"+string(g.ID)).Scan(&cnt))
	assert.Equal(t, 2, cnt, "exactly one member-tuple per member — re-running the backfill is a no-op (idempotent)")
}
