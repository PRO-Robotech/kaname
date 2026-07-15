// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// cluster_admin_grant_backfill_integration_test.go — Item #5 integration tests
// for migration 0004_backfill_cluster_admin_grants_into_access_bindings.sql.
//
// The migration runs once at setupTestDB time (goose.Up). To exercise it,
// these tests seed `cluster_admin_grants` rows AFTER the migration applied,
// then re-execute the backfill SQL inline to verify:
//
//   * active cag_* rows land as access_bindings(status='ACTIVE', resource_type='cluster',
//     resource_id='cluster_kacho_root', role_id=<roles/admin id>).
//   * revoked cag_* rows land as access_bindings(status='REVOKED',
//     revoked_at=<old granted_until>, revoked_by_user_id='system:cluster-admin-backfill').
//   * Idempotent — re-running the same backfill SQL produces NO duplicate rows
//     (ON CONFLICT DO NOTHING on PK / active partial UNIQUE).
//
// All tests use the existing setupTestDB testcontainer harness.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// backfillSQL — exact backfill statements from migration 0004. Extracted
// for re-execution under controlled conditions (the migration itself runs
// once at setupTestDB time; this lets the test seed cag rows AFTER and
// observe the backfill against those new rows).
//
// Kept in lockstep with internal/migrations/0004_backfill_cluster_admin_grants_into_access_bindings.sql.
const backfillSQL = `
DO $migration$
DECLARE
  v_admin_role_id TEXT;
BEGIN
  SELECT id INTO v_admin_role_id
    FROM kacho_iam.roles
   WHERE name = 'admin' AND cluster_id = 'cluster_kacho_root' AND is_system = true;
  IF v_admin_role_id IS NULL THEN
    RAISE EXCEPTION 'cluster-admin backfill: roles/admin not found';
  END IF;

  WITH src AS (
    SELECT id, subject_type, subject_id, granted_by, granted_at
      FROM kacho_iam.cluster_admin_grants
     WHERE granted_until IS NULL
  )
  INSERT INTO kacho_iam.access_bindings (
      id, subject_type, subject_id, role_id, resource_type, resource_id,
      status, granted_by_user_id, created_at
  )
  SELECT
      'abc' || substr(src.id, 5, 17),
      src.subject_type, src.subject_id, v_admin_role_id,
      'cluster', 'cluster_kacho_root',
      'ACTIVE',
      CASE WHEN length(src.granted_by) <= 64 THEN src.granted_by ELSE substr(src.granted_by, 1, 64) END,
      src.granted_at
  FROM src
  ON CONFLICT DO NOTHING;

  WITH src AS (
    SELECT id, subject_type, subject_id, granted_by, granted_at, granted_until
      FROM kacho_iam.cluster_admin_grants
     WHERE granted_until IS NOT NULL
  )
  INSERT INTO kacho_iam.access_bindings (
      id, subject_type, subject_id, role_id, resource_type, resource_id,
      status, granted_by_user_id, revoked_at, revoked_by_user_id, created_at
  )
  SELECT
      'abc' || substr(src.id, 5, 17),
      src.subject_type, src.subject_id, v_admin_role_id,
      'cluster', 'cluster_kacho_root',
      'REVOKED',
      CASE WHEN length(src.granted_by) <= 64 THEN src.granted_by ELSE substr(src.granted_by, 1, 64) END,
      src.granted_until,
      'system:cluster-admin-backfill',
      src.granted_at
  FROM src
  ON CONFLICT (id) DO NOTHING;
END
$migration$;
`

// runBackfill executes the inline backfill statements.
func runBackfill(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, backfillSQL)
	require.NoError(t, err, "backfill SQL must succeed")
}

// adminRoleID fetches roles/admin row id (deterministic md5-based).
func adminRoleID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.roles
		  WHERE name = 'admin' AND cluster_id = 'cluster_kacho_root' AND is_system = true`).
		Scan(&id))
	return id
}

func TestBackfillCAG_ActiveGrantBecomesActiveBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "backfill-active")
	seedClusterAdmin(t, ctx, pool, uid)

	runBackfill(t, ctx, pool)

	// Verify access_binding row exists.
	var (
		gotStatus    string
		gotResType   string
		gotResID     string
		gotRoleID    string
		gotRevokedAt *time.Time
	)
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT status, resource_type, resource_id, role_id, revoked_at
		  FROM kacho_iam.access_bindings
		 WHERE subject_type = 'user' AND subject_id = $1
		   AND resource_type = 'cluster'`, string(uid)).
		Scan(&gotStatus, &gotResType, &gotResID, &gotRoleID, &gotRevokedAt))

	assert.Equal(t, "ACTIVE", gotStatus)
	assert.Equal(t, "cluster", gotResType)
	assert.Equal(t, domain.ClusterSingletonID, gotResID)
	assert.Equal(t, adminRoleID(t, ctx, pool), gotRoleID,
		"backfilled binding must carry the global roles/admin id")
	assert.Nil(t, gotRevokedAt, "active grant must have revoked_at = NULL")
}

func TestBackfillCAG_RevokedGrantBecomesRevokedBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "backfill-revoked")
	seedRevokedClusterAdmin(t, ctx, pool, uid)

	runBackfill(t, ctx, pool)

	var (
		gotStatus    string
		gotRevokedAt *time.Time
		gotRevokedBy *string
	)
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT status, revoked_at, revoked_by_user_id
		  FROM kacho_iam.access_bindings
		 WHERE subject_type = 'user' AND subject_id = $1
		   AND resource_type = 'cluster'`, string(uid)).
		Scan(&gotStatus, &gotRevokedAt, &gotRevokedBy))

	assert.Equal(t, "REVOKED", gotStatus)
	require.NotNil(t, gotRevokedAt, "revoked grant must carry revoked_at")
	require.NotNil(t, gotRevokedBy)
	assert.Equal(t, "system:cluster-admin-backfill", *gotRevokedBy)
}

func TestBackfillCAG_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	u1 := mustSeedUser(t, ctx, pool, "idemp-active")
	u2 := mustSeedUser(t, ctx, pool, "idemp-revoked")
	seedClusterAdmin(t, ctx, pool, u1)
	seedRevokedClusterAdmin(t, ctx, pool, u2)

	// First run.
	runBackfill(t, ctx, pool)
	var n1 int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings
		  WHERE resource_type = 'cluster' AND subject_id IN ($1, $2)`,
		string(u1), string(u2)).Scan(&n1))
	require.Equal(t, 2, n1)

	// Second run -- must NOT duplicate.
	runBackfill(t, ctx, pool)
	var n2 int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings
		  WHERE resource_type = 'cluster' AND subject_id IN ($1, $2)`,
		string(u1), string(u2)).Scan(&n2))
	assert.Equal(t, n1, n2, "idempotent re-run must not insert duplicates")
}
