// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// testhelpers_test.go — database setup + seed helpers for cluster handler
// integration tests. Mirrors the helpers in internal/repo/kaname/pg/ but lives
// in the `cluster_test` package so the handler integration tests can call them
// directly without depending on the pg-internal test package.
//
// The Postgres itself is one per test BINARY (testmain_pgtest_test.go); each
// caller of setupTestDB still gets its own database.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// setupTestDB hands the calling test its OWN database, with kaname on the
// search path.
//
// It used to start a fresh container and replay the whole migration chain on
// every call. The database now comes from the one container this test binary
// owns (wired in testmain_pgtest_test.go), cloned from a template migrated once
// — see pkg/pgtest for why a clone is the same isolation a separate
// container gave.
func setupTestDB(t testing.TB) string {
	t.Helper()
	return pgtest.NewDB(t)
}

// mustSeedUser inserts a user + account row and returns the UserID.
// Uses corelib ids.NewID (the SAME generator the production user/account create
// paths use — internal/apps/kaname/api/user/{invite,internal_upsert}.go), which
// yields `usr<17-char>` (no underscore) that PASSES the GrantAdmin/RevokeAdmin
// subjectIDRe (`^usr[0-9a-hjkmnp-tv-z]{17}$`). The previous domain.NewKac127ID
// produced an underscore-shaped id that subjectIDRe REJECTS, making every
// TestCluster_6_0x use-case test fail once actually run (kacho-iam#140 — latent
// because these apps-level integration tests were not exercised by CI).
func mustSeedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin TX for seed user")
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"Test User "+suffix,
	)
	require.NoError(t, err, "seed user INSERT")

	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("seed-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid),
	)
	require.NoError(t, err, "seed user account INSERT")

	require.NoError(t, tx.Commit(ctx), "commit seed user TX")
	return uid
}

// seedClusterAdmin inserts an active (granted_until=NULL) cluster_admin_grants row.
func seedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, now(), NULL)`,
		id, domain.ClusterSingletonID, string(subject))
	require.NoError(t, err, "seed cluster_admin_grants row")
}

// bootstrapSeedSubject returns the id of the bootstrap-admin ServiceAccount
// that migration 0058 seeds a permanent cluster system_admin grant for, and
// asserts that grant is the only service_account one (singleton by design).
func bootstrapSeedSubject(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT subject_id FROM kaname.cluster_admin_grants
		  WHERE subject_type = 'service_account' AND granted_until IS NULL`)
	require.NoError(t, err)
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Len(t, ids, 1, "migration 0058 seeds exactly one bootstrap-SA cluster admin grant")
	return ids[0]
}

// decommissionBootstrapSeedGrant revokes the migration-seeded bootstrap-SA
// grant so a user grant can become the LAST active grant in the table.
//
// The last-admin guard counts every active grant regardless of subject_type,
// while RevokeAdmin only ever revokes subject_type='user' rows — so while the
// 0058 seed is active, "revoking the last admin" is unreachable through the
// RPC. Tests for that guard must first model a cluster whose bootstrap SA has
// been decommissioned (revoked, not deleted — the real lifecycle path).
func decommissionBootstrapSeedGrant(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.cluster_admin_grants
		    SET granted_until = now()
		  WHERE subject_type = 'service_account' AND granted_until IS NULL`)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(),
		"exactly one seeded service_account grant must be decommissioned")
}

// seedRevokedClusterAdmin inserts a history row with granted_until set.
func seedRevokedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	revokedAt := time.Now().UTC().Add(-1 * time.Hour)
	grantedAt := revokedAt.Add(-1 * time.Hour)
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, $4, $5)`,
		id, domain.ClusterSingletonID, string(subject), grantedAt, revokedAt)
	require.NoError(t, err, "seed revoked cluster_admin_grants row")
}

// poolFromDSN creates a new pgxpool for the given DSN — used in tests that
// need both a handler (via buildHandler) and direct-pool access for assertions.
func poolFromDSN(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}
