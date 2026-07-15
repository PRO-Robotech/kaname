// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster_test

// testhelpers_test.go — testcontainers setup + seed helpers for cluster
// handler integration tests. Mirrors the helpers in internal/repo/kacho/pg/
// but lives in the `cluster_test` package so the handler integration tests
// can call them directly without depending on the pg-internal test package.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// setupTestDB starts a fresh Postgres testcontainer, runs goose migrations,
// and returns a DSN with kacho_iam search_path set.
func setupTestDB(t testing.TB) string {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	return appendSearchPathOptions(dsn)
}

func appendSearchPathOptions(dsn string) string {
	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "options=") || strings.Contains(dsn, "options%3D") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + optionsParam
}

// mustSeedUser inserts a user + account row and returns the UserID.
// Uses corelib ids.NewID (the SAME generator the production user/account create
// paths use — internal/apps/kacho/api/user/{invite,internal_upsert}.go), which
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
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"Test User "+suffix,
	)
	require.NoError(t, err, "seed user INSERT")

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
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
		`INSERT INTO kacho_iam.cluster_admin_grants
		     (id, cluster_id, subject_type, subject_id, granted_by, granted_at, granted_until)
		 VALUES ($1, $2, 'user', $3, $3, now(), NULL)`,
		id, domain.ClusterSingletonID, string(subject))
	require.NoError(t, err, "seed cluster_admin_grants row")
}

// seedRevokedClusterAdmin inserts a history row with granted_until set.
func seedRevokedClusterAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject domain.UserID) {
	t.Helper()
	id := domain.NewKac127ID(domain.PrefixClusterAdminGrant)
	revokedAt := time.Now().UTC().Add(-1 * time.Hour)
	grantedAt := revokedAt.Add(-1 * time.Hour)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.cluster_admin_grants
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
