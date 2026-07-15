// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// bootstrap_admin_integration_test.go — Bug B integration tests for
// seed.RunBootstrapAdmin against a real Postgres (testcontainers).
//
// The cluster-admin (`system_admin@cluster_kacho_root`) tuple MUST reach
// OpenFGA via the transactional fga_outbox — never a raw SQL seed that
// bypasses the drainer. These tests prove RunBootstrapAdmin:
//
//   1. user present   → cluster_admin_grant + fga_outbox(fga.tuple.write) row
//      committed atomically, payload = {object:"cluster:cluster_kacho_root",
//      relation:"system_admin", user:"user:<id>"}.
//   2. user absent     → graceful skip, NO rows written.
//   3. idempotent re-run → 23505 graceful skip, NO duplicate grant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupBootstrapDB(t *testing.T) string {
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

	if strings.Contains(dsn, "?") {
		dsn += "&"
	} else {
		dsn += "?"
	}
	return dsn + "options=-c%20search_path%3Dkacho_iam%2Cpublic"
}

func seedBootstrapUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	accID := ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, accID, "ext-"+uid, email, "Bootstrap Admin")
	require.NoError(t, err)
	// accounts.name must match ^[a-z][-a-z0-9]{2,62}$ — derive a valid lowercase
	// suffix from the (crockford-base32, lowercase) account id tail.
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "boot-acc-"+strings.ToLower(accID[len(accID)-6:]), uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid
}

func TestRunBootstrapAdmin_UserPresent_EmitsFGAOutboxTuple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "admin@prorobotech.ru"
	uid := seedBootstrapUser(t, ctx, pool, email)

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.False(t, res.Skipped, "must NOT skip when the bootstrap user exists")
	assert.Equal(t, uid, res.UserID)
	assert.NotEmpty(t, res.GrantID)
	require.NotEmpty(t, res.FGAOutboxID, "must enqueue an fga_outbox row")

	// The fga_outbox row carries the system_admin@cluster tuple for the drainer.
	var eventType string
	var payload []byte
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload FROM fga_outbox ORDER BY id DESC LIMIT 1`).
		Scan(&eventType, &payload))
	assert.Equal(t, "fga.tuple.write", eventType)

	var tuple map[string]string
	require.NoError(t, json.Unmarshal(payload, &tuple))
	assert.Equal(t, "cluster:"+domain.ClusterSingletonID, tuple["object"])
	assert.Equal(t, "system_admin", tuple["relation"])
	assert.Equal(t, "user:"+uid, tuple["user"])

	// Grant row present.
	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, uid).Scan(&grants))
	assert.Equal(t, 1, grants)
}

func TestRunBootstrapAdmin_UserAbsent_GracefulSkip_NoRows(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	// fga_outbox carries baseline rows seeded by SEC-C / SEC-L migrations
	// (0009 / 0010); the skip must add NONE on top of that baseline.
	var outboxBefore int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM fga_outbox`).Scan(&outboxBefore))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(),
		seed.BootstrapAdminInput{Email: "never-registered@prorobotech.ru"})
	require.NoError(t, err)
	assert.True(t, res.Skipped)
	assert.Equal(t, "user not registered", res.SkipReason)

	var grants, outboxAfter int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants`).Scan(&grants))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM fga_outbox`).Scan(&outboxAfter))
	assert.Zero(t, grants, "no grant when user absent")
	assert.Equal(t, outboxBefore, outboxAfter, "no new fga_outbox row when user absent")
}

func TestRunBootstrapAdmin_Idempotent_NoDuplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "admin@prorobotech.ru"
	uid := seedBootstrapUser(t, ctx, pool, email)

	r1, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.False(t, r1.Skipped)

	r2, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	assert.True(t, r2.Skipped, "second run must gracefully skip (23505)")
	assert.Equal(t, uid, r2.UserID)

	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, uid).Scan(&grants))
	assert.Equal(t, 1, grants, "no duplicate grant on re-run")
}
