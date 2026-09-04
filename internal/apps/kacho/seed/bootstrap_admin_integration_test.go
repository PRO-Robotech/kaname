// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// bootstrap_admin_integration_test.go — Bug B integration tests for
// seed.RunBootstrapAdmin against a real Postgres (testcontainers).
//
// The cluster-admin (`system_admin@cluster_kacho_root`) tuple MUST be stated
// through the transactional journal `kacho_iam.fga_outbox` — never by a raw SQL
// seed that goes around it. Stage S6 removed the external engine that used to
// consume that journal; the journal itself remains, and a database trigger folds
// each row into `kacho_iam.relation_fact`, which is what a verdict is read from.
// So the requirement did not weaken when the consumer changed — it is now the ONLY
// way the grant becomes an answer. These tests prove RunBootstrapAdmin:
//
//   1. user present   → cluster_admin_grant + fga_outbox(fga.tuple.write) row
//      committed atomically, payload = {object:"cluster:cluster_kacho_root",
//      relation:"system_admin", user:"user:<id>"}.
//   2. user absent     → graceful skip, NO rows written.
//   3. idempotent re-run → 23505 graceful skip, NO duplicate grant.

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// setupBootstrapDB hands the caller its own migrated database on the package's
// shared Postgres, with search_path defaulting to kacho_iam.
//
// It used to boot a container and replay the whole migration chain per call, which
// this package paid seven times over. The caller still gets a database of its own —
// see internal/pgtest for why a clone of a migrated template is the isolation a
// separate container gave.
func setupBootstrapDB(t *testing.T) string {
	t.Helper()

	return pgtest.NewDB(t)
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
	// accounts.name must match the single resource-name form of the tree — derive a valid lowercase
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

	// The journal row carries the system_admin@cluster tuple; the trigger on that
	// table folds it into `kacho_iam.relation_fact` in this very transaction.
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

	// Both tables carry baseline rows seeded by migrations — fga_outbox from
	// SEC-C / SEC-L (0009 / 0010), and cluster_admin_grants from 0058, which
	// seeds the bootstrap-admin ServiceAccount's cluster system_admin grant.
	// The skip must add NONE on top of that baseline, so assert the delta.
	var grantsBefore, outboxBefore int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants`).Scan(&grantsBefore))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM fga_outbox`).Scan(&outboxBefore))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(),
		seed.BootstrapAdminInput{Email: "never-registered@prorobotech.ru"})
	require.NoError(t, err)
	assert.True(t, res.Skipped)
	assert.Equal(t, "user not registered", res.SkipReason)

	var grantsAfter, outboxAfter int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants`).Scan(&grantsAfter))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM fga_outbox`).Scan(&outboxAfter))
	assert.Equal(t, grantsBefore, grantsAfter, "no new grant when user absent")
	assert.Equal(t, outboxBefore, outboxAfter, "no new fga_outbox row when user absent")

	// And specifically: no user-subject grant at all — RunBootstrapAdmin only
	// ever writes subject_type='user', so this stays exact regardless of which
	// system principals the migrations seed.
	var userGrants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_type='user'`).Scan(&userGrants))
	assert.Zero(t, userGrants, "no user grant when the bootstrap user is absent")
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
