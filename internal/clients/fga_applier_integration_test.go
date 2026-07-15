// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_applier_integration_test.go — end-to-end test that proves the full
// chain works: row in `kacho_iam.fga_outbox` (shape written by bootstrap_admin)
// → LISTEN/NOTIFY wakeup → corelib drainer → clients.NewFGAApplier
// → OpenFGAStubClient.WriteTuples → tuple visible via Check.
//
// This is the integration sibling of fga_applier_test.go (unit tests of the
// applier in isolation). It uses:
//
//   - testcontainers Postgres 16-alpine (same pattern as
//     internal/repo/kacho/pg/account_integration_test.go)
//   - real kacho-iam migrations (0001 + 0002 — fga_outbox table + NOTIFY trigger)
//   - real corelib drainer (from kacho-corelib/outbox/drainer)
//   - real FGAApplier (clients.NewFGAApplier wired over OpenFGAStubClient)
//
// Smoke acceptance: bootstrap-admin at startup → 1 row in fga_outbox →
// within 5s the row is marked sent_at NOT NULL → the stub-FGA contains
// the tuple.
//
// Skipped under `go test -short` to keep fast unit runs hermetic.
package clients_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// setupFGAOutboxDB spins up a Postgres testcontainer, runs the kacho-iam
// migrations onto it, and returns a pgxpool aimed at the fresh DB with
// search_path = kacho_iam,public.
func setupFGAOutboxDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in -short mode (testcontainers Postgres)")
	}
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

	// Append search_path so unqualified SQL resolves to kacho_iam (parity with
	// the production binary's DSN — see config.DSN()).
	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if !strings.Contains(dsn, "options=") && !strings.Contains(dsn, "options%3D") {
		if strings.Contains(dsn, "?") {
			dsn += "&" + optionsParam
		} else {
			dsn += "?" + optionsParam
		}
	}

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// TestIntegration_BootstrapAdminGrant_EndToEnd is the foundational
// end-to-end proof: a bootstrap-admin-shape row inserted into
// `kacho_iam.fga_outbox` is picked up by the drainer (via NOTIFY) and
// applied to the OpenFGA stub within a few seconds. After that:
//
//   - the row is marked sent_at IS NOT NULL, last_error IS NULL,
//     attempt_count = 1
//   - the stub-FGA Check returns ALLOWED for the exact tuple
//
// Without the drainer wiring, the row would sit pending forever — this
// test pins the wiring.
func TestIntegration_BootstrapAdminGrant_EndToEnd(t *testing.T) {
	pool := setupFGAOutboxDB(t)
	logger := observability.NewSlogger(testLoggerWriter{t})

	stub := clients.NewOpenFGAStubClient()
	d, err := drainer.New[clients.FGAOutboxEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.fga_outbox",
			Channel:      "kacho_iam_fga_outbox",
			BatchSize:    32,
			PollFallback: 2 * time.Second, // faster than prod (30s) for test stability
			MaxAttempts:  5,
			BackoffMin:   50 * time.Millisecond,
			BackoffMax:   500 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeFGAOutboxEvent,
		clients.NewFGAApplier(stub),
		logger,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	drainerDone := make(chan error, 1)
	go func() { drainerDone <- d.Run(ctx) }()

	// Deterministically wait until the drainer's dedicated connection has issued
	// LISTEN — observable in pg_stat_activity — BEFORE we INSERT, so this test
	// actually exercises the NOTIFY delivery path rather than the startup catch-up
	// SELECT. A fixed sleep could, on a loaded runner, let the INSERT race ahead of
	// LISTEN, so the catch-up would silently mask a broken NOTIFY path (e.g. a wrong
	// channel name) while the test stays green. Polling the catalog removes that
	// timing dependence: once the LISTEN backend is idle on `LISTEN <channel>`, the
	// row we insert next can only reach the drainer via NOTIFY.
	require.Eventually(t, func() bool {
		var n int
		if qerr := pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity
			  WHERE datname = current_database()
			    AND state = 'idle'
			    AND query = 'LISTEN kacho_iam_fga_outbox'`).Scan(&n); qerr != nil {
			return false
		}
		return n > 0
	}, 5*time.Second, 20*time.Millisecond,
		"drainer never established LISTEN on kacho_iam_fga_outbox")

	// Payload shape matches bootstrap_admin.go:124-128 exactly.
	payload, err := json.Marshal(map[string]any{
		"object":   "cluster:default",
		"relation": "system_admin",
		"user":     "user:usr_root_e2e",
	})
	require.NoError(t, err)

	var insertedID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload)
		 VALUES ('fga.tuple.write', $1::jsonb)
		 RETURNING id`,
		payload,
	).Scan(&insertedID)
	require.NoError(t, err)
	require.Positive(t, insertedID)

	// Poll for delivery (≤ 5s — generous CI margin; on dev usually <50ms via NOTIFY).
	require.Eventually(t, func() bool {
		ok, _ := stub.Check(ctx, "user:usr_root_e2e", "system_admin", "cluster:default")
		return ok
	}, 5*time.Second, 50*time.Millisecond,
		"OpenFGA stub never received the tuple — drainer chain is broken")

	// Confirm the row is fully marked sent.
	var (
		sentAt       *time.Time
		lastError    *string
		attemptCount int
	)
	err = pool.QueryRow(ctx,
		`SELECT sent_at, last_error, attempt_count
		   FROM kacho_iam.fga_outbox WHERE id = $1`,
		insertedID,
	).Scan(&sentAt, &lastError, &attemptCount)
	require.NoError(t, err)
	require.NotNil(t, sentAt, "row must be marked sent_at after successful apply")
	assert.Nil(t, lastError, "last_error must be NULL on happy path")
	assert.Equal(t, 1, attemptCount, "one attempt should be enough on happy path")

	// Graceful shutdown.
	cancel()
	select {
	case err := <-drainerDone:
		assert.NoError(t, err, "drainer.Run should exit cleanly on ctx cancel")
	case <-time.After(3 * time.Second):
		t.Fatal("drainer.Run did not exit within 3s of ctx cancel")
	}
}

// TestIntegration_StartupCatchUp_ExistingRow_Applied is the second smoke:
// row INSERTED BEFORE the drainer starts must still be applied via startup
// catch-up SELECT (not via NOTIFY). This is the path that fires on every
// kacho-iam restart in prod when bootstrap_admin inserted before
// the drainer goroutine got to LISTEN.
func TestIntegration_StartupCatchUp_ExistingRow_Applied(t *testing.T) {
	pool := setupFGAOutboxDB(t)
	logger := observability.NewSlogger(testLoggerWriter{t})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// INSERT pending row BEFORE drainer is wired.
	payload, _ := json.Marshal(map[string]any{
		"object":   "cluster:default",
		"relation": "system_admin",
		"user":     "user:usr_catchup",
	})
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload)
		 VALUES ('fga.tuple.write', $1::jsonb)`,
		payload)
	require.NoError(t, err)

	// Now wire + start drainer.
	stub := clients.NewOpenFGAStubClient()
	d, err := drainer.New[clients.FGAOutboxEvent](
		pool,
		drainer.Config{
			Table:        "kacho_iam.fga_outbox",
			Channel:      "kacho_iam_fga_outbox",
			BatchSize:    32,
			PollFallback: 2 * time.Second,
			MaxAttempts:  5,
			BackoffMin:   50 * time.Millisecond,
			BackoffMax:   500 * time.Millisecond,
			ApplyTimeout: 2 * time.Second,
		},
		clients.DecodeFGAOutboxEvent,
		clients.NewFGAApplier(stub),
		logger,
	)
	require.NoError(t, err)

	drainerDone := make(chan error, 1)
	go func() { drainerDone <- d.Run(ctx) }()

	require.Eventually(t, func() bool {
		ok, _ := stub.Check(ctx, "user:usr_catchup", "system_admin", "cluster:default")
		return ok
	}, 5*time.Second, 50*time.Millisecond,
		"startup catch-up did not pick up the pre-existing row")

	cancel()
	select {
	case <-drainerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("drainer.Run did not exit within 3s of ctx cancel")
	}
}

// testLoggerWriter adapts t.Log into io.Writer for observability.NewSlogger.
// Each Write call becomes one t.Log line, which keeps slog output attached
// to the surrounding test in `go test -v`.
type testLoggerWriter struct{ t *testing.T }

func (w testLoggerWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}
