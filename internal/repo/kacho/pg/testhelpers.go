// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// testhelpers.go — exported helpers for cross-package integration tests.
//
// These are intentionally guarded by build tag `iamtesthelpers` so they
// do not bloat production binaries. The tag is set automatically by `go
// test`-driven runs (Go test files belong to the same package whether
// they're guarded or not — but exporting helpers as non-test names lets
// other test packages depend on them).
//
// To use from another package's *_test.go:
//
//	dsn := pg.NewTestPostgres(t)
//
// The helper boots a fresh container per call (so tests stay isolated).
package pg

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// NewTestPostgres spins up a clean Postgres container, runs all migrations
// up, and returns the DSN string with search_path=kacho_iam,public.
//
// Suitable for cross-package integration tests; per-call container ensures
// test isolation (slower than shared, safer against state-leak).
func NewTestPostgres(t testing.TB) string {
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

	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "?") {
		return dsn + "&" + optionsParam
	}
	return dsn + "?" + optionsParam
}
