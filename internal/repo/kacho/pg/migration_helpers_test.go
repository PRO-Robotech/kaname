// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_helpers_test.go — shared helpers for migration-scoped integration
// tests that need finer control than setupTestDB (which runs ALL migrations Up).
//
//   - setupTestDBNoUp: spins up a testcontainers Postgres 16 WITHOUT running any
//     migration, returning the DSN so a test can `goose.UpTo(<n>)` to a precise
//     version (e.g. pre-0033 to plant an OLD-shape fixture, then UpTo the target).
//   - applyMigrationUpBody: re-executes the `-- +goose Up` body of a shipped
//     migration file verbatim (statement-by-statement, honouring goose
//     StatementBegin/End) so an idempotency re-run exercises the REAL migration
//     SQL — not a copy. Used to prove 0033 Up is a no-op on already-scalar rows.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

func setupTestDBNoUp(t testing.TB) string {
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
	return appendSearchPathOptions(dsn)
}

// applyMigrationUpBody reads <prefix>_*.sql, extracts the `-- +goose Up` body and
// executes it against db. goose StatementBegin/End blocks are kept whole; plain
// statements are split on `;`. The migration must be idempotent for a re-run to
// be safe (0033 is — re-running on scalar rows is a no-op).
func applyMigrationUpBody(t *testing.T, db *sql.DB, prefix string) error {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err)
	var file string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix+"_") {
			file = e.Name()
			break
		}
	}
	require.NotEmpty(t, file, "migration file with prefix %q not found", prefix)

	raw, err := migrations.FS.ReadFile(file)
	require.NoError(t, err)
	body := string(raw)

	// Up section is between `-- +goose Up` and `-- +goose Down`.
	up := body
	if i := strings.Index(body, "-- +goose Down"); i >= 0 {
		up = body[:i]
	}
	up = strings.Replace(up, "-- +goose Up", "", 1)

	for _, stmt := range splitGooseStatements(up) {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// splitGooseStatements splits a goose Up body into executable statements,
// keeping `-- +goose StatementBegin/End` blocks intact (PL/pgSQL function bodies)
// and splitting the rest on `;`.
func splitGooseStatements(body string) []string {
	var out []string
	lines := strings.Split(body, "\n")
	var cur strings.Builder
	inBlock := false
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		switch {
		case trimmed == "-- +goose StatementBegin":
			inBlock = true
			continue
		case trimmed == "-- +goose StatementEnd":
			inBlock = false
			out = append(out, cur.String())
			cur.Reset()
			continue
		case strings.HasPrefix(trimmed, "--"):
			continue
		}
		cur.WriteString(ln)
		cur.WriteString("\n")
		if !inBlock && strings.HasSuffix(trimmed, ";") {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}
