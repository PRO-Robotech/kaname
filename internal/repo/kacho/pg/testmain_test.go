// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestMain owns the one Postgres this package runs against, and enforces that the
// integration proofs cannot silently vanish from CI.
//
// # Why one container rather than one per test
//
// setupTestDB used to start a fresh container AND replay every migration on each
// call, and it is called 364 times here. That is what made this the most
// expensive package in the tree: ~22 minutes on an idle machine, without the race
// detector CI adds on top of a 25-minute budget. The cost was the harness, not
// the tests.
//
// Now the container starts once, the migrations run once into a template
// database, and each caller gets its own database cloned from that template.
// Postgres builds a clone by copying the template's files, so it is cheap while
// remaining a genuinely separate database: the isolation the CAS / UNIQUE /
// EXCLUDE / SKIP LOCKED proofs depend on is unchanged, and concurrent goroutines
// inside one test still contend on the same real rows.
//
// # The enforcement half (unchanged in intent)
//
// Every integration test here individually skips under `-short` — the sole
// silent-skip vector, since none of them gate on a separate Docker probe. A full
// CI run invoked with `-short` would therefore drop every race proof that
// data-integrity.md requires while still reporting green (a skipped test is
// neither red nor green). When KACHO_IAM_REQUIRE_INTEGRATION is set (the CI
// integration lane), `-short` is refused hard.
//
// Under `-short` no container starts at all: every test that would use one skips,
// so paying for it would be pure cost.
func TestMain(m *testing.M) {
	flag.Parse()
	if os.Getenv("KACHO_IAM_REQUIRE_INTEGRATION") != "" && testing.Short() {
		fmt.Fprintln(os.Stderr,
			"KACHO_IAM_REQUIRE_INTEGRATION set but -short given: refusing to skip integration/concurrency/DB-trigger proofs")
		os.Exit(1)
	}
	if testing.Short() {
		os.Exit(m.Run())
	}

	code, err := runWithSharedPostgres(m)
	if err != nil {
		// A missing Docker daemon must FAIL here, never skip — the same posture as
		// before, when the per-test container start failed.
		fmt.Fprintf(os.Stderr, "integration Postgres unavailable: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

const (
	// templateDB holds the migrated schema every test database is cloned from.
	templateDB = "kacho_iam_template"
	// adminDB is where CREATE/DROP DATABASE are issued from. It is never the
	// template (Postgres refuses to copy a database that has open connections) and
	// never a test's own database (a session cannot drop the one it is using).
	adminDB = "kacho_iam_admin"
)

var (
	// sharedBaseDSN — connection string to the package container, pointing at
	// adminDB. Empty until TestMain has started the container.
	sharedBaseDSN string
	// testDBSeq names cloned databases uniquely within the run.
	testDBSeq atomic.Int64
)

// runWithSharedPostgres starts the container, prepares the template, and runs the
// suite. The container is terminated on every path out.
func runWithSharedPostgres(m *testing.M) (int, error) {
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(adminDB),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return 0, fmt.Errorf("start postgres: %w", err)
	}
	defer func() { _ = pgc.Terminate(ctx) }()

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return 0, fmt.Errorf("connection string: %w", err)
	}
	sharedBaseDSN = dsn

	if err := prepareTemplate(); err != nil {
		return 0, err
	}
	return m.Run(), nil
}

// prepareTemplate creates the template database and migrates it ONCE. The
// connection is closed before returning: Postgres refuses `CREATE DATABASE …
// TEMPLATE t` while anything is still connected to t.
func prepareTemplate() error {
	admin, err := sql.Open("pgx", sharedBaseDSN)
	if err != nil {
		return fmt.Errorf("open admin: %w", err)
	}
	defer func() { _ = admin.Close() }()

	if _, err := admin.Exec(`CREATE DATABASE ` + templateDB); err != nil {
		return fmt.Errorf("create template database: %w", err)
	}

	tmpl, err := sql.Open("pgx", dsnForDB(templateDB))
	if err != nil {
		return fmt.Errorf("open template: %w", err)
	}
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		_ = tmpl.Close()
		return fmt.Errorf("goose dialect: %w", err)
	}
	if err := goose.Up(tmpl, "."); err != nil {
		_ = tmpl.Close()
		return fmt.Errorf("migrate template: %w", err)
	}
	if err := tmpl.Close(); err != nil {
		return fmt.Errorf("close template: %w", err)
	}
	return nil
}

// dsnForDB rewrites the shared DSN to point at another database on the same
// container.
func dsnForDB(name string) string {
	u, err := url.Parse(sharedBaseDSN)
	if err != nil {
		// sharedBaseDSN comes from the container driver; if it does not parse the
		// harness itself is broken, and returning something plausible would hide it.
		panic(fmt.Sprintf("unparseable container DSN %q: %v", sharedBaseDSN, err))
	}
	u.Path = "/" + name
	return u.String()
}
