// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// testhelpers.go — exported helpers for cross-package integration tests.
//
// The helper lives in a non-_test.go file so other packages' *_test.go can depend on
// it. It pulls in testing; that is acceptable for a helper never linked into a
// production binary (nothing under cmd/ imports it).
//
// To use from another package's *_test.go:
//
//	dsn := pg.NewTestPostgres(t)
package pg

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// NewTestPostgres returns a DSN for the CALLER's own database, with
// search_path=kacho_iam,public.
//
// It used to boot a fresh container and replay every migration on each call, which is
// what made packages calling it grow past the 600s `go test` gives a package by
// default. Now it hands back a database on the one container the calling test binary
// owns — see internal/pgtest for why a clone of a migrated template is the same
// isolation a separate container gave.
//
// The caller's package must wire TestMain, because the container belongs to the test
// BINARY and each package is its own binary:
//
//	func TestMain(m *testing.M) {
//		os.Exit(pgtest.Run(m, pgtest.Config{
//			Name:    "iam",
//			Migrate: pgtest.Goose(migrations.FS),
//		}))
//	}
//
// Without it pgtest fails the test naming what is missing, rather than handing back a
// DSN pointing at nothing.
func NewTestPostgres(t testing.TB) string {
	t.Helper()
	return AppendIAMSearchPath(pgtest.NewDB(t))
}

// AppendIAMSearchPath adds the libpq runtime parameter that puts kacho_iam on the
// search path. The URL-query form `search_path=` is not honoured by pgx, hence the
// `options=-c …` spelling.
func AppendIAMSearchPath(dsn string) string {
	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "?") {
		return dsn + "&" + optionsParam
	}
	return dsn + "?" + optionsParam
}
