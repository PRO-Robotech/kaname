// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstrap_token

import (
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
)

// setupTestDB hands the calling test its OWN database — all goose migrations
// already applied (including 0058, which seeds the bootstrap SA + grant) — and
// returns a dsn with search_path=kacho_iam.
//
// It used to start a fresh container and replay the whole chain on every call.
// The database now comes from the one container this test binary owns (wired in
// testmain_pgtest_test.go), cloned from a template migrated once — see
// internal/pgtest for why a clone is the same isolation a separate container
// gave. The 0058 seed is part of the template, so it is present in every clone.
func setupTestDB(t testing.TB) string {
	t.Helper()
	return appendSearchPathOptions(pgtest.NewDB(t))
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
