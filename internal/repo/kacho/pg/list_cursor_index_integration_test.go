// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// list_cursor_index_integration_test.go — every table a paged listing walks by
// (created_at, id) must have an index that serves that order.
//
// This is a gate on a CLASS, so it is written as a census rather than as eight
// assertions: the set of tables is derived from what the repository code actually
// orders by, and a new listing that adopts the cursor convention without an index
// turns this red instead of quietly costing a sequential scan per page.
//
// Why the schema and not a plan: on the tables a test can create, the planner picks a
// sequential scan whichever indexes exist, because everything fits in one page. An
// EXPLAIN-based check would therefore pass on a tree with no indexes at all — the
// exact shape of a check that cannot fail.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// cursorOrderedTables reads the repository sources and returns every table whose
// listing orders by the cursor. Derived, not listed: a hard-coded table list goes
// stale exactly when a new listing is added, which is when the check is needed.
func cursorOrderedTables(t *testing.T) []string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	entries, err := filepath.Glob(filepath.Join(dir, "*_repo.go"))
	require.NoError(t, err)
	require.NotEmpty(t, entries, "no repository sources found — the census read nothing")

	// Only SQL LITERALS are read, never the file as a whole: prose in a comment
	// contains the words too, and a regex over raw text finds "FROM the" in an
	// explanation of the very rule being checked.
	literalRe := regexp.MustCompile("(?s)`([^`]*)`")
	// Имя может быть КВАЛИФИЦИРОВАНО схемой (`FROM kacho_iam.limits`), и тогда
	// таблица — второй сегмент, а не первый. Прежняя форма брала первый
	// идентификатор после FROM и на квалифицированном имени возвращала СХЕМУ:
	// перепись объявляла таблицей `kacho_iam`, дальше искала у неё индекс и
	// падала — вердикт неверный, а не находка.
	//
	// Класс шире одного запроса: квалифицированные имена есть в 11 файлах
	// репозиториев iam и ещё в vpc/nlb/storage; гейт не краснел лишь потому,
	// что курсорные списки до сих пор писались без схемы. Первый же такой
	// список сделал бы вердикт ложным независимо от того, есть индекс или нет.
	fromRe := regexp.MustCompile(`(?is)\bFROM\s+(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)`)

	found := map[string]bool{}
	scanned, literals := 0, 0
	for _, path := range entries {
		raw, rerr := os.ReadFile(path)
		require.NoError(t, rerr)
		scanned++
		for _, lit := range literalRe.FindAllStringSubmatch(string(raw), -1) {
			sql := lit[1]
			idx := strings.Index(sql, "ORDER BY created_at ASC, id ASC")
			if idx < 0 {
				continue
			}
			literals++
			// The table is the last FROM before the ORDER BY of THIS statement.
			all := fromRe.FindAllStringSubmatch(sql[:idx], -1)
			if len(all) == 0 {
				continue
			}
			found[all[len(all)-1][1]] = true
		}
	}
	out := make([]string, 0, len(found))
	for name := range found {
		out = append(out, name)
	}
	sort.Strings(out)
	t.Logf("census: %d repository sources scanned, %d cursor-ordered statements, %d tables: %s",
		scanned, literals, len(out), strings.Join(out, ", "))
	return out
}

func TestListCursor_EveryPagedTableHasItsIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	tables := cursorOrderedTables(t)
	require.NotEmpty(t, tables, "the census found no cursor-ordered table — it read nothing")

	for _, table := range tables {
		t.Run(table, func(t *testing.T) {
			// Does an index exist whose FIRST two columns are (created_at, id)? The
			// leading position is what makes it usable for the order; an index that
			// merely mentions the columns does not.
			var count int
			err := pool.QueryRow(ctx, `
				SELECT count(*)
				  FROM pg_index i
				  JOIN pg_class c   ON c.oid = i.indrelid
				  JOIN pg_class ic  ON ic.oid = i.indexrelid
				  JOIN pg_namespace n ON n.oid = c.relnamespace
				 WHERE n.nspname = 'kacho_iam'
				   AND c.relname = $1
				   AND (SELECT a.attname FROM pg_attribute a
				         WHERE a.attrelid = c.oid AND a.attnum = i.indkey[0]) = 'created_at'
				   AND (SELECT a.attname FROM pg_attribute a
				         WHERE a.attrelid = c.oid AND a.attnum = i.indkey[1]) = 'id'`,
				table).Scan(&count)
			require.NoError(t, err)
			require.Positive(t, count, fmt.Sprintf(
				"kacho_iam.%s is listed with ORDER BY (created_at, id) and a keyset cursor, "+
					"but no index leads with those columns — every page is a sequential scan "+
					"plus a sort, and the cursor saves only the rows it excludes", table))
		})
	}
}
