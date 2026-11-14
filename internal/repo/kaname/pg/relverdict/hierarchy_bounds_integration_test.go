// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Исполняется именно scope CTE каждого боевого запроса. Перенумеровываются
// только его четыре параметра; алгоритм обхода и таблица не заменяются.
// Посев проверяет SQL-границу, а не выдаётся за RegisterResource/API acceptance.
func TestNativeHierarchySQLFiveHopsFourParents(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	edge := func(id, parent string, depth int) {
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth) VALUES('hierarchy_probe',$1,'hierarchy_probe',$2,$3)`, id, parent, depth)
		require.NoError(t, err)
	}
	for i := 0; i < 6; i++ {
		edge(fmt.Sprintf("hop%d", i), fmt.Sprintf("hop%d", i+1), 1)
	}
	for i := 1; i <= 4; i++ {
		edge("fanout", fmt.Sprintf("parent%d", i), i)
	}
	forms := []struct{ name, sql, typ, id, depth, fanout string }{
		{"ask", verdictSQL, "$2", "$3", "$7", "$12"},
		{"many", verdictManySQL, "$2", "i.object_id", "$7", "$12"},
		{"list", listSQL, "$2", "c.object_id", "$5", "$12"},
		{"subjects", subjectsSQL, "$1", "$2", "$5", "$10"},
		{"expand", expandSQL, "$1", "$2", "$3", "$8"},
	}
	// Пакет many/list имеет внешнюю корреляцию: её форма проверяется отдельно
	// ниже при извлечении и заменяется только значением исследуемого root ID.
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			columns := "s_type, s_id, depth"
			prefix := ""
			if f.name == "many" || f.name == "list" {
				columns = "object_id, s_type, s_id, depth"
				table := "ids"
				if f.name == "list" {
					table = "candidate"
				}
				prefix = table + "(object_id) AS (SELECT $2::text), "
			}
			marker := "scope(" + columns + ") AS ("
			start := strings.Index(f.sql, marker)
			require.GreaterOrEqual(t, start, 0)
			tail := f.sql[start+len(marker):]
			end := strings.Index(tail, "\n),")
			require.GreaterOrEqual(t, end, 0)
			body := tail[:end]
			// Остальные параметры основного запроса этому CTE не принадлежат.
			body = strings.NewReplacer(f.fanout+"::int", "$4::int", f.depth+"::int", "$3::int", f.typ+"::text", "$1::text", f.id+"::text", "$2::text").Replace(body)
			sql := "WITH RECURSIVE " + prefix + "scope(" + columns + ") AS (" + body + ") SELECT s_id,min(depth) FROM scope GROUP BY s_id ORDER BY s_id"
			ask := func(root string) map[string]int {
				rows, err := tx.Query(ctx, sql, "hierarchy_probe", root, hierarchy.MaxPointerHops, hierarchy.MaxImmediateParents)
				require.NoError(t, err)
				defer rows.Close()
				out := map[string]int{}
				for rows.Next() {
					var id string
					var depth int
					require.NoError(t, rows.Scan(&id, &depth))
					out[id] = depth
				}
				require.NoError(t, rows.Err())
				return out
			}
			require.Equal(t, map[string]int{"hop0": 0, "hop1": 1, "hop2": 2, "hop3": 3, "hop4": 4, "hop5": 5}, ask("hop0"))
			require.Equal(t, map[string]int{"fanout": 0, "parent1": 1, "parent2": 1, "parent3": 1, "parent4": 1}, ask("fanout"))
		})
	}
	// Пятый stored link запрещён прежней схемой, даже когда traversal допускает 5.
	savepoint, err := tx.Begin(ctx)
	require.NoError(t, err)
	_, err = savepoint.Exec(ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth) VALUES('hierarchy_probe','fanout','hierarchy_probe','parent5',5)`)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "23514", pgerr.Code)
	require.Equal(t, "resource_parent_edge_depth_bounded", pgerr.ConstraintName)
	require.NoError(t, savepoint.Rollback(ctx))
}

// Отдельно проверяется SQL ABI: поздний clock не занимает место fanout.
func TestNativeHierarchyAdministrativeParameterSeparation(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, axis := range []string{"", "kaname.accounts"} {
			sql, err := administrativeQuerySQL(axis, nested)
			require.NoError(t, err)
			require.Contains(t, sql, "LIMIT $12::int")
			require.Contains(t, sql, "s.depth < $7::int")
			require.Contains(t, sql, "b.expires_at > $13::timestamptz")
			require.Contains(t, sql, "$19::text")
		}
	}
}
