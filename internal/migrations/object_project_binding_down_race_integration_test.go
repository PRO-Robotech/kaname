// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectProjectBindingDown_ConcurrentWriter(t *testing.T) {
	for _, outcome := range []string{"absent", "rollback", "commit"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			dsn := pgtest.NewEmptyDB(t)
			db, err := sql.Open("pgx", dsn)
			require.NoError(t, err)
			defer db.Close()
			goose.SetBaseFS(migrations.FS)
			require.NoError(t, goose.SetDialect("postgres"))
			require.NoError(t, goose.UpToContext(ctx, db, ".", 20261026120000))
			_, err = db.ExecContext(ctx, `UPDATE kaname.catalog_resource SET permanent_project=true WHERE dotted='registry.registries'`)
			require.NoError(t, err)
			var bindings int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.object_project_binding`).Scan(&bindings))
			require.Zero(t, bindings, "фикстура: привязок ещё нет")
			var writer *sql.Tx
			var writerPID int
			if outcome != "absent" {
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer writer.Rollback()
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID))
				_, err = writer.ExecContext(ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_project_id,parent_account_id,labels,source_version) VALUES ('registry.registries','down-race-object','down-race-project','down-race-account','{}',now())`)
				require.NoError(t, err)
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT count(*) FROM kaname.object_project_binding`).Scan(&bindings))
				require.Equal(t, 1, bindings, "фикстура: настоящий writer создал привязку")
			}
			downDB, err := sql.Open("pgx", dsn)
			require.NoError(t, err)
			defer downDB.Close()
			downDB.SetMaxOpenConns(1)
			var downPID int
			require.NoError(t, downDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&downPID))
			done := make(chan error, 1)
			go func() { done <- goose.DownToContext(ctx, downDB, ".", 20261026090001) }()
			if writer != nil {
				require.Eventually(t, func() bool {
					var waiting bool
					err := db.QueryRowContext(ctx, `SELECT $1::integer = ANY(pg_blocking_pids($2))`, writerPID, downPID).Scan(&waiting)
					return err == nil && waiting
				}, 15*time.Second, 10*time.Millisecond, "фикстура: настоящий Down ждёт writer")
				t.Logf("Down pid=%d blocked by writer pid=%d, outcome=%s", downPID, writerPID, outcome)
				if outcome == "commit" {
					require.NoError(t, writer.Commit())
				} else {
					require.NoError(t, writer.Rollback())
				}
			}
			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var exists bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_regclass('kaname.object_project_binding') IS NOT NULL`).Scan(&exists))
			var mirrors int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_id='down-race-object'`).Scan(&mirrors))
			if outcome == "commit" {
				assert.ErrorContains(t, err, "rolling back would let an object move between projects")
				assert.True(t, exists, "закоммиченная постоянная привязка должна пережить отказ Down")
				assert.Equal(t, 1, mirrors)
				if exists {
					require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.object_project_binding WHERE object_id='down-race-object'`).Scan(&bindings))
					assert.Equal(t, 1, bindings)
				}
			} else {
				assert.NoError(t, err)
				assert.False(t, exists)
				assert.Zero(t, mirrors)
			}
		})
	}
}
