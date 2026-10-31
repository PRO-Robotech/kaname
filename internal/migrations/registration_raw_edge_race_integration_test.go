// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"fmt"
	"github.com/PRO-Robotech/corelib/migratorrun"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Reviewer-only external probe: no injected trigger/DDL/callback. The normal
// migration runner creates the schema; the contested schedule uses plain DML.
func TestReview983_RawEdgeVersusFirstBinding(t *testing.T) {
	for _, tc := range []struct{ name, edgeProject string }{
		{"legal_same_project_twin", "review-project-P"},
		{"foreign_project_edge", "review-project-Q"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			dsn := pgtest.NewEmptyDB(t)
			runner, err := migratorrun.New(migratorrun.Config{Service: "kaname", Dialect: "postgres", DSN: dsn, FS: migrations.FS, MigrationsDir: "."})
			require.NoError(t, err)
			require.NoError(t, runner.Up(ctx, ""))
			observer, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer observer.Close(context.Background())
			raw, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer raw.Close(context.Background())
			command, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer command.Close(context.Background())
			tag, err := observer.Exec(ctx, `UPDATE kaname.catalog_resource SET permanent_project=true WHERE dotted='registry.registries' AND live`)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected(), "declared BEFORE either operation: not an R8 transition")
			id := "review983-" + tc.name
			rawTx, err := raw.Begin(ctx)
			require.NoError(t, err)
			defer rawTx.Rollback(context.Background())
			_, err = rawTx.Exec(ctx, `INSERT INTO kaname.resource_parent_edge
   (object_type,object_id,parent_type,parent_id,depth,source_version)
   VALUES ('registry_registry',$1,'project',$2,3,now())`, id, tc.edgeProject)
			require.NoError(t, err, "schema accepts raw edge before first binding")
			var n int
			require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.object_project_binding WHERE object_type='registry_registry' AND object_id=$1`, id).Scan(&n))
			require.Zero(t, n)
			require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='registry_registry' AND object_id=$1`, id).Scan(&n))
			require.Zero(t, n, "raw edge must still be uncommitted and invisible")
			commandTx, err := command.Begin(ctx)
			require.NoError(t, err)
			defer commandTx.Rollback(context.Background())
			done := make(chan error, 1)
			go func() {
				out, e := resource_mirror.UpsertTx(ctx, commandTx, resource_mirror.Row{ObjectType: "registry.registries", ObjectID: id,
					ParentProjectID: "review-project-P", ParentAccountID: "review-account-A", SourceVersion: time.Now().UTC(),
					ParentChain: []string{"project:review-project-P", "account:review-account-A"}})
				if e == nil && !out.Applied {
					e = assertionError("command did not apply")
				}
				if e == nil {
					e = commandTx.Commit(ctx)
				}
				done <- e
			}()
			// Support an implementation that serializes this schedule: if command is
			// blocked by raw's transaction, commit raw and let it continue. No sleeps
			// decide correctness: blocking is established by PostgreSQL's lock graph.
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			var commandErr error
			commandFirst, blocked := false, false
			for !commandFirst && !blocked {
				select {
				case commandErr = <-done:
					commandFirst = true
				case <-ticker.C:
					require.NoError(t, observer.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int32(raw.PgConn().PID()), int32(command.PgConn().PID())).Scan(&blocked))
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			rawErr := rawTx.Commit(ctx)
			if !commandFirst {
				select {
				case commandErr = <-done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			t.Logf("schedule command_committed_before_raw=%t command_blocked_by_raw=%t raw_err=%v command_err=%v", commandFirst, blocked, rawErr, commandErr)
			require.NoError(t, rawErr)
			require.NoError(t, commandErr)
			var mismatch int
			require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge e
   JOIN kaname.object_project_binding b ON b.object_type=e.object_type AND b.object_id=e.object_id
   WHERE e.object_type='registry_registry' AND e.object_id=$1 AND e.parent_type='project' AND e.parent_id<>b.project_id`, id).Scan(&mismatch))
			t.Logf("committed binding/edge mismatches=%d", mismatch)
			require.Zero(t, mismatch, "R9: declared-before-registration object must not retain project edge foreign to its first binding")
		})
	}
}

type assertionError string

func (e assertionError) Error() string { return string(e) }

func TestRegistrationRawUpdateVersusFirstBinding(t *testing.T) {
	for _, moving := range []bool{false, true} {
		for _, tc := range []struct{ name, edgeProject string }{
			{"legal_same_project_twin", "review-project-P"},
			{"foreign_project_edge", "review-project-Q"},
		} {
			t.Run(fmt.Sprintf("%s/moving=%t", tc.name, moving), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
				defer cancel()
				dsn := pgtest.NewEmptyDB(t)
				runner, err := migratorrun.New(migratorrun.Config{Service: "kaname", Dialect: "postgres", DSN: dsn, FS: migrations.FS, MigrationsDir: "."})
				require.NoError(t, err)
				require.NoError(t, runner.Up(ctx, ""))
				observer, err := pgx.Connect(ctx, dsn)
				require.NoError(t, err)
				defer observer.Close(context.Background())
				raw, err := pgx.Connect(ctx, dsn)
				require.NoError(t, err)
				defer raw.Close(context.Background())
				command, err := pgx.Connect(ctx, dsn)
				require.NoError(t, err)
				defer command.Close(context.Background())
				tag, err := observer.Exec(ctx, `UPDATE kaname.catalog_resource SET permanent_project=true WHERE dotted='registry.registries' AND live`)
				require.NoError(t, err)
				require.EqualValues(t, 1, tag.RowsAffected(), "declared BEFORE either operation: not an R8 transition")
				id := "update983-" + tc.name
				oldID := id
				if moving {
					oldID += "-old"
				}
				_, err = observer.Exec(ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version)
    VALUES ('registry_registry',$1,'project','review-project-P',3,now())`, oldID)
				require.NoError(t, err)
				_, err = observer.Exec(ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_project_id,parent_account_id,source_version)
    VALUES ('registry.registries',$1,'','',now()-interval '1 hour')`, id)
				require.NoError(t, err)
				rawTx, err := raw.Begin(ctx)
				require.NoError(t, err)
				defer rawTx.Rollback(context.Background())
				_, err = rawTx.Exec(ctx, `UPDATE kaname.resource_parent_edge SET object_id=$1,parent_id=$2
    WHERE object_type='registry_registry' AND object_id=$3 AND depth=3`, id, tc.edgeProject, oldID)
				require.NoError(t, err, "schema accepts raw edge before first binding")
				var n int
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.object_project_binding WHERE object_type='registry_registry' AND object_id=$1`, id).Scan(&n))
				require.Zero(t, n)
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='registry_registry' AND object_id=$1`, id).Scan(&n))
				if moving {
					require.Zero(t, n)
				} else {
					require.Equal(t, 1, n)
				}
				commandTx, err := command.Begin(ctx)
				require.NoError(t, err)
				defer commandTx.Rollback(context.Background())
				done := make(chan error, 1)
				go func() {
					out, e := resource_mirror.UpsertTx(ctx, commandTx, resource_mirror.Row{ObjectType: "registry.registries", ObjectID: id,
						ParentProjectID: "review-project-P", ParentAccountID: "review-account-A", SourceVersion: time.Now().UTC(),
						ParentChain: []string{"project:review-project-P", "account:review-account-A"}})
					if e == nil && !out.Applied {
						e = assertionError("command did not apply")
					}
					if e == nil {
						e = commandTx.Commit(ctx)
					}
					done <- e
				}()
				// Support an implementation that serializes this schedule: if command is
				// blocked by raw's transaction, commit raw and let it continue. No sleeps
				// decide correctness: blocking is established by PostgreSQL's lock graph.
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				var commandErr error
				commandFirst, blocked := false, false
				for !commandFirst && !blocked {
					select {
					case commandErr = <-done:
						commandFirst = true
					case <-ticker.C:
						require.NoError(t, observer.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int32(raw.PgConn().PID()), int32(command.PgConn().PID())).Scan(&blocked))
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				rawErr := rawTx.Commit(ctx)
				if !commandFirst {
					select {
					case commandErr = <-done:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
				}
				t.Logf("schedule command_committed_before_raw=%t command_blocked_by_raw=%t raw_err=%v command_err=%v", commandFirst, blocked, rawErr, commandErr)
				require.NoError(t, rawErr)
				require.NoError(t, commandErr)
				var mismatch int
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge e
   JOIN kaname.object_project_binding b ON b.object_type=e.object_type AND b.object_id=e.object_id
   WHERE e.object_type='registry_registry' AND e.object_id=$1 AND e.parent_type='project' AND e.parent_id<>b.project_id`, id).Scan(&mismatch))
				t.Logf("committed binding/edge mismatches=%d", mismatch)
				require.Zero(t, mismatch, "R9: declared-before-registration object must not retain project edge foreign to its first binding")
			})
		}
	}
}
