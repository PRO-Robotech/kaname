// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/migratorrun"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func registrationRRDB(t *testing.T) (context.Context, *pgx.Conn, *pgx.Conn, *pgx.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	dsn := pgtest.NewEmptyDB(t)
	runner, err := migratorrun.New(migratorrun.Config{Service: "kaname", Dialect: "postgres", DSN: dsn, FS: migrations.FS, MigrationsDir: "."})
	require.NoError(t, err)
	require.NoError(t, runner.Up(ctx, ""))
	conns := make([]*pgx.Conn, 3)
	for i := range conns {
		conns[i], err = pgx.Connect(ctx, dsn)
		require.NoError(t, err)
		c := conns[i]
		t.Cleanup(func() { c.Close(context.Background()) })
		_, err = c.Exec(ctx, "SET deadlock_timeout='200ms'")
		require.NoError(t, err)
	}
	_, err = conns[0].Exec(ctx, `UPDATE kaname.catalog_resource SET permanent_project=true WHERE dotted='registry.registries' AND live`)
	require.NoError(t, err)
	return ctx, conns[0], conns[1], conns[2]
}
func registrationRRState(err error) string {
	if err == nil {
		return "00000"
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		return p.Code
	}
	return err.Error()
}
func registrationRRWait(t *testing.T, ctx context.Context, observer *pgx.Conn, holder, waiter uint32) {
	t.Helper()
	require.Eventually(t, func() bool {
		var b bool
		err := observer.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, int32(holder), int32(waiter)).Scan(&b)
		return err == nil && b
	}, 10*time.Second, 10*time.Millisecond, "concrete PostgreSQL blocking graph required")
}

const registrationRRCommand = `INSERT INTO kaname.resource_registration_command(dotted_type,object_id,parent_project_id,parent_account_id,labels,source_version,parent_chain) VALUES ('registry.registries',$1,'registrationRR-P','registrationRR-A','{}',now(),ARRAY['project:registrationRR-P','account:registrationRR-A'])`
const registrationRREdge = `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version) VALUES ('registry_registry',$1,'project',$2,3,now())`

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// A stale RR snapshot aborts honestly with 40001. A fresh retry distinguishes
// lawful equality from a visible integrity violation; neither error is renamed.
func TestRegistrationRepeatableRead_EdgeAfterBinding(t *testing.T) {
	for _, wait := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			isolation pgx.TxIsoLevel
			project   string
		}{
			{"RR_foreign", pgx.RepeatableRead, "registrationRR-Q"}, {"RR_lawful", pgx.RepeatableRead, "registrationRR-P"}, {"RC_foreign", pgx.ReadCommitted, "registrationRR-Q"},
		} {
			t.Run(fmt.Sprintf("%s_wait=%t", tc.name, wait), func(t *testing.T) {
				ctx, observer, raw, command := registrationRRDB(t)
				id := "rr-edge-after-binding"
				rawTx, err := raw.BeginTx(ctx, pgx.TxOptions{IsoLevel: tc.isolation})
				require.NoError(t, err)
				defer rawTx.Rollback(context.Background())
				var n int
				if wait {
					err = rawTx.QueryRow(ctx, `SELECT count(*) FROM kaname.catalog_resource`).Scan(&n)
				} else {
					err = rawTx.QueryRow(ctx, `SELECT count(*) FROM kaname.object_project_binding WHERE object_id=$1`, id).Scan(&n)
					require.Zero(t, n)
				}
				require.NoError(t, err)
				cmdTx, err := command.Begin(ctx)
				require.NoError(t, err)
				defer cmdTx.Rollback(context.Background())
				_, err = cmdTx.Exec(ctx, registrationRRCommand, id)
				require.NoError(t, err)
				if !wait {
					require.NoError(t, cmdTx.Commit(ctx))
				}
				done := make(chan error, 1)
				go func() { _, e := rawTx.Exec(ctx, registrationRREdge, id, tc.project); done <- e }()
				if wait {
					registrationRRWait(t, ctx, observer, command.PgConn().PID(), raw.PgConn().PID())
					require.NoError(t, cmdTx.Commit(ctx))
				}
				var rawErr error
				select {
				case rawErr = <-done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if tc.isolation == pgx.RepeatableRead {
					require.Equal(t, "40001", registrationRRState(rawErr))
				} else {
					require.Equal(t, "23", registrationRRState(rawErr)[:2])
				}
				require.ErrorIs(t, rawTx.Commit(ctx), pgx.ErrTxCommitRollback)
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id=$1 AND depth=3`, id).Scan(&n))
				require.Zero(t, n, "failed transaction leaves no raw edge")
				retry, err := raw.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
				require.NoError(t, err)
				defer retry.Rollback(context.Background())
				_, err = retry.Exec(ctx, registrationRREdge, id, tc.project)
				if tc.project == "registrationRR-P" {
					require.NoError(t, err)
					require.NoError(t, retry.Commit(ctx))
				} else {
					require.Equal(t, "23", registrationRRState(err)[:2])
					require.ErrorIs(t, retry.Commit(ctx), pgx.ErrTxCommitRollback)
				}
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge e JOIN kaname.object_project_binding b USING(object_type,object_id) WHERE e.object_id=$1 AND e.parent_type='project' AND e.parent_id<>b.project_id`, id).Scan(&n))
				require.Zero(t, n)
				t.Logf("RR edge-after-binding: isolation=%s wait=%t first=%s fresh retry=%s mismatch=%d", tc.isolation, wait, registrationRRState(rawErr), registrationRRState(err), n)
			})
		}
	}
}

func TestRegistrationRepeatableRead_FirstBindingAfterEdge(t *testing.T) {
	for _, command := range []bool{false, true} {
		for _, project := range []string{"registrationRR-P", "registrationRR-Q"} {
			t.Run(fmt.Sprintf("command=%t_edge=%s", command, project), func(t *testing.T) {
				ctx, observer, first, edge := registrationRRDB(t)
				id := "rr-binding-after-edge"
				tx, err := first.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
				require.NoError(t, err)
				defer tx.Rollback(context.Background())
				var n int
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.catalog_resource`).Scan(&n))
				_, err = edge.Exec(ctx, registrationRREdge, id, project)
				require.NoError(t, err)
				sql := `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_project_id,parent_account_id,labels,source_version) VALUES ('registry.registries',$1,'registrationRR-P','registrationRR-A','{}',now())`
				if command {
					sql = registrationRRCommand
				}
				_, err = tx.Exec(ctx, sql, id)
				require.Equal(t, "40001", registrationRRState(err))
				require.ErrorIs(t, tx.Commit(ctx), pgx.ErrTxCommitRollback)
				require.NoError(t, observer.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.object_project_binding WHERE object_id=$1)+(SELECT count(*) FROM kaname.resource_mirror WHERE object_id=$1)`, id).Scan(&n))
				require.Zero(t, n, "failed first binding leaves no mirror or binding")
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id=$1 AND depth=3 AND parent_id=$2`, id, project).Scan(&n))
				require.Equal(t, 1, n, "committed prior edge survives the aborted writer")
				retry, err := first.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
				require.NoError(t, err)
				defer retry.Rollback(context.Background())
				_, err = retry.Exec(ctx, sql, id)
				// Full command replaces the complete unbound chain; raw mirror must respect
				// the existing chain. No old edge is silently lost by a stale RR snapshot.
				if command || project == "registrationRR-P" {
					require.NoError(t, err)
					require.NoError(t, retry.Commit(ctx))
				} else {
					require.Equal(t, "23", registrationRRState(err)[:2])
					require.ErrorIs(t, retry.Commit(ctx), pgx.ErrTxCommitRollback)
				}
				require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge e JOIN kaname.object_project_binding b USING(object_type,object_id) WHERE e.object_id=$1 AND e.parent_type='project' AND e.parent_id<>b.project_id`, id).Scan(&n))
				require.Zero(t, n)
				if command {
					require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id=$1 AND depth=3`, id).Scan(&n))
					require.Zero(t, n, "fresh complete command replaces the old chain")
				}
				t.Logf("RR binding-after-edge: command=%t edge=%s stale=40001 fresh retry=%s mismatch=0", command, project, registrationRRState(err))
			})
		}
	}
}

func TestRegistrationRepeatableRead_CatalogGateHasNoSemanticEffects(t *testing.T) {
	ctx, observer, raw, _ := registrationRRDB(t)
	var before, after string
	const snapshot = `SELECT jsonb_build_object('catalog',(SELECT to_jsonb(cr) FROM kaname.catalog_resource cr WHERE dotted='registry.registries'),'audit',(SELECT count(*) FROM kaname.audit_outbox),'reconcile',(SELECT count(*) FROM kaname.resource_reconcile_outbox))::text`
	require.NoError(t, observer.QueryRow(ctx, snapshot).Scan(&before))
	_, err := raw.Exec(ctx, registrationRREdge, "rr-catalog-only", "registrationRR-P")
	require.NoError(t, err)
	_, err = raw.Exec(ctx, registrationRRCommand, "rr-catalog-only")
	require.NoError(t, err)
	require.NoError(t, observer.QueryRow(ctx, snapshot).Scan(&after))
	require.JSONEq(t, before, after, "catalog columns and audit/reconcile counts are unchanged")
	rows, err := observer.Query(ctx, `SELECT t.tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t WHERE t.tgrelid='kaname.catalog_resource'::regclass AND NOT t.tgisinternal ORDER BY t.tgname`)
	require.NoError(t, err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name, definition string
		require.NoError(t, rows.Scan(&name, &definition))
		names = append(names, name)
		t.Logf("catalog callback %s", definition)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"catalog_resource_binds_registered_objects_on_declare", "catalog_resource_binds_registered_objects_on_insert", "catalog_resource_holds_project_bindings", "registration_catalog_fence_forget_all", "registration_catalog_fence_forget_identity", "registration_catalog_fence_forget_row", "resource_registration_locks_writers"}, names, "new callbacks require gate re-review")
}

func TestRegistrationRepeatableRead_MovedRawEdgeUpdate(t *testing.T) {
	for _, project := range []string{"registrationRR-P", "registrationRR-Q"} {
		t.Run(project, func(t *testing.T) {
			ctx, observer, raw, command := registrationRRDB(t)
			_, err := observer.Exec(ctx, registrationRREdge, "rr-old-key", "registrationRR-P")
			require.NoError(t, err)
			tx, err := raw.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			var n int
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id='rr-old-key'`).Scan(&n))
			require.Equal(t, 1, n)
			_, err = command.Exec(ctx, registrationRRCommand, "rr-new-key")
			require.NoError(t, err)
			const move = `UPDATE kaname.resource_parent_edge SET object_id='rr-new-key',parent_id=$1 WHERE object_id='rr-old-key'`
			_, err = tx.Exec(ctx, move, project)
			require.Equal(t, "40001", registrationRRState(err))
			require.ErrorIs(t, tx.Commit(ctx), pgx.ErrTxCommitRollback)
			require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id='rr-old-key'`).Scan(&n))
			require.Equal(t, 1, n, "rollback retains the original edge")
			retry, err := raw.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			require.NoError(t, err)
			defer retry.Rollback(context.Background())
			_, err = retry.Exec(ctx, move, project)
			if project == "registrationRR-P" {
				require.NoError(t, err)
				require.NoError(t, retry.Commit(ctx))
			} else {
				require.Equal(t, "23", registrationRRState(err)[:2])
				require.ErrorIs(t, retry.Commit(ctx), pgx.ErrTxCommitRollback)
			}
			require.NoError(t, observer.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_parent_edge e JOIN kaname.object_project_binding b USING(object_type,object_id) WHERE e.object_id='rr-new-key' AND e.parent_type='project' AND e.parent_id<>b.project_id`).Scan(&n))
			require.Zero(t, n)
		})
	}
}
