// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const accessDefinitionHoldSQL = `SELECT kaname.authority_access_label_definition_hold_v1($1::text,$2::text,$3::text,$4::text,$5::text,$6::uuid,$7::bigint,$8::text,$9::text,$10::text)`

type accessDefinitionWitness struct {
	scopeKind, scopeID, module, resource, key string
	id                                        string
	revision                                  int64
	xmin, ctid                                string
}

func (w accessDefinitionWitness) args(value any) []any {
	return []any{w.scopeKind, w.scopeID, w.module, w.resource, w.key, w.id, w.revision, w.xmin, w.ctid, value}
}

func seedAccessDefinition(t *testing.T, r protocolRig, kind, id, key string, values ...string) accessDefinitionWitness {
	t.Helper()
	w := accessDefinitionWitness{scopeKind: kind, scopeID: id, module: "iam", resource: "account", key: key}
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition(scope_kind,scope_id,module,resource,label_key) VALUES($1,$2,$3,$4,$5) RETURNING id::text`, kind, id, w.module, w.resource, key).Scan(&w.id))
	for _, value := range values {
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,$2)`, w.id, value)
		require.NoError(t, err)
	}
	return readAccessDefinition(t, r, w)
}

func readAccessDefinition(t *testing.T, r protocolRig, w accessDefinitionWitness) accessDefinitionWitness {
	t.Helper()
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT revision,xmin::text,ctid::text FROM kaname.authority_access_label_definition WHERE id=$1::uuid`, w.id).Scan(&w.revision, &w.xmin, &w.ctid))
	return w
}

func requireAccessDefinitionHold(t *testing.T, r protocolRig, w accessDefinitionWitness, value any, want bool) {
	t.Helper()
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	var held bool
	require.NoError(t, tx.QueryRow(r.ctx, accessDefinitionHoldSQL, w.args(value)...).Scan(&held))
	require.Equal(t, want, held)
	require.NoError(t, tx.Rollback(r.ctx))
}

func requireAccessDefinitionSQLState(t *testing.T, err error, state string) {
	t.Helper()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, state, pgErr.Code, pgErr.Message)
}

func TestAccessLabelDefinitionExactWitnessScopeAndEmptyValue(t *testing.T) {
	r := writerProtocolRig(t)
	project := kac127SeedProject(t, r.ctx, r.admin, r.a, "access-definition-scope")
	account := seedAccessDefinition(t, r, "account", r.a, "trust", "yes", "")
	other := seedAccessDefinition(t, r, "account", r.b, "trust", "other")
	projectDefinition := seedAccessDefinition(t, r, "project", project, "trust", "project")
	cluster := seedAccessDefinition(t, r, "cluster", "cluster_root", "trust", "cluster")
	requireAccessDefinitionHold(t, r, account, "yes", true)
	requireAccessDefinitionHold(t, r, account, "", true)
	requireAccessDefinitionHold(t, r, account, nil, true)
	requireAccessDefinitionHold(t, r, account, "missing", false)
	requireAccessDefinitionHold(t, r, other, "", false)
	requireAccessDefinitionHold(t, r, other, nil, true)
	requireAccessDefinitionHold(t, r, projectDefinition, "project", true)
	requireAccessDefinitionHold(t, r, cluster, "cluster", true)
	// ABA: UUID, координата и семантическая revision восстановлены, но это
	// другая физическая строка. Пустое определение не требует обхода membership FK.
	aba := seedAccessDefinition(t, r, "account", r.a, "aba")
	remove, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, remove)
	tag, err := remove.Exec(r.ctx, `DELETE FROM kaname.authority_access_label_definition WHERE id=$1::uuid`, aba.id)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, remove.Commit(r.ctx))
	restore, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, restore)
	_, err = restore.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_definition(id,scope_kind,scope_id,module,resource,label_key,revision) VALUES($1::uuid,$2,$3,$4,$5,$6,$7)`, aba.id, aba.scopeKind, aba.scopeID, aba.module, aba.resource, aba.key, aba.revision)
	require.NoError(t, err)
	require.NoError(t, restore.Commit(r.ctx))
	restored := readAccessDefinition(t, r, aba)
	require.Equal(t, aba.revision, restored.revision)
	require.NotEqual(t, aba.xmin, restored.xmin)
	requireAccessDefinitionHold(t, r, aba, nil, false)
	requireAccessDefinitionHold(t, r, restored, nil, true)
	for name, change := range map[string]func(*accessDefinitionWitness){
		"other-account": func(w *accessDefinitionWitness) { w.scopeID = r.b },
		"project-scope": func(w *accessDefinitionWitness) { w.scopeKind = "project"; w.scopeID = project },
		"cluster-scope": func(w *accessDefinitionWitness) { w.scopeKind = "cluster"; w.scopeID = "cluster_root" },
		"module":        func(w *accessDefinitionWitness) { w.module = "compute" },
		"resource":      func(w *accessDefinitionWitness) { w.resource = "project" },
		"key":           func(w *accessDefinitionWitness) { w.key = "other" },
		"id":            func(w *accessDefinitionWitness) { w.id = other.id },
		"revision":      func(w *accessDefinitionWitness) { w.revision++ },
		"xmin":          func(w *accessDefinitionWitness) { w.xmin = "0" },
		"ctid":          func(w *accessDefinitionWitness) { w.ctid = "(0,0)" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := account
			change(&candidate)
			requireAccessDefinitionHold(t, r, candidate, nil, false)
		})
	}
}

func TestAccessLabelDefinitionMembershipRevisionChangesOnlyWithMembership(t *testing.T) {
	r := writerProtocolRig(t)
	w := seedAccessDefinition(t, r, "account", r.a, "revision")
	require.EqualValues(t, 1, w.revision)
	exec := func(sql string, args ...any) int64 {
		t.Helper()
		tag, err := r.admin.Exec(r.ctx, sql, args...)
		require.NoError(t, err)
		return tag.RowsAffected()
	}
	require.EqualValues(t, 1, exec(`INSERT INTO kaname.authority_access_label_value VALUES($1::uuid,'')`, w.id))
	next := readAccessDefinition(t, r, w)
	require.Equal(t, w.revision+1, next.revision)
	requireAccessDefinitionHold(t, r, w, nil, false)
	requireAccessDefinitionHold(t, r, next, "", true)
	w = next
	require.Zero(t, exec(`INSERT INTO kaname.authority_access_label_value VALUES($1::uuid,'') ON CONFLICT DO NOTHING`, w.id))
	require.EqualValues(t, 1, exec(`UPDATE kaname.authority_access_label_value SET label_value=label_value,definition_id=definition_id WHERE definition_id=$1::uuid`, w.id))
	require.Zero(t, exec(`DELETE FROM kaname.authority_access_label_value WHERE definition_id=$1::uuid AND label_value='absent'`, w.id))
	require.Equal(t, w, readAccessDefinition(t, r, w), "неизменившееся membership не трогает даже physical witness определения")
	requireAccessDefinitionHold(t, r, w, "", true)
	require.EqualValues(t, 1, exec(`DELETE FROM kaname.authority_access_label_value WHERE definition_id=$1::uuid AND label_value=''`, w.id))
	next = readAccessDefinition(t, r, w)
	require.Equal(t, w.revision+1, next.revision)
	requireAccessDefinitionHold(t, r, w, nil, false)
	requireAccessDefinitionHold(t, r, next, "", false)
	requireAccessDefinitionHold(t, r, next, nil, true)
}

func TestAccessLabelDefinitionMutationGuardsAndRuntimeDenied(t *testing.T) {
	r := writerProtocolRig(t)
	w := seedAccessDefinition(t, r, "account", r.a, "guards", "yes")
	other := seedAccessDefinition(t, r, "account", r.b, "guards", "yes")
	for name, check := range map[string]struct {
		sql  string
		args []any
	}{
		"coordinate":         {`UPDATE kaname.authority_access_label_definition SET scope_id=$2 WHERE id=$1::uuid`, []any{w.id, r.b}},
		"key":                {`UPDATE kaname.authority_access_label_definition SET label_key='changed' WHERE id=$1::uuid`, []any{w.id}},
		"id":                 {`UPDATE kaname.authority_access_label_definition SET id='00000000-0000-0000-0000-000000000001'::uuid WHERE id=$1::uuid`, []any{w.id}},
		"revision-jump":      {`UPDATE kaname.authority_access_label_definition SET revision=revision+2 WHERE id=$1::uuid`, []any{w.id}},
		"revision-backwards": {`UPDATE kaname.authority_access_label_definition SET revision=revision-1 WHERE id=$1::uuid`, []any{w.id}},
		"insert-revision":    {`INSERT INTO kaname.authority_access_label_definition(scope_kind,scope_id,module,resource,label_key,revision) VALUES('account',$1,'iam','account','wrong-initial',2)`, []any{r.a}},
		"membership-value":   {`UPDATE kaname.authority_access_label_value SET label_value='different' WHERE definition_id=$1::uuid`, []any{w.id}},
		"membership-owner":   {`UPDATE kaname.authority_access_label_value SET definition_id=$2::uuid WHERE definition_id=$1::uuid`, []any{w.id, other.id}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, check.sql, check.args...)
			requireAccessDefinitionSQLState(t, err, "23514")
			require.Equal(t, w, readAccessDefinition(t, r, w))
		})
	}
	// Разрешены ровно прежняя запись либо следующий номер без смены координат.
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.authority_access_label_definition SET revision=revision WHERE id=$1::uuid`, w.id)
	require.NoError(t, err)
	require.Equal(t, w.revision, readAccessDefinition(t, r, w).revision)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_access_label_definition SET revision=revision+1 WHERE id=$1::uuid`, w.id)
	require.NoError(t, err)
	require.Equal(t, w.revision+1, readAccessDefinition(t, r, w).revision)
	for _, table := range []string{"authority_access_label_definition", "authority_access_label_value"} {
		// Таблицы берутся из закрытого списка; CASCADE позволяет дойти до guard обеих таблиц.
		_, err = r.admin.Exec(r.ctx, fmt.Sprintf(`TRUNCATE TABLE kaname.%s CASCADE`, table))
		requireAccessDefinitionSQLState(t, err, "42501")
		_, err = r.runtime.Exec(r.ctx, fmt.Sprintf(`SELECT * FROM kaname.%s`, table))
		requireAccessDefinitionSQLState(t, err, "42501")
	}
	var held bool
	err = r.runtime.QueryRow(r.ctx, accessDefinitionHoldSQL, w.args(nil)...).Scan(&held)
	requireAccessDefinitionSQLState(t, err, "42501")
	var invoker bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT prosecdef FROM pg_proc WHERE oid='kaname.authority_access_label_definition_hold_v1(text,text,text,text,text,uuid,bigint,text,text,text)'::regprocedure`).Scan(&invoker))
	require.True(t, invoker, "owner hold не должен стать SECURITY DEFINER entry для runtime")
	// Старый RR snapshot нельзя выдать за повторную текущую проверку.
	rr, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	lifecycleRollback(t, rr)
	err = rr.QueryRow(r.ctx, accessDefinitionHoldSQL, w.args(nil)...).Scan(&held)
	requireAccessDefinitionSQLState(t, err, "25001")
	require.NoError(t, rr.Rollback(r.ctx))
}

func TestAccessLabelDefinitionHoldBlocksValueMutationUntilRelease(t *testing.T) {
	r := writerProtocolRig(t)
	for _, mutation := range []string{"insert", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			w := seedAccessDefinition(t, r, "account", r.a, "hold-"+mutation, "yes")
			holder, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			lifecycleRollback(t, holder)
			var held bool
			require.NoError(t, holder.QueryRow(r.ctx, accessDefinitionHoldSQL, w.args("yes")...).Scan(&held))
			require.True(t, held)
			// Две настоящие транзакции: timeout относится к lock, а не задержке клиента.
			competitor, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			lifecycleRollback(t, competitor)
			_, err = competitor.Exec(r.ctx, `SET LOCAL lock_timeout='250ms'`)
			require.NoError(t, err)
			sql := `INSERT INTO kaname.authority_access_label_value VALUES($1::uuid,'next')`
			if mutation == "delete" {
				sql = `DELETE FROM kaname.authority_access_label_value WHERE definition_id=$1::uuid AND label_value='yes'`
			}
			_, err = competitor.Exec(r.ctx, sql, w.id)
			requireAccessDefinitionSQLState(t, err, "55P03")
			require.NoError(t, competitor.Rollback(r.ctx))
			require.Equal(t, w, readAccessDefinition(t, r, w))
			require.NoError(t, holder.Commit(r.ctx))
			_, err = r.admin.Exec(r.ctx, sql, w.id)
			require.NoError(t, err)
			next := readAccessDefinition(t, r, w)
			require.Equal(t, w.revision+1, next.revision)
			requireAccessDefinitionHold(t, r, w, nil, false)
			requireAccessDefinitionHold(t, r, next, nil, true)
		})
	}
}

func TestAccessLabelDefinitionHoldRechecksWitnessAfterMembershipWait(t *testing.T) {
	r := writerProtocolRig(t)
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprintf("commit=%t", commit), func(t *testing.T) {
			w := seedAccessDefinition(t, r, "account", r.a, fmt.Sprintf("waiting-%t", commit), "yes")
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			defer cancel()
			changer, err := r.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			lifecycleRollback(t, changer)
			_, err = changer.Exec(ctx, `DELETE FROM kaname.authority_access_label_value WHERE definition_id=$1::uuid AND label_value='yes'`, w.id)
			require.NoError(t, err)
			waiter, err := r.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			type result struct {
				held bool
				err  error
			}
			done := make(chan result, 1)
			joined := false
			// На любом отказе сначала отменяем worker, затем ждём завершения и только
			// после этого используем его connection для rollback.
			defer func() {
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				_ = changer.Rollback(cleanup)
				if !joined {
					select {
					case <-done:
						joined = true
					case <-cleanup.Done():
						t.Error("hold worker did not stop after cancellation")
					}
				}
				if joined {
					_ = waiter.Rollback(cleanup)
				}
			}()
			waiterPID := waiter.Conn().PgConn().PID()
			changerPID := changer.Conn().PgConn().PID()
			go func() {
				var held bool
				err := waiter.QueryRow(ctx, accessDefinitionHoldSQL, w.args("yes")...).Scan(&held)
				done <- result{held, err}
			}()
			require.Eventually(t, func() bool {
				var blocked bool
				err := r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))`, waiterPID, changerPID).Scan(&blocked)
				return err == nil && blocked
			}, 3*time.Second, 10*time.Millisecond, "hold обязан ждать именно незавершённое изменение membership")
			if commit {
				require.NoError(t, changer.Commit(ctx))
			} else {
				require.NoError(t, changer.Rollback(ctx))
			}
			var outcome result
			select {
			case outcome = <-done:
				joined = true
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.NoError(t, outcome.err)
			require.Equal(t, !commit, outcome.held, "после commit прежний witness устарел; rollback сохраняет разрешённый факт")
			require.NoError(t, waiter.Rollback(ctx))
			current := readAccessDefinition(t, r, w)
			if commit {
				require.Equal(t, w.revision+1, current.revision)
			} else {
				require.Equal(t, w, current)
			}
		})
	}
}
