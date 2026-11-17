// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// UPDATE явного ID не проходит через DEFAULT. Его самостоятельный guard
// обязан требовать обе собственные исключительные блокировки даже у владельца
// и при физическом исключении других producers. Законные близнецы проверяют,
// что отказ не заменён безусловным запретом смены ID или неизменяющего UPDATE.
func TestSequenceExplicitIDUpdateRequiresBothKeysAndPreservesRollback(t *testing.T) {
	for _, relation := range []struct {
		table, column, sequence string
		namespace               int
	}{
		{"resource_journal", "sequence_no", "resource_journal_sequence_no_seq", 1262569304},
		{"fga_outbox", "id", "fga_outbox_id_seq", 1262569305},
	} {
		t.Run(relation.table, func(t *testing.T) {
			r := writerProtocolRig(t)
			const oldID int64 = 9223372036854775600
			ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
			// Тот же допустимый прямой INSERT, что у существующей sequence-пробы;
			// отдельная завершённая команда освобождает его ключ до UPDATE.
			var err error
			if relation.table == "resource_journal" {
				_, err = r.admin.Exec(ctx, `INSERT INTO kaname.resource_journal(sequence_no,resource_kind,resource_id,project_id,scope,event_type,payload)
 VALUES($1,'account',$2,'','[]'::jsonb,'UPDATED',jsonb_build_object('id',$2::text))`, oldID, r.a)
			} else {
				// v_* не материализуется canonical fold: фикстура не создаёт право.
				_, err = r.admin.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at)
 VALUES($1,'fga.tuple.write',jsonb_build_object('object','account:'||$2::text,'user','user:usr_sequence_update_probe','relation','v_get'),now())`, oldID, r.a)
			}
			cancel()
			require.NoError(t, err)
			table := pgx.Identifier{"kaname", relation.table}.Sanitize()
			column := pgx.Identifier{relation.column}.Sanitize()
			sequence := pgx.Identifier{"kaname", relation.sequence}.Sanitize()
			readState := func(t *testing.T) string {
				t.Helper()
				ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
				defer cancel()
				var state string
				require.NoError(t, r.admin.QueryRow(ctx, fmt.Sprintf(`SELECT jsonb_build_object(
 'row',(SELECT to_jsonb(x) FROM ONLY %s x WHERE %s=$1),
 'sequence',(SELECT jsonb_build_object('last_value',last_value,'is_called',is_called) FROM %s))::text`, table, column, sequence), oldID).Scan(&state))
				return state
			}
			before := readState(t)
			for _, login := range []struct {
				name string
				pool *pgxpool.Pool
			}{{"owner", r.admin}, {"unprivileged-runtime", r.runtime}} {
				t.Run(login.name, func(t *testing.T) {
					var updateAllowed bool
					aclCtx, stop := context.WithTimeout(r.ctx, 5*time.Second)
					err := login.pool.QueryRow(aclCtx, `SELECT has_table_privilege(current_user,$1,'UPDATE')`, "kaname."+relation.table).Scan(&updateAllowed)
					stop()
					require.NoError(t, err)
					require.True(t, updateAllowed, "GIVEN: отказ должен исходить от guard, не от отсутствия UPDATE ACL")
					for _, tc := range []struct {
						name                                                   string
						oldLock, newLock, shared, physical, unchanged, allowed bool
						delta                                                  int64
					}{
						{name: "no-keys", delta: 1},
						{name: "only-old-key", oldLock: true, delta: 1},
						{name: "only-new-key", newLock: true, delta: 1},
						{name: "shared-is-not-exclusive", oldLock: true, newLock: true, shared: true, delta: 1},
						{name: "physical-exclusion-does-not-bypass-update", physical: true, delta: 1},
						{name: "both-keys-increasing-id", oldLock: true, newLock: true, allowed: true, delta: 1},
						{name: "both-keys-decreasing-id", oldLock: true, newLock: true, allowed: true, delta: -1},
						{name: "unchanged-id-needs-no-keys", unchanged: true, allowed: true},
					} {
						t.Run(tc.name, func(t *testing.T) {
							ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
							defer cancel()
							target := oldID + tc.delta
							if tc.unchanged {
								target = oldID
							}
							if !tc.unchanged {
								var distinct bool
								require.NoError(t, r.admin.QueryRow(ctx, `SELECT hashtext($1::bigint::text)<>hashtext($2::bigint::text)`, oldID, target).Scan(&distinct))
								require.True(t, distinct, "GIVEN: разные ID не должны совпасть по advisory witness")
							}
							tx, err := login.pool.Begin(ctx)
							require.NoError(t, err)
							// Ограниченный cleanup зарегистрирован до любого следующего assert.
							t.Cleanup(func() {
								cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
								defer stop()
								if err := tx.Rollback(cleanup); !errors.Is(err, pgx.ErrTxClosed) {
									require.NoError(t, err)
								}
							})
							if tc.physical {
								_, err := tx.Exec(ctx, "LOCK TABLE "+table+" IN SHARE ROW EXCLUSIVE MODE")
								require.NoError(t, err)
								var held bool
								require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND relation=to_regclass($1) AND mode='ShareRowExclusiveLock' AND granted)`, "kaname."+relation.table).Scan(&held))
								require.True(t, held)
							}
							lockSQL := `SELECT pg_advisory_xact_lock($1,hashtext($2::bigint::text))`
							if tc.shared {
								lockSQL = `SELECT pg_advisory_xact_lock_shared($1,hashtext($2::bigint::text))`
							}
							for _, key := range []struct {
								held bool
								id   int64
							}{{tc.oldLock, oldID}, {tc.newLock, target}} {
								if key.held {
									_, err := tx.Exec(ctx, lockSQL, relation.namespace, key.id)
									require.NoError(t, err)
								}
							}
							var actual int64
							err = tx.QueryRow(ctx, fmt.Sprintf("UPDATE %s SET %s=$2 WHERE %s=$1 RETURNING %s", table, column, column, column), oldID, target).Scan(&actual)
							if tc.allowed {
								require.NoError(t, err)
								require.Equal(t, target, actual, "законная смена ID сохраняет точное значение и направление")
							} else {
								var pe *pgconn.PgError
								require.ErrorAs(t, err, &pe)
								require.Equal(t, "42501", pe.Code)
								require.Equal(t, "resource producer preheld key missing", pe.Message)
							}
							require.NoError(t, tx.Rollback(ctx))
							require.Equal(t, before, readState(t), "rollback сохраняет исходную строку и sequence state; UPDATE не вызывает DEFAULT/nextval")
							if !tc.unchanged {
								var targetExists bool
								require.NoError(t, r.admin.QueryRow(ctx, fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM ONLY %s WHERE %s=$1)", table, column), target).Scan(&targetExists))
								require.False(t, targetExists)
							}
						})
					}
				})
			}
		})
	}
}
