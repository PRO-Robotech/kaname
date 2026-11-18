// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func nativeDeleteReceiptClaim(t *testing.T, r protocolRig, tx pgx.Tx) (string, int64, string) {
	t.Helper()
	var nonce, payload string
	var id int64
	var unbound bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_native_delete_prepare_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a).Scan(&nonce))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT id,payload::text,created_at IS NULL FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce).Scan(&id, &payload, &unbound))
	require.True(t, unbound, "claim не вправе назначать окончательные часы")
	return nonce, id, payload
}

// Снятие сохраняет различие отсутствующего source_version и JSON null. Два
// вызова в одной TX имеют независимые nonce и проходят постоянный COMMIT guard.
func TestNativeDeleteReceiptExactPayloadAndCommit(t *testing.T) {
	r := writerProtocolRig(t)
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		t.Run(string(isolation), func(t *testing.T) {
			tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: isolation})
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			var before, after int
			var lower, upper time.Time
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*),clock_timestamp() FROM kaname.fga_outbox`).Scan(&before, &lower))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[]::jsonb[])`)
			require.NoError(t, err)
			for _, suffix := range []string{"", `||'{"source_version":null}'::jsonb`} {
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[(`+forwardReceiptPayload+`)`+suffix+`])`, r.a)
				require.NoError(t, err)
			}
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*),clock_timestamp() FROM kaname.fga_outbox`).Scan(&after, &upper))
			require.Equal(t, before+2, after)
			var exact int
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND (payload=(`+forwardReceiptPayload+`) OR payload=(`+forwardReceiptPayload+`)||'{"source_version":null}'::jsonb) AND created_at>=$2 AND created_at<=$3`, r.a, lower, upper).Scan(&exact))
			require.Equal(t, 2, exact)
			var missingVersion, nullVersion int
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FILTER(WHERE NOT(payload ? 'source_version')),count(*) FILTER(WHERE payload ? 'source_version' AND payload->'source_version'='null'::jsonb) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND (payload=(`+forwardReceiptPayload+`) OR payload=(`+forwardReceiptPayload+`)||'{"source_version":null}'::jsonb) AND created_at>=$2 AND created_at<=$3`, r.a, lower, upper).Scan(&missingVersion, &nullVersion))
			require.Equal(t, 1, missingVersion, "отсутствующий source_version сохраняется отдельно")
			require.Equal(t, 1, nullVersion, "явный JSON null сохраняется отдельно")
			require.NoError(t, tx.Commit(r.ctx))
			var anchors int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_forward_emit_anchor_v4`).Scan(&anchors))
			require.Zero(t, anchors)
		})
	}
}

func TestNativeDeleteReceiptRejectsVersionBeforeReservation(t *testing.T) {
	r := writerProtocolRig(t)
	for _, version := range []string{"0", "1", `"owner"`, "{}", "false"} {
		t.Run(version, func(t *testing.T) {
			var before, after string
			const sequence = `SELECT jsonb_build_array(last_value,log_cnt,is_called)::text FROM kaname.fga_outbox_id_seq`
			require.NoError(t, r.admin.QueryRow(r.ctx, sequence).Scan(&before))
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[`+forwardReceiptPayload+`,(`+forwardReceiptPayload+`)||jsonb_build_object('source_version',$2::jsonb)])`, r.a, version)
			forwardReceiptDenied(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
			require.NoError(t, r.admin.QueryRow(r.ctx, sequence).Scan(&after))
			require.Equal(t, before, after, "весь массив отвергается до первого nextval")
		})
	}
}

func TestNativeDeleteReceiptStampRefusesWrongScopeAndReplay(t *testing.T) {
	r := writerProtocolRig(t)
	forwardReceiptFaultDoor(t, r)
	for _, fault := range []string{"unclaimed", "write-program", "wrong-payload", "wrong-nonce", "rebind", "receipt-delete", "receipt-key", "receipt-backend", "receipt-xid", "receipt-invoker", "receipt-table", "receipt-preconsumed", "effect-delete", "effect-digest", "effect-row"} {
		t.Run(fault, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			var nonce, payload string
			var id int64
			if fault == "write-program" {
				nonce, id, payload, _ = forwardReceiptPrepared(t, r, tx)
			} else if fault == "unclaimed" {
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_native_delete_prepare_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a).Scan(&nonce))
				id, payload = 1, `{}`
			} else {
				nonce, id, payload = nativeDeleteReceiptClaim(t, r, tx)
			}
			switch fault {
			case "wrong-payload":
				payload = strings.ReplaceAll(payload, "v_get", "v_list")
			case "wrong-nonce":
				nonce = "00000000-0000-0000-0000-000000000001"
			case "rebind":
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
				require.NoError(t, err)
			default:
				if strings.HasPrefix(fault, "receipt-") || strings.HasPrefix(fault, "effect-") {
					_, err = tx.Exec(r.ctx, `SELECT kaname.test_forward_receipt_fault_v4($1,$2::uuid)`, fault, nonce)
					require.NoError(t, err)
				}
			}
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
			forwardReceiptDenied(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
}

// Откат targetlist stamp вместе с INSERT восстанавливает пустую метку и receipt;
// вложенная команда другого nonce не подменяет родительскую программу.
func TestNativeDeleteReceiptStampSavepointAndNestedCommand(t *testing.T) {
	r := writerProtocolRig(t)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nonce, id, payload := nativeDeleteReceiptClaim(t, r, tx)
	const insert = `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) SELECT $2,'fga.tuple.delete',$3::jsonb,kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`
	_, err = tx.Exec(r.ctx, `SAVEPOINT before_delete_stamp`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, insert, nonce, id, payload)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT before_delete_stamp`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, insert, nonce, id, payload)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
}

// TestNativeDeleteRowValidationWorkGrowsOncePerTriggerEntry проверяет настоящий
// native caller: каждый BEFORE/AFTER row frame сохраняет свежую проверку,
// не повторяя private program/custody внутри того же frame. Счётчики снимаются
// до отложенных COMMIT-проверок; каждая команда откатывается к исходному состоянию.
func TestNativeDeleteRowValidationWorkGrowsOncePerTriggerEntry(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `GRANT SET ON PARAMETER track_functions TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	_, err = tx.Exec(r.ctx, `SET LOCAL track_functions='all'`)
	require.NoError(t, err)
	read := func() [3]int64 {
		var counts [3]int64
		for i, name := range []string{"_authority_forward_row_v4(bigint,jsonb,boolean)", "_authority_forward_program_v4(uuid)", "_authority_forward_custody_v4()"} {
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT coalesce((SELECT calls FROM pg_stat_xact_user_functions WHERE funcid=('kaname.'||$1)::regprocedure),0)`, name).Scan(&counts[i]))
		}
		return counts
	}
	var costs [2][3]int64
	for n := 1; n <= 2; n++ {
		_, err = tx.Exec(r.ctx, `SAVEPOINT row_validation_work`)
		require.NoError(t, err)
		var baseline int
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&baseline))
		before := read()
		_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY(
 SELECT jsonb_build_object('object','account:'||$1::text,'user','user:usr_row_work_'||i::text,'relation','v_get')
 FROM generate_series(1,$2::integer) i ORDER BY i))`, r.a, n)
		require.NoError(t, err)
		after := read()
		for i := range after {
			costs[n-1][i] = after[i] - before[i]
			require.Positive(t, costs[n-1][i], "должны наблюдаться счётчики завершённых вызовов функций")
		}
		var actual int
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&actual))
		require.Equal(t, baseline+n, actual, "каждый исходный payload сохраняется как отдельный эффект журнала")
		_, err = tx.Exec(r.ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
		require.NoError(t, err, "настоящий native caller завершает receipts и программу")
		_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT row_validation_work`)
		require.NoError(t, err)
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&actual))
		require.Equal(t, baseline, actual)
	}
	require.Equal(t, int64(2), costs[1][0]-costs[0][0], "дополнительный эффект проходит свежие BEFORE и AFTER row entry")
	require.Equal(t, int64(1), costs[1][1]-costs[0][1], "самостоятельная проверка программы остаётся в каждом stamp без повторения внутри row entry")
	require.Equal(t, int64(3), costs[1][2]-costs[0][2], "свежая custody проверяется для stamp и обоих row entry")
	require.NoError(t, tx.Rollback(r.ctx))
}
