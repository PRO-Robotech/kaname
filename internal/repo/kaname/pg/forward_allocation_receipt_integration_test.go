// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Это настоящий unsigned LOGIN, а не подмена current_user владельцем. Payload
// v_get сохраняет исходный fold: событие существует, ложное право не возникает.
const forwardReceiptPayload = `jsonb_build_object('object','account:'||$1::text,'user','user:usr_forward_receipt','relation','v_get')`

func forwardReceiptDenied(t *testing.T, err error) {
	t.Helper()
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code, pe.Message)
}

func forwardReceiptPrepared(t *testing.T, r protocolRig, tx pgx.Tx) (string, int64, string, time.Time) {
	t.Helper()
	var nonce, payload string
	var id int64
	var stamp time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_forward_prepare_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a).Scan(&nonce))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT id,payload::text,created_at FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce).Scan(&id, &payload, &stamp))
	return nonce, id, payload, stamp
}

func forwardReceiptInsert(r protocolRig, tx pgx.Tx, id int64, payload string, at time.Time) error {
	_, err := tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) VALUES($1,'fga.tuple.write',$2::jsonb,$3)`, id, payload, at)
	return err
}

func TestForwardAllocationReceiptExactRowsAndCompletion(t *testing.T) {
	r := writerProtocolRig(t)
	for _, isolation := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		t.Run(string(isolation), func(t *testing.T) {
			tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: isolation})
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			var before int
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&before))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[]::jsonb[])`)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`,`+forwardReceiptPayload+`])`, r.a)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
			require.NoError(t, err)
			var count int
			var exact bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*),bool_and(event_type='fga.tuple.write' AND payload=`+forwardReceiptPayload+` AND created_at=transaction_timestamp()) FROM kaname.fga_outbox WHERE payload->>'user'='user:usr_forward_receipt'`, r.a).Scan(&count, &exact))
			require.Equal(t, 3, count)
			require.True(t, exact)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx), "deferred anchor проверяет завершение после actual statement triggers")
	var anchors int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_forward_emit_anchor_v4`).Scan(&anchors))
	require.Zero(t, anchors)
}

func TestForwardAllocationReceiptCannotCommitUnappliedOrReplay(t *testing.T) {
	for _, stage := range []string{"prepared", "claimed", "inserted-without-finish", "claim-replay", "insert-replay", "wrong-payload", "wrong-stamp", "foreign-nonce"} {
		t.Run(stage, func(t *testing.T) {
			r := writerProtocolRig(t)
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			if stage == "prepared" {
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_prepare_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
				require.NoError(t, err)
				forwardReceiptDenied(t, tx.Commit(r.ctx))
				return
			}
			nonce, id, payload, at := forwardReceiptPrepared(t, r, tx)
			switch stage {
			case "claimed":
				err = tx.Commit(r.ctx)
			case "claim-replay":
				_, err = tx.Exec(r.ctx, `SELECT * FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce)
			case "foreign-nonce":
				_, err = tx.Exec(r.ctx, `SELECT * FROM kaname.authority_forward_claim_v4('00000000-0000-0000-0000-000000000001')`)
			case "wrong-payload":
				err = forwardReceiptInsert(r, tx, id, strings.ReplaceAll(payload, "v_get", "v_list"), at)
			case "wrong-stamp":
				err = forwardReceiptInsert(r, tx, id, payload, at.Add(time.Microsecond))
			default:
				require.NoError(t, forwardReceiptInsert(r, tx, id, payload, at))
				if stage == "insert-replay" {
					err = forwardReceiptInsert(r, tx, id, payload, at)
				} else {
					err = tx.Commit(r.ctx)
				}
			}
			forwardReceiptDenied(t, err)
		})
	}
}

// Fault injector существует только в тесте. В продукте обычный LOGIN не имеет
// ни одного из этих UPDATE/DELETE/DROP прав. Каждая мутация — конечный case.
func forwardReceiptFaultDoor(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_forward_receipt_fault_v4(p_fault text,p_nonce uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$
BEGIN
 CASE p_fault
 WHEN 'receipt-delete' THEN DELETE FROM pg_temp.kaname_forward_receipts_v4 WHERE nonce=p_nonce;
 WHEN 'receipt-key' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET key_hash=key_hash # 1 WHERE nonce=p_nonce;
 WHEN 'receipt-shared' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET lock_mode='ShareLock' WHERE nonce=p_nonce;
 WHEN 'receipt-backend' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET backend=backend+1 WHERE nonce=p_nonce;
 WHEN 'receipt-xid' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET transaction_id='1'::xid8 WHERE nonce=p_nonce;
 WHEN 'receipt-invoker' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET invoker_oid=0 WHERE nonce=p_nonce;
 WHEN 'receipt-table' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET table_oid='kaname.resource_journal'::regclass WHERE nonce=p_nonce;
 WHEN 'receipt-nonce' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET nonce=gen_random_uuid() WHERE nonce=p_nonce;
 WHEN 'receipt-preconsumed' THEN UPDATE pg_temp.kaname_forward_receipts_v4 SET consumed=true WHERE nonce=p_nonce;
 WHEN 'effect-delete' THEN DELETE FROM pg_temp.kaname_forward_effects_v4 WHERE nonce=p_nonce;
 WHEN 'effect-digest' THEN UPDATE pg_temp.kaname_forward_effects_v4 SET row_digest=sha256('wrong'::bytea) WHERE nonce=p_nonce;
 WHEN 'effect-row' THEN UPDATE pg_temp.kaname_forward_effects_v4 SET row_value=jsonb_set(row_value,'{payload,relation}','"v_list"') WHERE nonce=p_nonce;
 WHEN 'program-count' THEN UPDATE pg_temp.kaname_forward_program_v4 SET effect_count=effect_count+1 WHERE nonce=p_nonce;
 WHEN 'program-delete' THEN DELETE FROM pg_temp.kaname_forward_program_v4 WHERE nonce=p_nonce;
 WHEN 'anchor-delete' THEN DELETE FROM kaname.authority_forward_emit_anchor_v4 WHERE nonce=p_nonce;
 WHEN 'temp-drop' THEN DROP TABLE pg_temp.kaname_forward_receipts_v4,pg_temp.kaname_forward_effects_v4,pg_temp.kaname_forward_program_v4;
 ELSE RAISE EXCEPTION 'unknown test fault';
 END CASE;
END $fault$;
REVOKE ALL ON FUNCTION kaname.test_forward_receipt_fault_v4(text,uuid) FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_forward_receipt_fault_v4(text,uuid) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_forward_receipt_fault_v4(text,uuid)`)
		require.NoError(t, e)
	})
}

func TestForwardAllocationReceiptTamperCannotCommit(t *testing.T) {
	r := writerProtocolRig(t)
	forwardReceiptFaultDoor(t, r)
	for _, fault := range []string{"receipt-delete", "receipt-key", "receipt-shared", "receipt-backend", "receipt-xid", "receipt-invoker", "receipt-table", "receipt-nonce", "receipt-preconsumed", "effect-delete", "effect-digest", "effect-row", "program-count", "program-delete", "anchor-delete", "temp-drop"} {
		t.Run(fault, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			nonce, id, payload, at := forwardReceiptPrepared(t, r, tx)
			_, err = tx.Exec(r.ctx, `SELECT kaname.test_forward_receipt_fault_v4($1,$2::uuid)`, fault, nonce)
			require.NoError(t, err)
			err = forwardReceiptInsert(r, tx, id, payload, at)
			if err == nil {
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
			}
			if err == nil {
				err = tx.Commit(r.ctx)
			}
			forwardReceiptDenied(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
			var count int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE id=$1`, id).Scan(&count))
			require.Zero(t, count)
		})
	}
	for _, fault := range []string{"anchor-delete", "temp-drop"} {
		t.Run("commit-without-finish/"+fault, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			nonce, _, _, _ := forwardReceiptPrepared(t, r, tx)
			_, err = tx.Exec(r.ctx, `SELECT kaname.test_forward_receipt_fault_v4($1,$2::uuid)`, fault, nonce)
			require.NoError(t, err)
			// Здесь нет следующего INSERT/finish, способного случайно поймать
			// fault вместо постоянного deferred completion anchor.
			forwardReceiptDenied(t, tx.Commit(r.ctx))
		})
	}
}

func TestForwardAllocationReceiptSavepointsAndNestedCommands(t *testing.T) {
	r := writerProtocolRig(t)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nonce, id, payload, at := forwardReceiptPrepared(t, r, tx)
	_, err = tx.Exec(r.ctx, `SAVEPOINT before_actual_insert`)
	require.NoError(t, err)
	require.NoError(t, forwardReceiptInsert(r, tx, id, payload, at))
	_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT before_actual_insert`)
	require.NoError(t, err)
	// Родительская receipt и lock пережили rollback дочернего actual INSERT.
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
	require.NoError(t, err)
	require.NoError(t, forwardReceiptInsert(r, tx, id, payload, at))
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SAVEPOINT before_reservation`)
	require.NoError(t, err)
	child, childID, _, _ := forwardReceiptPrepared(t, r, tx)
	_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT before_reservation`)
	require.NoError(t, err)
	var held bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND classid=1262569305::oid AND objid=hashtext($1::bigint::text)::oid AND objsubid=2 AND granted)`, childID).Scan(&held))
	require.False(t, held, "новый key и его receipt откатились вместе")
	_, err = tx.Exec(r.ctx, `SAVEPOINT invalid_child_replay`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT * FROM kaname.authority_forward_claim_v4($1::uuid)`, child)
	forwardReceiptDenied(t, err)
	_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT invalid_child_replay`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
}

func TestForwardAllocationReceiptOriginalPrivilegesAndSignedBoundary(t *testing.T) {
	for _, scenario := range []string{"sequence-privilege", "table-privilege", "foreign-temp", "signed", "strict-unsigned"} {
		t.Run(scenario, func(t *testing.T) {
			r := writerProtocolRig(t)
			if scenario == "sequence-privilege" {
				_, err := r.admin.Exec(r.ctx, `REVOKE USAGE,UPDATE ON SEQUENCE kaname.fga_outbox_id_seq FROM `+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
			}
			if scenario == "table-privilege" {
				_, err := r.admin.Exec(r.ctx, `REVOKE INSERT ON kaname.fga_outbox FROM `+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
			}
			if scenario == "strict-unsigned" || scenario == "signed" {
				r.strict(t)
			}
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			if scenario == "signed" {
				r.enter(t, tx, r.intent(r.a), "decision")
			}
			if scenario == "foreign-temp" || scenario == "sequence-privilege" {
				_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_forward_program_v4(junk integer)`)
				require.NoError(t, err)
			}
			var before, after string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called)::text FROM kaname.fga_outbox_id_seq s`).Scan(&before))
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
			forwardReceiptDenied(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called)::text FROM kaname.fga_outbox_id_seq s`).Scan(&after))
			require.Equal(t, before, after, "отказ до nextval, включая precedence privilege+foreign temp")
		})
	}
}

func TestForwardAllocationReceiptRXBeforeKeyAndCrossBackend(t *testing.T) {
	r := writerProtocolRig(t)
	holder, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(holder)
	var next int64
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT last_value+CASE WHEN is_called THEN 1 ELSE 0 END FROM kaname.fga_outbox_id_seq`).Scan(&next))
	_, err = holder.Exec(r.ctx, `SELECT pg_advisory_xact_lock_shared(1262569305,hashtext($1::bigint::text))`, next)
	require.NoError(t, err)
	cfg := r.runtime.Config()
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	var pid int
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
		tx, e := pool.Begin(ctx)
		if e != nil {
			return e
		}
		defer tx.Rollback(context.WithoutCancel(ctx))
		_, e = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
		return e
	})
	require.Eventually(t, func() bool {
		var waiting bool
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569305::oid AND objid=hashtext($2::bigint::text)::oid AND NOT granted)`, pid, next).Scan(&waiting))
		return waiting
	}, 5*time.Second, 10*time.Millisecond)
	var rx bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='kaname.fga_outbox'::regclass AND mode='RowExclusiveLock' AND granted)`, pid).Scan(&rx))
	require.True(t, rx)
	require.NoError(t, holder.Rollback(ctx))
	require.NoError(t, lifecycleResult(t, ctx, done))
	first, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(first)
	nonce, _, _, _ := forwardReceiptPrepared(t, r, first)
	// Compatibility admission уже сериализует unsigned writers. Передаём
	// nonce другому backend после rollback исходного: не создаём ложный hang
	// на существующем global admission вместо проверки чужого receipt.
	require.NoError(t, first.Rollback(r.ctx))
	second, err := pool.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(second)
	_, err = second.Exec(r.ctx, `SELECT * FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce)
	forwardReceiptDenied(t, err)
}

var forwardReceiptSignatures = []string{
	"authority_forward_emit_v4(jsonb[])", "authority_forward_prepare_v4(jsonb[])",
	"authority_forward_claim_v4(uuid)", "authority_forward_finish_v4(uuid)",
	"_authority_forward_custody_v4()", "_authority_forward_shape_v4()",
	"_authority_forward_context_v4()", "_authority_forward_program_v4(uuid)",
	"_authority_forward_row_v4(bigint,jsonb,boolean)", "_authority_forward_complete_v4(uuid)",
	"_authority_forward_anchor_complete_v4()", "_authority_forward_storage_v4()",
}

func TestForwardAllocationReceiptReadinessAndPrivateACL(t *testing.T) {
	r := writerProtocolRig(t)
	checkReady := func(t *testing.T) {
		t.Helper()
		var ready bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
		require.True(t, ready, "положительный baseline/recovery замыкает actual transitive readiness")
	}
	checkReady(t)
	for _, signature := range forwardReceiptSignatures {
		t.Run(signature, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			var definition string
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_get_functiondef(to_regprocedure('kaname.'||$1))`, signature).Scan(&definition))
			_, err = tx.Exec(r.ctx, strings.Replace(definition, "AS $function$", "AS $function$\n-- TEST: изменён actual prosrc\n", 1))
			require.NoError(t, err)
			var ready bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
			checkReady(t)
			var allowed bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE')`, signature).Scan(&allowed))
			require.Equal(t, !strings.HasPrefix(signature, "_"), allowed)
		})
	}
	for _, mutation := range []string{
		`ALTER FUNCTION kaname.authority_forward_emit_v4(jsonb[]) SECURITY DEFINER`,
		`ALTER FUNCTION kaname.authority_forward_claim_v4(uuid) STRICT`,
		`ALTER FUNCTION kaname._authority_forward_row_v4(bigint,jsonb,boolean) PARALLEL SAFE`,
		`ALTER TABLE kaname.authority_forward_emit_anchor_v4 DISABLE TRIGGER authority_forward_anchor_complete_v4`,
		`GRANT SELECT ON kaname.authority_forward_emit_anchor_v4 TO PUBLIC`,
		`GRANT SELECT(nonce) ON kaname.authority_forward_emit_anchor_v4 TO PUBLIC`,
		`GRANT EXECUTE ON FUNCTION kaname._authority_forward_row_v4(bigint,jsonb,boolean) TO PUBLIC`,
	} {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, mutation)
		require.NoError(t, err)
		var ready bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
		require.False(t, ready, mutation)
		require.NoError(t, tx.Rollback(r.ctx))
		checkReady(t)
	}
	for _, mutation := range []string{
		`UPDATE pg_temp.kaname_forward_program_v4 SET phase='finished'`,
		`UPDATE pg_temp.kaname_forward_receipts_v4 SET guarded=true,consumed=true`,
		`DELETE FROM pg_temp.kaname_forward_effects_v4`,
		`DELETE FROM kaname.authority_forward_emit_anchor_v4`,
		`SELECT kaname._authority_forward_row_v4(1,'{}'::jsonb,false)`,
	} {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		_, _, _, _ = forwardReceiptPrepared(t, r, tx)
		_, err = tx.Exec(r.ctx, mutation)
		forwardReceiptDenied(t, err)
		require.NoError(t, tx.Rollback(r.ctx))
	}
}

func TestForwardAllocationReceiptGooseRoundTrip(t *testing.T) {
	r := writerProtocolRig(t)
	db, own, previous := sevenCRUDMigrationDB(t, r)
	const state = `SELECT jsonb_build_object('functions',(SELECT jsonb_agg(jsonb_build_object('name',proname,'definition',pg_get_functiondef(oid),'acl',proacl,'owner',proowner) ORDER BY proname) FROM pg_proc WHERE pronamespace='kaname'::regnamespace AND proname LIKE '%forward%v4'),'anchor',(SELECT jsonb_build_object('owner',relowner,'acl',relacl) FROM pg_class WHERE oid='kaname.authority_forward_emit_anchor_v4'::regclass))::text`
	var before, after string
	require.NoError(t, r.admin.QueryRow(r.ctx, state).Scan(&before))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."))
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var absent bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_regclass('kaname.authority_forward_emit_anchor_v4') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='kaname'::regnamespace AND proname LIKE '%forward%v4')`).Scan(&absent))
	require.True(t, absent)
	require.NoError(t, goose.UpTo(db, ".", own))
	require.NoError(t, r.admin.QueryRow(r.ctx, state).Scan(&after))
	require.Equal(t, before, after)
}
