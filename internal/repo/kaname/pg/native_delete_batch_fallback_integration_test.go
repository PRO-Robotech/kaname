// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Reader создаётся каждым собственным fixture: наличие функции из другого TOP
// не предполагается. ACL private таблиц и canonical executable graph неизменны.
func nativeFallbackReader(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_native_fallback_image_v4() RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reader$
 SELECT jsonb_build_object(
 'epochs',(SELECT coalesce(jsonb_object_agg(key,jsonb_build_object('revision',revision,'generation',generation)),'{}'::jsonb) FROM kaname.authority_policy_epoch),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb) FROM kaname.relation_fact f),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox f),
 'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),'[]'::jsonb) FROM kaname.authority_forward_emit_anchor_v4 a))
 $reader$;
 REVOKE ALL ON FUNCTION kaname.test_native_fallback_image_v4() FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_native_fallback_image_v4() TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := r.admin.Exec(context.WithoutCancel(r.ctx), `DROP FUNCTION kaname.test_native_fallback_image_v4()`)
		require.NoError(t, cleanupErr)
	})
}

func nativeFallbackImage(t *testing.T, ctx context.Context, tx pgx.Tx) (map[string]nativeBatchEpoch, string) {
	t.Helper()
	var raw string
	require.NoError(t, tx.QueryRow(ctx, `SELECT kaname.test_native_fallback_image_v4()::text`).Scan(&raw))
	var image struct {
		Epochs map[string]nativeBatchEpoch `json:"epochs"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &image))
	return image.Epochs, raw
}

// Проверяются именно первоначальные права, а не искусственно урезанная роль.
// Новая optional дверь НЕ включена в этот независимый снимок исходного ABI.
func nativeFallbackOriginalPrivileges(t *testing.T, ctx context.Context, tx pgx.Tx) string {
	t.Helper()
	var raw string
	require.NoError(t, tx.QueryRow(ctx, `SELECT jsonb_build_object(
 'login',current_user,'session',session_user,
 'elevated',(SELECT rolsuper OR rolcreaterole OR rolbypassrls FROM pg_roles WHERE rolname=current_user),
 'outbox_insert',has_table_privilege(current_user,'kaname.fga_outbox','INSERT'),
 'outbox_select',has_table_privilege(current_user,'kaname.fga_outbox','SELECT'),
 'sequence',has_sequence_privilege(current_user,'kaname.fga_outbox_id_seq','USAGE') OR has_sequence_privilege(current_user,'kaname.fga_outbox_id_seq','UPDATE'),
 'fact_select',has_table_privilege(current_user,'kaname.relation_fact','SELECT'),
 'fact_insert',has_table_privilege(current_user,'kaname.relation_fact','INSERT'),
 'fact_update',has_table_privilege(current_user,'kaname.relation_fact','UPDATE'),
 'fact_delete',has_table_privilege(current_user,'kaname.relation_fact','DELETE'),
 'ledger_select',has_table_privilege(current_user,'kaname.access_binding_emitted_tuples','SELECT'),
 'bindings_select',has_table_privilege(current_user,'kaname.access_bindings','SELECT'),
 'pointer_select',has_table_privilege(current_user,'kaname.resource_registration_pointer','SELECT'),
 'retirement_select',has_table_privilege(current_user,'kaname.resource_registration_retirement','SELECT'),
 'fold',has_function_privilege(current_user,'kaname.relation_fact_fold_row(text,jsonb,timestamp with time zone)','EXECUTE'),
 'forward',has_function_privilege(current_user,'kaname.authority_forward_emit_v4(jsonb[])','EXECUTE'),
 'native_delete',has_function_privilege(current_user,'kaname.authority_native_delete_emit_v4(jsonb[])','EXECUTE'))::text`).Scan(&raw))
	var values map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &values))
	require.Equal(t, values["login"], values["session"])
	require.Equal(t, false, values["elevated"])
	for _, key := range []string{"outbox_insert", "outbox_select", "sequence", "fact_select", "fact_insert", "fact_update", "fact_delete", "ledger_select", "bindings_select", "pointer_select", "retirement_select", "fold", "forward", "native_delete"} {
		require.Equal(t, true, values[key], "исходная привилегия %s обязательна; actual original privileges: %s", key, raw)
	}
	return raw
}

func nativeFallbackLimits(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	_, err := tx.Exec(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL idle_in_transaction_session_timeout='60s'`)
	require.NoError(t, err)
}

// REVOKE только новой optional функции не должен запрещать старый generic SQL
// или actual native DELETE. Весь оператор возвращается прежнему fold; право
// EXECUTE не восстанавливается, SECURITY INVOKER не превращается в owner.
func TestNativeDeleteBatchOptionalGetterPrivilegePreservesWholeCommandFallback(t *testing.T) {
	r := writerProtocolRig(t)
	nativeFallbackReader(t, r)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nativeFallbackLimits(t, ctx, tx)
	originalPrivileges := nativeFallbackOriginalPrivileges(t, ctx, tx)
	require.NoError(t, tx.Rollback(ctx))
	var getterExists, initiallyAllowed bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT to_regprocedure('kaname.authority_native_delete_batch_read_v4()') IS NOT NULL,has_function_privilege($1,'kaname.authority_native_delete_batch_read_v4()','EXECUTE')`, r.role).Scan(&getterExists, &initiallyAllowed))
	require.True(t, getterExists)
	require.True(t, initiallyAllowed)
	_, err = r.admin.Exec(ctx, `REVOKE EXECUTE ON FUNCTION kaname.authority_native_delete_batch_read_v4() FROM `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	tx, err = r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nativeFallbackLimits(t, ctx, tx)
	require.JSONEq(t, originalPrivileges, nativeFallbackOriginalPrivileges(t, ctx, tx))
	var allowed bool
	require.NoError(t, tx.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.authority_native_delete_batch_read_v4()','EXECUTE')`).Scan(&allowed))
	require.False(t, allowed)
	before, baseline := nativeFallbackImage(t, ctx, tx)
	var xid string
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	const first = "user:usr_batch_fallback_first"
	const second = "user:usr_batch_fallback_second"
	const third = "user:usr_batch_fallback_third"
	_, firstExists := before[first]
	_, secondExists := before[second]
	_, thirdExists := before[third]
	require.False(t, firstExists)
	require.False(t, secondExists)
	require.False(t, thirdExists)
	shared := "scope:" + r.a
	_, err = tx.Exec(ctx, `SAVEPOINT native_fallback_command`)
	require.NoError(t, err)
	// Три прежних generic SQL payload, один actual INSERT без allocation API.
	_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
 SELECT 'fga.tuple.write',jsonb_build_object('object','account:'||$1::text,'user',s,'relation','editor'),transaction_timestamp()
 FROM unnest($2::text[]) s`, r.a, []string{first, second, third})
	require.NoError(t, err, "ordinary invoker generic WRITE не требует новой optional EXECUTE")
	written, _ := nativeFallbackImage(t, ctx, tx)
	require.Equal(t, nativeBatchEpoch{Revision: before[shared].Revision + 3, Generation: before[shared].Generation}, written[shared])
	for _, subject := range []string{first, second, third} {
		require.Equal(t, nativeBatchEpoch{Revision: 1, Generation: xid}, written[subject])
	}
	var facts int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=ANY($2::text[])`, r.a, []string{first, second, third}).Scan(&facts))
	require.Equal(t, 3, facts)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at) VALUES('fga.tuple.delete',jsonb_build_object('object','account:'||$1::text,'user',$2::text,'relation','editor'),clock_timestamp())`, r.a, first)
	require.NoError(t, err, "ordinary invoker generic DELETE сохраняется")
	require.NoError(t, fga_outbox.EmitNativeDeleteTx(ctx, tx, []clients.RelationTuple{{User: second, Relation: "editor", Object: "account:" + r.a}, {User: third, Relation: "editor", Object: "account:" + r.a}}), "actual public native DELETE выбирает whole-command fallback")
	after, _ := nativeFallbackImage(t, ctx, tx)
	require.Len(t, after, len(before)+3)
	for key, value := range before {
		if key != shared {
			require.Equal(t, value, after[key], "прежний epoch %s неизменен", key)
		}
	}
	require.Equal(t, nativeBatchEpoch{Revision: before[shared].Revision + 6, Generation: before[shared].Generation}, after[shared])
	for _, subject := range []string{first, second, third} {
		require.Equal(t, nativeBatchEpoch{Revision: 2, Generation: xid}, after[subject])
	}
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=ANY($2::text[])`, r.a, []string{first, second, third}).Scan(&facts))
	require.Zero(t, facts)
	var events, badPayloads int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE payload IS DISTINCT FROM jsonb_build_object('object','account:'||$1::text,'user',payload->>'user','relation','editor')) FROM kaname.fga_outbox WHERE payload->>'user'=ANY($2::text[])`, r.a, []string{first, second, third}).Scan(&events, &badPayloads))
	require.Equal(t, 6, events)
	require.Zero(t, badPayloads)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err, "независимые deferred receipts завершаются на прежней native двери")
	require.JSONEq(t, originalPrivileges, nativeFallbackOriginalPrivileges(t, ctx, tx))
	require.NoError(t, tx.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.authority_native_delete_batch_read_v4()','EXECUTE')`).Scan(&allowed))
	require.False(t, allowed, "fallback не повышает права")
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_fallback_command`)
	require.NoError(t, err)
	_, restored := nativeFallbackImage(t, ctx, tx)
	require.JSONEq(t, baseline, restored, "полный rollback epochs/facts/outbox/receipts")
	require.NoError(t, tx.Rollback(ctx))
}

// _shape измеряет actual полную проверку private receipts, не SQL-текст.
// Исходные prepare и synchronous finish/complete вызывают её по одному разу.
// Deferred COMMIT проверяется ПОСЛЕ измерения и не смешивается с этой границей.
func TestNativeForwardWriteAvoidsDeleteOnlyReceiptValidationWork(t *testing.T) {
	r := writerProtocolRig(t)
	nativeFallbackReader(t, r)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	_, err := r.admin.Exec(ctx, `GRANT SET ON PARAMETER track_functions TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nativeFallbackLimits(t, ctx, tx)
	_, err = tx.Exec(ctx, `SET LOCAL track_functions='all'`)
	require.NoError(t, err)
	before, baseline := nativeFallbackImage(t, ctx, tx)
	const subject = "user:usr_batch_forward_write_work"
	_, exists := before[subject]
	require.False(t, exists)
	var xid string
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	counter := func() int64 {
		var calls int64
		require.NoError(t, tx.QueryRow(ctx, `SELECT coalesce((SELECT calls FROM pg_stat_xact_user_functions WHERE funcid='kaname._authority_forward_shape_v4()'::regprocedure),0)`).Scan(&calls))
		return calls
	}
	_, err = tx.Exec(ctx, `SAVEPOINT native_forward_write_work`)
	require.NoError(t, err)
	start := counter()
	_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[jsonb_build_object('object','account:'||$1::text,'user',$2::text,'relation','editor')])`, r.a, subject)
	require.NoError(t, err)
	shapeCalls := counter() - start
	require.Positive(t, shapeCalls, "необходим actual tracked _shape, отсутствие stats не означает нулевую работу")
	after, _ := nativeFallbackImage(t, ctx, tx)
	shared := "scope:" + r.a
	require.Len(t, after, len(before)+1)
	for key, value := range before {
		if key != shared {
			require.Equal(t, value, after[key])
		}
	}
	require.Equal(t, nativeBatchEpoch{Revision: before[shared].Revision + 1, Generation: before[shared].Generation}, after[shared])
	require.Equal(t, nativeBatchEpoch{Revision: 1, Generation: xid}, after[subject])
	var facts, events int
	require.NoError(t, tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=$2),(SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload=jsonb_build_object('object','account:'||$1::text,'user',$2::text,'relation','editor') AND created_at=transaction_timestamp())`, r.a, subject).Scan(&facts, &events))
	require.Equal(t, 1, facts)
	require.Equal(t, 1, events)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err, "семантика и independent deferred completion должны сохраниться")
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_forward_write_work`)
	require.NoError(t, err)
	_, restored := nativeFallbackImage(t, ctx, tx)
	require.JSONEq(t, baseline, restored)
	require.NoError(t, tx.Rollback(ctx))
	// Ожидаемый RED r1 — лишняя проверка DELETE receipts в WRITE initializer.
	require.Equal(t, int64(2), shapeCalls, "WRITE сохраняет только исходные prepare+finish проверки; измерение до deferred completion")
}
