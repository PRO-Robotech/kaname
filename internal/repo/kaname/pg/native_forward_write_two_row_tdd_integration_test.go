// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Ordinary LOGIN, два настоящих compute_instance, semantic assertions до RED work gate.
// Oracle выполняет по одному public native WRITE на input: rowwise даже после batching.
func TestNativeForwardWriteBatchPreservesRowwiseMetadataAndBoundsInsertWork(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	ids := []string{"native-write-two-01", "native-write-two-02"}
	users := []string{"user:usr_native_write_two_01", "user:usr_native_write_two_02"}
	payloads := make([]string, 2)
	weights := map[string]int64{}
	for i := range ids {
		_, err := r.admin.Exec(ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,labels) VALUES('compute.instance',$1,$2,'{}'::jsonb)`, ids[i], r.a)
		require.NoError(t, err)
		raw, err := json.Marshal(map[string]any{"object": "compute_instance:" + ids[i], "user": users[i], "relations": []string{"v_update", "editor", "v_get", "v_delete"}})
		require.NoError(t, err)
		payloads[i] = string(raw)
		var keys []string
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT ARRAY(SELECT DISTINCT k FROM unnest(kaname.authority_policy_keys('relation_fact',jsonb_build_object('object_type','compute_instance','object_id',$1::text,'relation','editor','subject',$2::text))) k)`, ids[i], users[i]).Scan(&keys))
		require.Contains(t, keys, "scope:"+r.a)
		require.Contains(t, keys, users[i])
		require.NotContains(t, keys, "*")
		require.LessOrEqual(t, len(keys), 4096)
		for _, key := range keys {
			weights[key]++
		}
	}
	// Counter attribution проверяет actual canonical attachments, не добавляя callbacks.
	var factPolicyTriggers, journalPolicyTriggers, rowGuardTriggers int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.relation_fact'::regclass AND tgfoid='kaname.authority_policy_changed()'::regprocedure AND tgtype IN(4,16) AND tgenabled='O' AND NOT tgisinternal),
 (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.fga_outbox'::regclass AND tgfoid='kaname.authority_policy_changed()'::regprocedure AND tgtype=4 AND tgenabled='O' AND NOT tgisinternal),
 (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid IN('kaname.relation_fact'::regclass,'kaname.fga_outbox'::regclass) AND tgfoid='kaname.authority_protocol_row_guard()'::regprocedure AND tgtype=31 AND tgenabled='O' AND NOT tgisinternal)`).Scan(&factPolicyTriggers, &journalPolicyTriggers, &rowGuardTriggers))
	require.Equal(t, 2, factPolicyTriggers)
	require.Equal(t, 1, journalPolicyTriggers)
	require.Equal(t, 2, rowGuardTriggers)
	require.Equal(t, int64(2), weights["scope:"+r.a])
	for _, user := range users {
		require.Equal(t, int64(1), weights[user])
	}
	// Конечный no-arg TEST reader: только read-only metadata projection, без grants
	// к private producer helpers и без observer triggers/canonical function changes.
	_, err := r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_native_batch_image_v4() RETURNS jsonb
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reader$
 DECLARE result jsonb;programs jsonb:='[]';effects jsonb:='[]';receipts jsonb:='[]';valid boolean:=false;
 BEGIN
 SELECT jsonb_build_object(
 'epochs',(SELECT coalesce(jsonb_object_agg(key,jsonb_build_object('revision',revision,'generation',generation)),'{}'::jsonb) FROM kaname.authority_policy_epoch),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb) FROM kaname.relation_fact f),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox f),
 'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),'[]'::jsonb) FROM kaname.authority_forward_emit_anchor_v4 a),
 'mirrors',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY object_type,object_id),'[]'::jsonb) FROM kaname.resource_mirror m)) INTO result;
 IF to_regclass('pg_temp.kaname_forward_program_v4') IS NOT NULL THEN
  SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY nonce),'[]'::jsonb) INTO programs FROM pg_temp.kaname_forward_program_v4 p;
  SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY nonce,ordinal),'[]'::jsonb) INTO effects FROM pg_temp.kaname_forward_effects_v4 e;
  SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY nonce,ordinal),'[]'::jsonb) INTO receipts FROM pg_temp.kaname_forward_receipts_v4 r;
  SELECT count(*)=2 AND bool_and(
   p.phase='finished' AND p.effect_count=2 AND a.finished AND a.effect_count=2
   AND p.backend=pg_backend_pid() AND p.transaction_id=pg_current_xact_id()
   AND p.invoker_oid=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user))
   AND a.invoker_oid=p.invoker_oid AND a.backend=p.backend AND a.transaction_id=p.transaction_id
   AND a.program_oid='pg_temp.kaname_forward_program_v4'::regclass AND a.effects_oid='pg_temp.kaname_forward_effects_v4'::regclass
   AND a.receipts_oid='pg_temp.kaname_forward_receipts_v4'::regclass
   AND p.effects_oid=a.effects_oid AND p.receipts_oid=a.receipts_oid
   AND r.backend=p.backend AND r.transaction_id=p.transaction_id AND r.invoker_oid=p.invoker_oid
   AND r.program_oid=a.program_oid AND r.effects_oid=a.effects_oid AND r.table_oid='kaname.fga_outbox'::regclass
   AND r.key_namespace=1262569305 AND r.key_hash=hashtext(j.id::text) AND r.objsubid=2 AND r.lock_mode='ExclusiveLock'
   AND r.claimed AND r.guarded AND r.consumed AND r.reserved_id=e.reserved_id
   AND e.ordinal BETWEEN 1 AND 2 AND e.row_value=to_jsonb(j)-'id'
   AND e.row_digest=sha256(convert_to((to_jsonb(j)-'id')::text,'UTF8'))
   AND EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid() AND l.locktype='advisory'
    AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    AND l.classid::bigint=r.key_namespace::bigint AND l.objid::bigint=(r.key_hash::bigint & 4294967295::bigint) AND l.objsubid=r.objsubid AND l.mode=r.lock_mode AND l.granted))
  INTO valid FROM pg_temp.kaname_forward_program_v4 p
  JOIN kaname.authority_forward_emit_anchor_v4 a ON a.nonce=p.nonce AND a.backend=p.backend AND a.transaction_id=p.transaction_id
  JOIN pg_temp.kaname_forward_effects_v4 e ON e.nonce=p.nonce
  JOIN pg_temp.kaname_forward_receipts_v4 r ON r.nonce=e.nonce AND r.ordinal=e.ordinal
  JOIN kaname.fga_outbox j ON j.id=e.reserved_id;
 END IF;
 RETURN result||jsonb_build_object('programs',programs,'effects',effects,'receipts',receipts,'receipt_valid',coalesce(valid,false));
 END $reader$;
 REVOKE ALL ON FUNCTION kaname.test_native_batch_image_v4() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, e := r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_native_batch_image_v4()`)
		require.NoError(t, e)
	})
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err = r.admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION kaname.test_native_batch_image_v4() TO `+quoted+`; GRANT SET ON PARAMETER track_functions TO `+quoted)
	require.NoError(t, err)
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	_, err = tx.Exec(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL idle_in_transaction_session_timeout='60s'; SET LOCAL track_functions='all'`)
	require.NoError(t, err)
	var login, session, tracking, stmt, idle, xid string
	require.NoError(t, tx.QueryRow(ctx, `SELECT current_user,session_user,current_setting('track_functions'),current_setting('statement_timeout'),current_setting('idle_in_transaction_session_timeout'),pg_current_xact_id()::text`).Scan(&login, &session, &tracking, &stmt, &idle, &xid))
	require.Equal(t, r.role, login)
	require.Equal(t, r.role, session)
	require.Equal(t, "all", tracking)
	require.Equal(t, "30s", stmt)
	require.Equal(t, "1min", idle)
	before, baseline := nativeBatchRead(t, ctx, tx)
	_, rootExists := before.Epochs["*"]
	require.True(t, rootExists)
	for _, user := range users {
		_, exists := before.Epochs[user]
		require.False(t, exists)
	}
	var absent int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='compute_instance' AND object_id=ANY($1::text[])`, ids).Scan(&absent))
	require.Zero(t, absent)
	counter := func(signature string) int64 {
		var count int64
		require.NoError(t, tx.QueryRow(ctx, `SELECT coalesce((SELECT calls FROM pg_stat_xact_user_functions WHERE funcid=$1::regprocedure),0)`, signature).Scan(&count))
		return count
	}
	// Сначала literal historical one-input commands, затем rollback той же TX/time.
	_, err = tx.Exec(ctx, `SAVEPOINT native_write_rowwise_oracle`)
	require.NoError(t, err)
	oracleStart := nativeBatchPolicyCalls(t, ctx, tx)
	for _, payload := range payloads {
		_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4(ARRAY[$1::jsonb])`, payload)
		require.NoError(t, err)
	}
	oracleCalls := nativeBatchPolicyCalls(t, ctx, tx) - oracleStart
	require.Equal(t, int64(6), oracleCalls, "два FGA INSERT callbacks + четыре fact INSERT/empty UPDATE callbacks")
	oracle, _ := nativeBatchRead(t, ctx, tx)
	expected := make(map[string]nativeBatchEpoch, len(before.Epochs)+len(weights))
	for key, epoch := range before.Epochs {
		expected[key] = epoch
	}
	for key, weight := range weights {
		epoch, exists := expected[key]
		if !exists {
			epoch.Generation = xid
		}
		epoch.Revision += weight
		expected[key] = epoch
	}
	require.Equal(t, expected, oracle.Epochs)
	require.Equal(t, before.Epochs["*"], oracle.Epochs["*"])
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_write_rowwise_oracle`)
	require.NoError(t, err)
	_, restored := nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored)
	_, err = tx.Exec(ctx, `SAVEPOINT native_write_actual`)
	require.NoError(t, err)
	nativeStart := nativeBatchPolicyCalls(t, ctx, tx)
	rowStart := counter("kaname.authority_protocol_row_guard()")
	shapeStart := counter("kaname._authority_forward_shape_v4()")
	_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4($1::jsonb[])`, payloads)
	require.NoError(t, err)
	nativeCalls := nativeBatchPolicyCalls(t, ctx, tx) - nativeStart
	rowCalls := counter("kaname.authority_protocol_row_guard()") - rowStart
	shapeCalls := counter("kaname._authority_forward_shape_v4()") - shapeStart
	require.Positive(t, nativeCalls)
	require.Equal(t, int64(4), rowCalls, "два actual FGA и два actual fact BEFORE ROW")
	require.Equal(t, int64(2), shapeCalls, "prepare+finish: существующий WRITE shape contract сохраняется")
	var statsPresent bool
	require.NoError(t, tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_xact_user_functions WHERE funcid='kaname.authority_policy_changed()'::regprocedure AND calls>0) AND EXISTS(SELECT 1 FROM pg_stat_xact_user_functions WHERE funcid='kaname.authority_protocol_row_guard()'::regprocedure AND calls>0)`).Scan(&statsPresent))
	require.True(t, statsPresent)
	native, nativeRaw := nativeBatchRead(t, ctx, tx)
	require.Equal(t, oracle.Epochs, native.Epochs)
	require.JSONEq(t, string(oracle.Facts), string(native.Facts))
	// Journal payload и timestamp сравниваются без sequence IDs, которые не откатываются.
	var oracleEvents, nativeEvents []map[string]any
	require.NoError(t, json.Unmarshal(oracle.Outbox, &oracleEvents))
	require.NoError(t, json.Unmarshal(native.Outbox, &nativeEvents))
	for _, e := range oracleEvents {
		delete(e, "id")
	}
	for _, e := range nativeEvents {
		delete(e, "id")
	}
	require.Equal(t, oracleEvents, nativeEvents)
	var facts, badFacts, events, badClocks, bagDifference int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE relation<>'editor' OR source_version<>transaction_timestamp() OR created_at<>transaction_timestamp() OR condition_name<>'' OR condition_params<>'{}'::jsonb) FROM kaname.relation_fact WHERE object_type='compute_instance' AND object_id=ANY($1::text[])`, ids).Scan(&facts, &badFacts))
	require.Equal(t, int64(2), facts)
	require.Zero(t, badFacts)
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE created_at<>transaction_timestamp()) FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'user'=ANY($1::text[])`, users).Scan(&events, &badClocks))
	require.Equal(t, int64(2), events)
	require.Zero(t, badClocks)
	require.NoError(t, tx.QueryRow(ctx, `WITH expected AS(SELECT unnest($1::jsonb[]) payload),actual AS(SELECT payload FROM kaname.fga_outbox WHERE event_type='fga.tuple.write' AND payload->>'user'=ANY($2::text[])) SELECT count(*) FROM((SELECT payload FROM expected EXCEPT ALL SELECT payload FROM actual) UNION ALL (SELECT payload FROM actual EXCEPT ALL SELECT payload FROM expected)) d`, payloads, users).Scan(&bagDifference))
	require.Zero(t, bagDifference)
	var metadata struct {
		Programs, Effects, Receipts, Anchors []json.RawMessage
		ReceiptValid                         bool `json:"receipt_valid"`
	}
	require.NoError(t, json.Unmarshal([]byte(nativeRaw), &metadata))
	require.Len(t, metadata.Programs, 1)
	require.Len(t, metadata.Effects, 2)
	require.Len(t, metadata.Receipts, 2)
	require.Len(t, metadata.Anchors, 1)
	require.True(t, metadata.ReceiptValid)
	// Read-only снимок не меняет immutable receipts/program; completion проверяет owner anchor.
	_, secondRaw := nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, nativeRaw, secondRaw)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err)
	_, completedRaw := nativeBatchRead(t, ctx, tx)
	var completed struct{ Programs, Effects, Receipts, Anchors []json.RawMessage }
	require.NoError(t, json.Unmarshal([]byte(completedRaw), &completed))
	require.Empty(t, completed.Anchors)
	require.Equal(t, metadata.Programs, completed.Programs)
	require.Equal(t, metadata.Effects, completed.Effects)
	require.Equal(t, metadata.Receipts, completed.Receipts)
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_write_actual`)
	require.NoError(t, err)
	_, restored = nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored)
	require.NoError(t, tx.Rollback(ctx))
	outer, err := r.admin.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(outer)
	_, outside := nativeBatchRead(t, ctx, outer)
	require.JSONEq(t, baseline, outside)
	require.NoError(t, outer.Rollback(ctx))
	t.Logf("NATIVE_WRITE_TWO_ROW_WORK historical_singleton_policy_calls=%d native_policy_calls=%d row_guard_calls=%d shape_calls=%d expected_current_policy_calls=5 desired_policy_calls=3", oracleCalls, nativeCalls, rowCalls, shapeCalls)
	// Единственный ожидаемый RED: один FGA INSERT + одна пара fact INSERT/UPDATE.
	require.Equal(t, int64(3), nativeCalls, fmt.Sprintf("native all-new WRITE должен иметь один physical fact UPSERT; historical two-row implementation gives5, actual=%d", nativeCalls))
}
