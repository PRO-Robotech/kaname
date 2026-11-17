// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Снимок читает private metadata через конечный TEST-only reader владельца.
// Доменная операция остаётся на исходном ordinary LOGIN: ACL таблиц, канон
// функций и граф triggers не меняются. Reader не принимает SQL и не пишет.
type nativeBatchEpoch struct {
	Revision   int64  `json:"revision"`
	Generation string `json:"generation"`
}

type nativeBatchImage struct {
	Epochs  map[string]nativeBatchEpoch `json:"epochs"`
	Facts   json.RawMessage             `json:"facts"`
	Outbox  json.RawMessage             `json:"outbox"`
	Anchors json.RawMessage             `json:"anchors"`
}

func nativeBatchRead(t *testing.T, ctx context.Context, tx pgx.Tx) (nativeBatchImage, string) {
	t.Helper()
	var raw string
	require.NoError(t, tx.QueryRow(ctx, `SELECT kaname.test_native_batch_image_v4()::text`).Scan(&raw))
	var image nativeBatchImage
	require.NoError(t, json.Unmarshal([]byte(raw), &image))
	return image, raw
}

// Ровно существующая trigger-функция, без дополнительного observer trigger.
// Наличие строки и track_functions обязательны; отсутствие данных не есть ноль.
func nativeBatchPolicyCalls(t *testing.T, ctx context.Context, tx pgx.Tx) int64 {
	t.Helper()
	var calls int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT coalesce((SELECT calls FROM pg_stat_xact_user_functions WHERE funcid='kaname.authority_policy_changed()'::regprocedure),0)`).Scan(&calls))
	return calls
}

// 4097 разных plain user/editor facts дают 4097 actor keys и один общий scope.
// Фикстура не создаёт тысячи ресурсов: исходный account — действительный owner.
// Исторический oracle удаляет каждую строку отдельным настоящим DELETE, затем
// savepoint возвращает ТОТ ЖЕ набор перед actual native emitter. Все сравнения
// metadata и rollback выполняются до единственного ожидаемого RED work gate.
func TestNativeDeleteBatchPreservesRowwisePolicyMetadataAndBoundsDeleteWork(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	const count = 4097
	const prefix = "user:usr_native_batch_work_"
	_, err := r.admin.Exec(ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 SELECT 'account',$1,'editor',$2||lpad(n::text,5,'0'),'-infinity'::timestamptz FROM generate_series(1,$3::integer) n`, r.a, prefix, count)
	require.NoError(t, err)
	var unionKeys, sharedOccurrences int
	var containsRoot bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(DISTINCT k),count(*) FILTER(WHERE k='scope:'||$1::text),bool_or(k='*')
 FROM kaname.relation_fact f CROSS JOIN LATERAL unnest(kaname.authority_policy_keys('relation_fact',to_jsonb(f))) keys(k)
 WHERE f.object_type='account' AND f.object_id=$1 AND f.relation='editor' AND left(f.subject,length($2))=$2`, r.a, prefix).Scan(&unionKeys, &sharedOccurrences, &containsRoot))
	require.Equal(t, count+1, unionKeys, "actual union policy keys превышает4096")
	require.Equal(t, count, sharedOccurrences, "один и тот же scope действительно принадлежит всем строкам")
	require.False(t, containsRoot)
	// Наблюдение не добавляет trigger: точный граф проверяется перед измерением.
	var deleteTriggers, outboxTriggers int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM pg_trigger WHERE tgrelid='kaname.relation_fact'::regclass AND tgfoid='kaname.authority_policy_changed()'::regprocedure AND tgtype=8 AND tgenabled='O' AND NOT tgisinternal),
 (SELECT count(*) FROM pg_trigger WHERE tgrelid='kaname.fga_outbox'::regclass AND tgfoid='kaname.authority_policy_changed()'::regprocedure AND tgtype=4 AND tgenabled='O' AND NOT tgisinternal)`).Scan(&deleteTriggers, &outboxTriggers))
	require.Equal(t, 1, deleteTriggers)
	require.Equal(t, 1, outboxTriggers)
	var triggerGraph string
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(jsonb_build_object(
 'table',c.relname,'name',t.tgname,'function',t.tgfoid::regprocedure::text,
 'type',t.tgtype,'enabled',t.tgenabled,'internal',t.tgisinternal,
 'constraint',t.tgconstraint<>0,'deferrable',t.tgdeferrable,'initially_deferred',t.tginitdeferred,
 'args',encode(t.tgargs,'hex'),'nargs',t.tgnargs,'columns',t.tgattr::text,
 'old_table',t.tgoldtable,'new_table',t.tgnewtable,'qual',pg_get_expr(t.tgqual,t.tgrelid))
 ORDER BY c.relname,t.tgname),'[]'::jsonb)::text FROM pg_trigger t
 JOIN pg_class c ON c.oid=t.tgrelid
 WHERE t.tgrelid IN ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)
 AND NOT t.tgisinternal`).Scan(&triggerGraph))
	t.Logf("NATIVE_BATCH_CANONICAL_TRIGGER_GRAPH %s", triggerGraph)
	_, err = r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_native_batch_image_v4() RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reader$
 SELECT jsonb_build_object(
 'epochs',(SELECT coalesce(jsonb_object_agg(key,jsonb_build_object('revision',revision,'generation',generation)),'{}'::jsonb) FROM kaname.authority_policy_epoch),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb) FROM kaname.relation_fact f),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox f),
 'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),'[]'::jsonb) FROM kaname.authority_forward_emit_anchor_v4 a))
 $reader$;
 REVOKE ALL ON FUNCTION kaname.test_native_batch_image_v4() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := r.admin.Exec(context.WithoutCancel(r.ctx), `DROP FUNCTION kaname.test_native_batch_image_v4()`)
		require.NoError(t, cleanupErr)
	})
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err = r.admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION kaname.test_native_batch_image_v4() TO `+quoted)
	require.NoError(t, err)
	// Право только на параметр телеметрии; ordinary LOGIN не становится owner.
	_, err = r.admin.Exec(ctx, `GRANT SET ON PARAMETER track_functions TO `+quoted)
	require.NoError(t, err)
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	_, err = tx.Exec(ctx, `SET LOCAL statement_timeout='30s'; SET LOCAL idle_in_transaction_session_timeout='60s'; SET LOCAL track_functions='all'`)
	require.NoError(t, err)
	var login, tracking string
	require.NoError(t, tx.QueryRow(ctx, `SELECT current_user,current_setting('track_functions')`).Scan(&login, &tracking))
	require.Equal(t, r.role, login)
	require.Equal(t, "all", tracking)
	before, baseline := nativeBatchRead(t, ctx, tx)
	root, rootPresent := before.Epochs["*"]
	require.True(t, rootPresent)
	sharedKey := "scope:" + r.a
	shared, sharedPresent := before.Epochs[sharedKey]
	require.True(t, sharedPresent)
	var xid string
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	tuples := make([]clients.RelationTuple, count)
	for i := range tuples {
		subject := fmt.Sprintf("%s%05d", prefix, i+1)
		tuples[i] = clients.RelationTuple{User: subject, Relation: "editor", Object: "account:" + r.a}
		_, exists := before.Epochs[subject]
		require.False(t, exists, "проверяется также создание отсутствовавшего actor key")
	}
	// Исторический rowwise oracle: каждый statement имеет собственный transition set.
	_, err = tx.Exec(ctx, `SAVEPOINT native_batch_oracle`)
	require.NoError(t, err)
	oracleStart := nativeBatchPolicyCalls(t, ctx, tx)
	batch := &pgx.Batch{}
	for _, tuple := range tuples {
		batch.Queue(`DELETE FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=$2`, r.a, tuple.User)
	}
	results := tx.SendBatch(ctx, batch)
	defer results.Close()
	for range tuples {
		tag, deleteErr := results.Exec()
		require.NoError(t, deleteErr)
		require.Equal(t, int64(1), tag.RowsAffected())
	}
	require.NoError(t, results.Close())
	oracleCalls := nativeBatchPolicyCalls(t, ctx, tx) - oracleStart
	require.Equal(t, int64(count), oracleCalls, "один actual policy callback на каждый historical DELETE")
	oracle, _ := nativeBatchRead(t, ctx, tx)
	require.Equal(t, root, oracle.Epochs["*"], "4098 union keys не разрешают менять root rowwise семантики")
	require.Equal(t, nativeBatchEpoch{Revision: shared.Revision + count, Generation: shared.Generation}, oracle.Epochs[sharedKey])
	require.Len(t, oracle.Epochs, len(before.Epochs)+count)
	for key, epoch := range before.Epochs {
		if key != sharedKey {
			require.Equal(t, epoch, oracle.Epochs[key], "не затрагивается прежний policy key %s", key)
		}
	}
	for _, tuple := range tuples {
		require.Equal(t, nativeBatchEpoch{Revision: 1, Generation: xid}, oracle.Epochs[tuple.User])
	}
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_batch_oracle`)
	require.NoError(t, err)
	_, restored := nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored, "полный historical rollback: facts/epochs/outbox/anchors")

	_, err = tx.Exec(ctx, `SAVEPOINT native_batch_actual`)
	require.NoError(t, err)
	var nativeBefore, nativeAfter time.Time
	require.NoError(t, tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&nativeBefore))
	nativeStart := nativeBatchPolicyCalls(t, ctx, tx)
	require.NoError(t, fga_outbox.EmitNativeDeleteTx(ctx, tx, tuples))
	nativeCalls := nativeBatchPolicyCalls(t, ctx, tx) - nativeStart
	require.NoError(t, tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&nativeAfter))
	require.Positive(t, nativeCalls, "tracked actual callback обязан присутствовать")
	native, _ := nativeBatchRead(t, ctx, tx)
	require.Equal(t, oracle.Epochs, native.Epochs, "точные revisions/generation/key presence, включая shared multiplicity и root")
	require.JSONEq(t, string(oracle.Facts), string(native.Facts))
	var eventCount, payloadMismatch, factsLeft int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE payload IS DISTINCT FROM jsonb_build_object('object','account:'||$1::text,'user',payload->>'user','relation','editor')) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND left(payload->>'user',length($2))=$2`, r.a, prefix).Scan(&eventCount, &payloadMismatch))
	require.Equal(t, int64(count), eventCount)
	require.Zero(t, payloadMismatch)
	var payloadBagDifference, clockMismatch int64
	require.NoError(t, tx.QueryRow(ctx, `WITH expected AS (
 SELECT jsonb_build_object('object','account:'||$1::text,'user',$2::text||lpad(n::text,5,'0'),'relation','editor') payload FROM generate_series(1,$3::integer) n),
 actual AS (SELECT payload FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND left(payload->>'user',length($2))=$2)
 SELECT count(*) FROM ((SELECT payload FROM expected EXCEPT ALL SELECT payload FROM actual) UNION ALL (SELECT payload FROM actual EXCEPT ALL SELECT payload FROM expected)) d`, r.a, prefix, count).Scan(&payloadBagDifference))
	require.Zero(t, payloadBagDifference, "полный multiset исходных payloads, без потери и дублей")
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND left(payload->>'user',length($1))=$1 AND (created_at<$2 OR created_at>$3)`, prefix, nativeBefore, nativeAfter).Scan(&clockMismatch))
	require.Zero(t, clockMismatch, "исходный native DELETE сохраняет момент вставки, не начало TX")
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND left(subject,length($2))=$2`, r.a, prefix).Scan(&factsLeft))
	require.Zero(t, factsLeft)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err, "independent deferred receipt completion сохраняется")
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_batch_actual`)
	require.NoError(t, err)
	_, restored = nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored, "полный actual native rollback; sequence gaps не являются строками")

	// Пустой вход не исполняет DELETE и не публикует событие.
	emptyStart := nativeBatchPolicyCalls(t, ctx, tx)
	require.NoError(t, fga_outbox.EmitNativeDeleteTx(ctx, tx, nil))
	require.Equal(t, emptyStart, nativeBatchPolicyCalls(t, ctx, tx))
	_, restored = nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored)
	// Непустой исходный native payload без факта публикует outbox, но не DELETE.
	_, err = tx.Exec(ctx, `SAVEPOINT native_batch_absent`)
	require.NoError(t, err)
	absentStart := nativeBatchPolicyCalls(t, ctx, tx)
	require.NoError(t, fga_outbox.EmitNativeDeleteTx(ctx, tx, []clients.RelationTuple{{User: prefix + "absent", Relation: "editor", Object: "account:" + r.a}}))
	require.Equal(t, int64(1), nativeBatchPolicyCalls(t, ctx, tx)-absentStart, "единственный callback — actual fga_outbox INSERT; fact DELETE отсутствует")
	absent, _ := nativeBatchRead(t, ctx, tx)
	require.Equal(t, before.Epochs, absent.Epochs)
	require.JSONEq(t, string(before.Facts), string(absent.Facts))
	var absentEvents int64
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload=jsonb_build_object('user',$1::text,'object','account:'||$2::text,'relation','editor')`, prefix+"absent", r.a).Scan(&absentEvents))
	require.Equal(t, int64(1), absentEvents)
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_batch_absent`)
	require.NoError(t, err)
	_, restored = nativeBatchRead(t, ctx, tx)
	require.JSONEq(t, baseline, restored)
	require.NoError(t, tx.Rollback(ctx))
	// На этом интервале emitter меняет только fga_outbox и relation_fact.
	// Канонический AFTER INSERT policy callback outbox даёт ровно единицу;
	// остальные вызовы — реальные relation_fact DELETE statements, не строки SQL.
	// Это единственный ожидаемый RED исходной rowwise реализации.
	require.Equal(t, int64(1), nativeCalls-1, "batch native DELETE должен быть одним physical fact statement; historical=%d actual=%d", oracleCalls, nativeCalls-1)
}
