// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Каждый TOP создаёт свой конечный reader. Он не зависит от reader другого
// теста и даёт LOGIN только EXECUTE, не доступ к private anchor/epoch таблицам.
func nativeDeleteBoundaryFixture(t *testing.T, r protocolRig, ctx context.Context) []clients.RelationTuple {
	t.Helper()
	tuples := []clients.RelationTuple{
		{User: "user:usr_native_boundary_one", Relation: "editor", Object: "account:" + r.a},
		{User: "user:usr_native_boundary_two", Relation: "editor", Object: "account:" + r.a},
	}
	_, err := r.admin.Exec(ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 VALUES ('account',$1,'editor',$2,'-infinity'),('account',$1,'editor',$3,'-infinity')`, r.a, tuples[0].User, tuples[1].User)
	require.NoError(t, err)
	var facts, held, roots int
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE
 EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples et JOIN kaname.access_bindings ab ON ab.id=et.binding_id
 WHERE et.object='account:'||$1::text AND et.relation=f.relation AND et.fga_user=f.subject AND ab.status='ACTIVE')
 OR EXISTS(SELECT 1 FROM kaname.resource_registration_pointer rp WHERE rp.object_type=f.object_type
 AND rp.object_id=f.object_id AND rp.relation=f.relation AND rp.subject=f.subject AND rp.active)),
 count(*) FILTER(WHERE '*'=ANY(kaname.authority_policy_keys('relation_fact',to_jsonb(f))))
 FROM kaname.relation_fact f WHERE f.object_type='account' AND f.object_id=$1 AND f.relation='editor' AND f.subject=ANY($2::text[])`, r.a, []string{tuples[0].User, tuples[1].User}).Scan(&facts, &held, &roots))
	require.Equal(t, 2, facts)
	require.Zero(t, held, "оба actual факта доступны исходному unversioned DELETE")
	require.Zero(t, roots, "фикстура не уходит в root-producing fallback")
	_, err = r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_native_delete_boundary_image_v4() RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reader$
 SELECT jsonb_build_object(
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb) FROM kaname.relation_fact f),
 'epochs',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY key),'[]'::jsonb) FROM kaname.authority_policy_epoch e),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox o),
 'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY to_jsonb(a)::text),'[]'::jsonb) FROM kaname.authority_forward_emit_anchor_v4 a),
 'graph',(SELECT coalesce(jsonb_agg(pg_get_triggerdef(t.oid,false) ORDER BY t.tgrelid,t.tgname),'[]'::jsonb)
 FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN ('kaname.fga_outbox'::regclass,'kaname.relation_fact'::regclass)))
 $reader$;
 REVOKE ALL ON FUNCTION kaname.test_native_delete_boundary_image_v4() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, cleanupErr := r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_native_delete_boundary_image_v4()`)
		require.NoError(t, cleanupErr)
	})
	_, err = r.admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION kaname.test_native_delete_boundary_image_v4() TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	return tuples
}

func nativeDeleteBoundaryImage(t *testing.T, ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) string {
	t.Helper()
	var image string
	require.NoError(t, q.QueryRow(ctx, `SELECT kaname.test_native_delete_boundary_image_v4()::text`).Scan(&image))
	return image
}

// Ошибка должна прийти именно из public native команды; после возврата к
// savepoint и после полного rollback сохраняются все business/private строки.
func nativeDeleteBoundaryReject(t *testing.T, r protocolRig, ctx context.Context, tuples []clients.RelationTuple, message string) {
	t.Helper()
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	_, err = tx.Exec(ctx, `SET LOCAL statement_timeout='10s'; SET LOCAL idle_in_transaction_session_timeout='20s'`)
	require.NoError(t, err)
	before := nativeDeleteBoundaryImage(t, ctx, tx)
	_, err = tx.Exec(ctx, `SAVEPOINT native_boundary`)
	require.NoError(t, err)
	err = fga_outbox.EmitNativeDeleteTx(ctx, tx, tuples)
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	require.Contains(t, denied.Message, message)
	require.Contains(t, denied.Where, "authority_native_delete_emit_v4", "отказ обязан относиться к actual public native вызову")
	_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT native_boundary`)
	require.NoError(t, err)
	require.JSONEq(t, before, nativeDeleteBoundaryImage(t, ctx, tx), "нет частичных facts/epochs/outbox/anchor effects")
	require.NoError(t, tx.Rollback(ctx))
	require.JSONEq(t, before, nativeDeleteBoundaryImage(t, ctx, r.runtime), "полный caller rollback также сохраняет baseline")
}

func nativeDeleteBoundaryHealthyTwin(t *testing.T, r protocolRig, ctx context.Context, tuples []clients.RelationTuple) {
	t.Helper()
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	before := nativeDeleteBoundaryImage(t, ctx, tx)
	require.NoError(t, fga_outbox.EmitNativeDeleteTx(ctx, tx, tuples))
	var facts, events int
	require.NoError(t, tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=ANY($2::text[])),
 (SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'='account:'||$1::text AND payload->>'user'=ANY($2::text[]))`, r.a, []string{tuples[0].User, tuples[1].User}).Scan(&facts, &events))
	require.Zero(t, facts)
	require.Equal(t, 2, events)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err, "native receipt/batch completion обязан завершиться")
	require.NoError(t, tx.Rollback(ctx))
	require.JSONEq(t, before, nativeDeleteBoundaryImage(t, ctx, r.runtime))
}

func TestNativeDeleteBatchRequiresInvokerFactDeletePrivilege(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	tuples := nativeDeleteBoundaryFixture(t, r, ctx)
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err := r.admin.Exec(ctx, `REVOKE DELETE ON kaname.relation_fact FROM `+quoted)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, restoreErr := r.admin.Exec(cleanup, `GRANT DELETE ON kaname.relation_fact TO `+quoted)
		require.NoError(t, restoreErr)
	})
	var canDelete, canSelect, canUpdate, canInsert, canSequence, nativeHelpers bool
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT
 has_table_privilege(current_user,'kaname.relation_fact','DELETE'),
 has_table_privilege(current_user,'kaname.relation_fact','SELECT'),
 has_table_privilege(current_user,'kaname.relation_fact','UPDATE'),
 has_table_privilege(current_user,'kaname.fga_outbox','INSERT'),
 has_sequence_privilege(current_user,'kaname.fga_outbox_id_seq','USAGE,UPDATE'),
 has_function_privilege(current_user,'kaname.authority_native_delete_emit_v4(jsonb[])','EXECUTE')
 AND has_function_privilege(current_user,'kaname.authority_native_delete_prepare_v4(jsonb[])','EXECUTE')
 AND has_function_privilege(current_user,'kaname.authority_native_delete_stamp_v4(uuid,bigint,jsonb)','EXECUTE')`).Scan(&canDelete, &canSelect, &canUpdate, &canInsert, &canSequence, &nativeHelpers))
	require.False(t, canDelete)
	require.True(t, canSelect)
	require.True(t, canUpdate)
	require.True(t, canInsert)
	require.True(t, canSequence)
	require.True(t, nativeHelpers)
	// Сам SELECT FOR UPDATE действительно доступен тому же LOGIN без DELETE.
	probe, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(probe)
	var locked string
	require.NoError(t, probe.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='editor' AND subject=$2 FOR UPDATE`, r.a, tuples[0].User).Scan(&locked))
	require.Equal(t, tuples[0].User, locked)
	require.NoError(t, probe.Rollback(ctx))
	nativeDeleteBoundaryReject(t, r, ctx, tuples, "permission denied for table relation_fact")
	_, err = r.admin.Exec(ctx, `GRANT DELETE ON kaname.relation_fact TO `+quoted)
	require.NoError(t, err)
	nativeDeleteBoundaryHealthyTwin(t, r, ctx, tuples)
}

func TestNativeDeleteBatchRejectsExtraCanonicalJournalCallback(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	tuples := nativeDeleteBoundaryFixture(t, r, ctx)
	_, err := r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_native_batch_extra_callback_v4() RETURNS trigger
 LANGUAGE plpgsql AS $hook$ BEGIN RETURN NULL; END $hook$;
 CREATE TRIGGER relation_fact_01_boundary AFTER INSERT ON kaname.fga_outbox
 FOR EACH STATEMENT EXECUTE FUNCTION kaname.test_native_batch_extra_callback_v4()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, cleanupErr := r.admin.Exec(cleanup, `DROP TRIGGER IF EXISTS relation_fact_01_boundary ON kaname.fga_outbox;
 DROP FUNCTION IF EXISTS kaname.test_native_batch_extra_callback_v4()`)
		require.NoError(t, cleanupErr)
	})
	var canonical, between bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT tgrelid='kaname.fga_outbox'::regclass AND tgtype=4 AND tgenabled='O' AND NOT tgisinternal,
 tgname COLLATE "C">'relation_fact_00_native_batch' COLLATE "C" AND tgname COLLATE "C"<'relation_fact_follows_journal' COLLATE "C"
 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.fga_outbox'::regclass AND tgname='relation_fact_01_boundary'`).Scan(&canonical, &between))
	require.True(t, canonical)
	require.True(t, between)
	// Baseline снимается ВНУТРИ Reject после установки adversarial hook.
	// Сам hook не пишет и не бросает ошибку:42501 обязан выдать production graph.
	nativeDeleteBoundaryReject(t, r, ctx, tuples, "native batch executable closure changed")
	_, err = r.admin.Exec(ctx, `DROP TRIGGER relation_fact_01_boundary ON kaname.fga_outbox;
 DROP FUNCTION kaname.test_native_batch_extra_callback_v4()`)
	require.NoError(t, err)
	nativeDeleteBoundaryHealthyTwin(t, r, ctx, tuples)
}
