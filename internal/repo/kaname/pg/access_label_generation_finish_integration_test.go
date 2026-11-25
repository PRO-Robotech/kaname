// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const accessLabelGenerationFinish = "kaname._authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)"
const accessLabelGenerationFinishSQL = `SELECT kaname._authority_access_label_object_generation_finish_v1($1,$2,$3,$4)`

// Тест проверяет приватную операцию напрямую от владельца базы.
func TestAccessLabelGenerationFinishExactOwnerPartition(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels) VALUES
('iam.project','finish-root','00000000-0000-4000-8000-000000000061','{}'),
('iam.project','finish-other-root','00000000-0000-4000-8000-000000000062','{}'),
('iam.project','finish-empty-root','00000000-0000-4000-8000-000000000063','{}')`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
SELECT r.root_type,r.root_id,r.generation,'project','finish-output','viewer',f.subject
FROM kaname.authority_access_label_dirty_root r
CROSS JOIN (VALUES ('user:retained'),('user:absent'),('user:pending')) f(subject)
WHERE r.root_id='finish-root' OR (r.root_id='finish-other-root' AND f.subject='user:retained')`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,condition_name,condition_params)
VALUES('project','finish-output','viewer','user:retained','fixture_condition','{"scope":"exact"}')`)
	require.NoError(t, err)
	var publicBefore []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT to_jsonb(f) FROM kaname.relation_fact f
WHERE object_type='project' AND object_id='finish-output' AND relation='viewer' AND subject='user:retained'`).Scan(&publicBefore))
	capture := func(root string) []byte {
		t.Helper()
		var receipt []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_access_label_object_generation_capture_v1('project',$1,100,20)->'roots'->0`, root).Scan(&receipt))
		return receipt
	}
	receipt := capture("finish-root")
	// Ключи и полные образы сохранённых строк вычисляем в PostgreSQL
	// в формате приватного компилятора.
	var discharge []byte
	require.NoError(t, tx.QueryRow(r.ctx, `WITH expected AS (
 SELECT fact,jsonb_build_array(fact->>'object_type',fact->>'object_id',fact->>'relation',fact->>'subject')::text fact_key
 FROM jsonb_array_elements($1::jsonb->'facts') a(fact)
)
SELECT jsonb_build_object(
 'retained',jsonb_object_agg(e.fact_key,jsonb_build_object('fact',to_jsonb(f))) FILTER (WHERE e.fact->>'subject'='user:retained'),
 'absent',jsonb_object_agg(e.fact_key,true) FILTER (WHERE e.fact->>'subject'='user:absent'),
 'pending',jsonb_agg(e.fact) FILTER (WHERE e.fact->>'subject'='user:pending'))
FROM expected e LEFT JOIN kaname.relation_fact f ON
(f.object_type,f.object_id,f.relation,f.subject)=
(e.fact->>'object_type',e.fact->>'object_id',e.fact->>'relation',e.fact->>'subject')`, receipt).Scan(&discharge))
	countDirty := func(root string, want int) {
		t.Helper()
		var count int
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_access_label_dirty_fact WHERE root_type='iam.project' AND root_id=$1`, root).Scan(&count))
		require.Equal(t, want, count)
	}
	for _, tc := range []struct {
		name        string
		rows, reads int
	}{
		{"rows", 11, 6},
		{"reads", 12, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer sp.Rollback(r.ctx)
			var got []byte
			err = sp.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, tc.rows, tc.reads).Scan(&got)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "54000", pgErr.Code)
		})
		countDirty("finish-root", 3)
	}
	t.Run("complete-retained-image-before-any-delete", func(t *testing.T) {
		sp, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		defer sp.Rollback(r.ctx)
		var changed, got []byte
		require.NoError(t, sp.QueryRow(r.ctx, `SELECT jsonb_set($1::jsonb,
 ARRAY['retained',jsonb_build_array('project','finish-output','viewer','user:retained')::text,'fact','condition_params'],
 '{"scope":"changed"}'::jsonb)`, discharge).Scan(&changed))
		err = sp.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, changed, 12, 6).Scan(&got)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
	})
	countDirty("finish-root", 3)
	t.Run("absent-readback-before-any-delete", func(t *testing.T) {
		sp, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		defer sp.Rollback(r.ctx)
		_, err = sp.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
VALUES('project','finish-output','viewer','user:absent')`)
		require.NoError(t, err)
		var got []byte
		err = sp.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, 12, 6).Scan(&got)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "40001", pgErr.Code)
	})
	countDirty("finish-root", 3)
	var result []byte
	require.NoError(t, tx.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, 12, 6).Scan(&result))
	require.JSONEq(t, `{"confirmed":2,"pending":1,"rows":12,"reads":6}`, string(result))
	countDirty("finish-root", 1)
	countDirty("finish-other-root", 1)
	var pending string
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT subject FROM kaname.authority_access_label_dirty_fact WHERE root_id='finish-root'`).Scan(&pending))
	require.Equal(t, "user:pending", pending)
	var exists bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root WHERE root_id='finish-root')`).Scan(&exists))
	require.True(t, exists)
	var publicAfter []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT to_jsonb(f) FROM kaname.relation_fact f
WHERE object_type='project' AND object_id='finish-output' AND relation='viewer' AND subject='user:retained'`).Scan(&publicAfter))
	require.JSONEq(t, string(publicBefore), string(publicAfter), "retirement preserves the complete public fact")

	// Для закрытия последнего ключа заново читаем его физическое состояние.
	receipt = capture("finish-root")
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_build_object('retained','{}'::jsonb,
 'absent',jsonb_object_agg(jsonb_build_array(fact->>'object_type',fact->>'object_id',fact->>'relation',fact->>'subject')::text,true),
 'pending','[]'::jsonb) FROM jsonb_array_elements($1::jsonb->'facts') a(fact)`, receipt).Scan(&discharge))
	require.NoError(t, tx.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, 7, 5).Scan(&result))
	require.JSONEq(t, `{"confirmed":1,"pending":0,"rows":7,"reads":5}`, string(result))
	countDirty("finish-root", 0)
	countDirty("finish-other-root", 1)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root WHERE root_id='finish-root')`).Scan(&exists))
	require.False(t, exists)

	receipt = capture("finish-empty-root")
	require.NoError(t, tx.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, `{"retained":{},"absent":{},"pending":[]}`, 4, 4).Scan(&result))
	require.JSONEq(t, `{"confirmed":0,"pending":0,"rows":4,"reads":4}`, string(result))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root WHERE root_id='finish-empty-root')`).Scan(&exists))
	require.False(t, exists)
}

func TestAccessLabelGenerationFinishPreservesPendingPhysicalCensus(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
VALUES('iam.project','finish-pending','00000000-0000-4000-8000-000000000064','{}');
INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
SELECT root_type,root_id,generation,'project','finish-pending-output','viewer','user:pending'
FROM kaname.authority_access_label_dirty_root WHERE root_id='finish-pending'`)
	require.NoError(t, err)
	var receipt, discharge, result, after []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_access_label_object_generation_capture_v1('project','finish-pending',100,20)->'roots'->0`).Scan(&receipt))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_build_object('retained','{}'::jsonb,'absent','{}'::jsonb,'pending',$1::jsonb->'facts')`, receipt).Scan(&discharge))
	require.NoError(t, tx.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, 6, 4).Scan(&result))
	require.JSONEq(t, `{"confirmed":0,"pending":1,"rows":6,"reads":4}`, string(result))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_access_label_object_generation_capture_v1('project','finish-pending',100,20)->'roots'->0`).Scan(&after))
	require.JSONEq(t, string(receipt), string(after), "pending-only completion changes no physical receipt row")

	for _, tc := range []struct{ name, mutation string }{
		{"root-version", `UPDATE kaname.authority_access_label_dirty_root SET new_labels=new_labels WHERE root_id='finish-pending'`},
		{"fact-version", `UPDATE kaname.authority_access_label_dirty_fact SET subject=subject WHERE root_id='finish-pending'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer sp.Rollback(r.ctx)
			_, err = sp.Exec(r.ctx, tc.mutation)
			require.NoError(t, err)
			err = sp.QueryRow(r.ctx, accessLabelGenerationFinishSQL, receipt, discharge, 6, 4).Scan(&result)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "40001", pgErr.Code)
		})
	}
}

func TestAccessLabelGenerationFinishRemainsOwnerOnly(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege($1,'EXECUTE')`, accessLabelGenerationFinish).Scan(&allowed))
	require.False(t, allowed)
	var value []byte
	err := r.runtime.QueryRow(r.ctx, accessLabelGenerationFinishSQL, `{}`, `{}`, 4, 4).Scan(&value)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
	for _, table := range []string{"authority_access_label_dirty_root", "authority_access_label_dirty_fact"} {
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege('kaname.'||$1,'SELECT,INSERT,UPDATE,DELETE')`, table).Scan(&allowed))
		require.False(t, allowed)
	}
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	raw, err := migrations.FS.ReadFile("20261125060000_access_label_generation_finish.sql")
	require.NoError(t, err)
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, ok)
	_, err = tx.Exec(r.ctx, down)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, up)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT has_function_privilege($1::name,$2,'EXECUTE')`, r.role, accessLabelGenerationFinish).Scan(&allowed))
	require.False(t, allowed)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT p.provolatile='v' AND NOT p.prosecdef
 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid=$1::regprocedure`, accessLabelGenerationFinish).Scan(&allowed))
	require.True(t, allowed)
}
