// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const accessLabelGenerationCapture = "kaname._authority_access_label_object_generation_capture_v1(text,text,integer,integer)"
const accessLabelGenerationCaptureSQL = `SELECT kaname._authority_access_label_object_generation_capture_v1($1,$2,$3,$4)`

type accessLabelGenerationSnapshot struct {
	DirectRoot   json.RawMessage   `json:"direct_root"`
	OutputStates []json.RawMessage `json:"output_states"`
	Roots        []struct {
		State      json.RawMessage   `json:"state"`
		Facts      json.RawMessage   `json:"facts"`
		FactStates []json.RawMessage `json:"fact_states"`
	} `json:"roots"`
	Rows  int `json:"rows"`
	Reads int `json:"reads"`
}

// Только приватное наблюдение владельца. Ручная подготовка поколений не
// подменяет будущую проверку signed producer, worker или retirement.
func TestAccessLabelObjectGenerationCaptureKeepsCompletePhysicalCensus(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels) VALUES
('iam.account',$1,'00000000-0000-4000-8000-000000000001','{}'),
('iam.project','capture-output','00000000-0000-4000-8000-000000000002','{}'),
('iam.project','capture-other','00000000-0000-4000-8000-000000000003','{}'),
('iam.project','capture-unrelated','00000000-0000-4000-8000-000000000004','{}'),
('iam.account','capture-deleted-account','00000000-0000-4000-8000-000000000005','{}')`, r.a)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
SELECT r.root_type,r.root_id,r.generation,f.object_type,f.object_id,f.relation,f.subject
FROM (VALUES
('iam.account',$1::text,'project','capture-output','viewer','user:z'),
('iam.account',$1::text,'project','capture-output','viewer','user:a'),
('iam.account',$1::text,'project','capture-another-output','editor','user:outside'),
('iam.project','capture-other','project','capture-output','viewer','user:a'),
('iam.project','capture-unrelated','project','capture-unrelated-output','viewer','user:unrelated')
) f(root_type,root_id,object_type,object_id,relation,subject)
JOIN kaname.authority_access_label_dirty_root r USING(root_type,root_id)`, r.a)
	require.NoError(t, err)
	var physicalResourceExists bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.projects WHERE id='capture-output')
 OR EXISTS(SELECT 1 FROM kaname.accounts WHERE id='capture-deleted-account')`).Scan(&physicalResourceExists))
	require.False(t, physicalResourceExists)

	capture := func(model, id string, rows, reads int) (accessLabelGenerationSnapshot, []byte) {
		t.Helper()
		var raw []byte
		require.NoError(t, tx.QueryRow(r.ctx, accessLabelGenerationCaptureSQL, model, id, rows, reads).Scan(&raw))
		var result accessLabelGenerationSnapshot
		require.NoError(t, json.Unmarshal(raw, &result))
		return result, raw
	}
	got, raw := capture("project", "capture-output", 10, 7)
	require.Equal(t, 10, got.Rows, "три output-строки, три корня и четыре строки полного поколения")
	require.Equal(t, 7, got.Reads)
	require.Len(t, got.OutputStates, 3)
	require.Len(t, got.Roots, 3)
	var expectedOutput []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_array(xmin::text,ctid::text,to_jsonb(d))
 ORDER BY root_type COLLATE "C",root_id COLLATE "C",relation COLLATE "C",subject COLLATE "C")
 FROM kaname.authority_access_label_dirty_fact d WHERE object_type='project' AND object_id='capture-output'`).Scan(&expectedOutput))
	actualOutput, err := json.Marshal(got.OutputStates)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedOutput), string(actualOutput))
	_, repeated := capture("project", "capture-output", 10, 7)
	require.JSONEq(t, string(raw), string(repeated))
	for i, key := range [][2]string{{"iam.account", r.a}, {"iam.project", "capture-other"}, {"iam.project", "capture-output"}} {
		var state, facts, states []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_build_array(xmin::text,ctid::text,to_jsonb(r))
 FROM kaname.authority_access_label_dirty_root r WHERE root_type=$1 AND root_id=$2`, key[0], key[1]).Scan(&state))
		require.JSONEq(t, string(state), string(got.Roots[i].State))
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT
 coalesce(jsonb_agg(jsonb_build_object('object_type',object_type,'object_id',object_id,'relation',relation,'subject',subject)
 ORDER BY object_type COLLATE "C",object_id COLLATE "C",relation COLLATE "C",subject COLLATE "C"),'[]'),
 coalesce(jsonb_agg(jsonb_build_array(xmin::text,ctid::text,to_jsonb(d))
 ORDER BY object_type COLLATE "C",object_id COLLATE "C",relation COLLATE "C",subject COLLATE "C"),'[]')
 FROM kaname.authority_access_label_dirty_fact d WHERE root_type=$1 AND root_id=$2`, key[0], key[1]).Scan(&facts, &states))
		require.JSONEq(t, string(facts), string(got.Roots[i].Facts))
		actualStates, err := json.Marshal(got.Roots[i].FactStates)
		require.NoError(t, err)
		require.JSONEq(t, string(states), string(actualStates))
	}
	var direct struct {
		State json.RawMessage `json:"state"`
	}
	require.NoError(t, json.Unmarshal(got.DirectRoot, &direct))
	require.JSONEq(t, string(got.Roots[2].State), string(direct.State))
	require.JSONEq(t, `[]`, string(got.Roots[2].Facts), "пустой корень удалённого проекта сохранён")
	account, _ := capture("account", "capture-deleted-account", 1, 3)
	require.Len(t, account.Roots, 1)
	require.JSONEq(t, `[]`, string(account.Roots[0].Facts))
	missing, _ := capture("project", "capture-missing", 0, 2)
	require.Empty(t, missing.Roots)
	require.Equal(t, 2, missing.Reads)
	require.JSONEq(t, `{"root_type":"iam.project","root_id":"capture-missing","state":null}`, string(missing.DirectRoot))
	ordinary, _ := capture("iam_user", "capture-missing", 0, 1)
	require.Empty(t, ordinary.Roots)
	require.Equal(t, 1, ordinary.Reads)
	require.Equal(t, "null", string(ordinary.DirectRoot))

	// Смена физической версии при прежнем логическом значении видна в снимке.
	_, err = tx.Exec(r.ctx, `UPDATE kaname.authority_access_label_dirty_fact SET subject=subject
 WHERE root_type='iam.account' AND root_id=$1 AND object_id='capture-output' AND subject='user:a'`, r.a)
	require.NoError(t, err)
	changed, changedRaw := capture("project", "capture-output", 10, 7)
	require.NotEqual(t, string(raw), string(changedRaw))
	require.JSONEq(t, string(got.Roots[0].Facts), string(changed.Roots[0].Facts))
	require.NotEqual(t, got.Roots[0].FactStates, changed.Roots[0].FactStates)
	_, err = tx.Exec(r.ctx, `UPDATE kaname.authority_access_label_dirty_root SET new_labels=new_labels
 WHERE root_type='iam.account' AND root_id=$1`, r.a)
	require.NoError(t, err)
	rootChanged, _ := capture("project", "capture-output", 10, 7)
	require.NotEqual(t, changed.Roots[0].State, rootChanged.Roots[0].State)

	for _, tc := range []struct {
		name, model, objectID string
		rows, reads           int
		code                  string
	}{
		{"output-sentinel", "project", "capture-output", 2, 7, "54000"},
		{"fact-sentinel", "project", "capture-output", 6, 7, "54000"},
		{"root-sentinel", "project", "capture-output", 9, 7, "54000"},
		{"read-limit", "project", "capture-output", 10, 6, "54000"},
		{"invalid-budget", "project", "capture-output", -1, 7, "54000"},
		{"dotted-type", "iam.project", "capture-output", 10, 7, "42501"},
		{"unknown-model", "capture_unknown_model", "capture-missing", 0, 2, "42501"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			defer sp.Rollback(r.ctx)
			var value []byte
			err = sp.QueryRow(r.ctx, accessLabelGenerationCaptureSQL, tc.model, tc.objectID, tc.rows, tc.reads).Scan(&value)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, tc.code, pgErr.Code)
		})
	}
}

func TestAccessLabelObjectGenerationCaptureRemainsOwnerOnly(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege($1,'EXECUTE')`, accessLabelGenerationCapture).Scan(&allowed))
	require.False(t, allowed)
	var value []byte
	err := r.runtime.QueryRow(r.ctx, accessLabelGenerationCaptureSQL, "project", "missing", 0, 2).Scan(&value)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
	for _, table := range []string{"authority_access_label_dirty_root", "authority_access_label_dirty_fact"} {
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege('kaname.'||$1,'SELECT,INSERT,UPDATE,DELETE')`, table).Scan(&allowed))
		require.False(t, allowed)
	}

	// Проверяем также grants через ALTER DEFAULT PRIVILEGES при повторном Up.
	// Миграция не меняет данные; Down/Up выполняются внутри откатываемой транзакции.
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	raw, err := migrations.FS.ReadFile("20261125020000_access_label_object_generation_capture.sql")
	require.NoError(t, err)
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	require.True(t, ok)
	_, err = tx.Exec(r.ctx, down)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, up)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT has_function_privilege($1::name,$2,'EXECUTE')`, r.role, accessLabelGenerationCapture).Scan(&allowed))
	require.False(t, allowed)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT p.provolatile='s' AND NOT p.prosecdef
 AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
 AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
 FROM pg_proc p WHERE p.oid=$1::regprocedure`, accessLabelGenerationCapture).Scan(&allowed))
	require.True(t, allowed)
}

// Отсутствующий проект с открытым поколением не должен подтверждаться
// рабочим циклом как полностью обработанное событие.
func TestResourceObjectReconcileDefersOpenAccessLabelGeneration(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	r := f.r
	const root, output = "reconcile-deleted-project", "reconcile-related-project"
	require.NoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", root))

	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels) VALUES ('iam.project',$1,'00000000-0000-4000-8000-000000000006','{}')`, root)
	require.NoError(t, err)
	require.ErrorIs(t, f.engine.ReconcileObject(r.ctx, "iam.project", root), kaname.ErrAccessLabelReconcilePending)

	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact
 (root_type,root_id,generation,object_type,object_id,relation,subject)
 SELECT root_type,root_id,generation,'project',$2,'viewer',subjects.subject
 FROM kaname.authority_access_label_dirty_root
 CROSS JOIN (VALUES ('user:waiting'),('user:also-waiting')) subjects(subject)
 WHERE root_type='iam.project' AND root_id=$1`, root, output)
	require.NoError(t, err)
	require.ErrorIs(t, f.engine.ReconcileObject(r.ctx, "iam.project", output), kaname.ErrAccessLabelReconcilePending)

	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer tx.Rollback(r.ctx)
	var pending bool
	var rows, reads int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT pending,logical_rows,logical_reads
 FROM kaname.authority_resource_reconcile_pending_v1('project',$1,1,2)`, output).Scan(&pending, &rows, &reads))
	require.True(t, pending)
	require.Equal(t, 1, rows, "проверка не перечитывает всё открытое поколение")
	require.Equal(t, 2, reads)
	require.NoError(t, tx.Rollback(r.ctx))

	// События можно подтвердить после закрытия поколения. Здесь закрытие
	// готовит владелец фикстуры, чтобы проверить штатный вход работника.
	_, err = r.admin.Exec(r.ctx, `DELETE FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.project' AND root_id=$1`, root)
	require.NoError(t, err)
	require.NoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", root))
	require.NoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", output))
}

func TestAccessLabelReconcileObservationRequiresWorkerPrivilegesAndSnapshot(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const query = `SELECT pending,logical_rows,logical_reads FROM kaname.authority_resource_reconcile_pending_v1('project','missing',0,2)`
	var pending bool
	var rows, reads int
	var pgErr *pgconn.PgError
	err := r.runtime.QueryRow(r.ctx, query).Scan(&pending, &rows, &reads)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)

	read := func() error {
		t.Helper()
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		return tx.QueryRow(r.ctx, query).Scan(&pending, &rows, &reads)
	}
	require.NoError(t, read())
	require.False(t, pending)
	require.Zero(t, rows)
	require.Equal(t, 2, reads)

	_, err = r.admin.Exec(r.ctx, `REVOKE SELECT ON kaname.resource_reconcile_outbox FROM `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	require.ErrorAs(t, read(), &pgErr)
	require.Equal(t, "42501", pgErr.Code)
}

// Проекция нужна для сбора выходных графов. Метаданные и точные состояния
// источников доступны только владельцу и подтверждаются повторным чтением.
func TestAccessLabelGenerationProjectionSharesOnlyPlanningCoordinates(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const root, output, otherOutput = "projection-root", "projection-output-a", "projection-output-b"
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels)
 VALUES ('iam.project',$1,'00000000-0000-4000-8000-000000000007','{"team":"private-team"}')`, root)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact
 (root_type,root_id,generation,object_type,object_id,relation,subject)
 SELECT root_type,root_id,generation,'project',coord.id,'viewer',coord.subject
 FROM kaname.authority_access_label_dirty_root
 CROSS JOIN (VALUES ($2::text,'user:private-alpha'),($2::text,'user:private-beta'),($3::text,'user:private-alpha')) coord(id,subject)
 WHERE root_type='iam.project' AND root_id=$1`, root, output, otherOutput)
	require.NoError(t, err)

	const query = `SELECT fingerprint,roots,outputs,logical_rows,logical_reads
 FROM kaname.authority_resource_generation_observe_v1('project',$1,$2,$3)`
	var fingerprint *string
	var roots, outputs []byte
	var rows, reads int
	observe := func(id string, maxRows, maxReads int) error {
		t.Helper()
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		return tx.QueryRow(r.ctx, query, id, maxRows, maxReads).Scan(&fingerprint, &roots, &outputs, &rows, &reads)
	}

	require.NoError(t, observe(output, 7, 6))
	require.NotNil(t, fingerprint)
	var ownerDigest string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT encode(sha256(convert_to(
 kaname._authority_access_label_object_generation_capture_v1('project',$1,6,4)::text,'UTF8')),'hex')`, output).Scan(&ownerDigest))
	require.Equal(t, ownerDigest, *fingerprint)
	require.JSONEq(t, `[["iam.project","projection-root"]]`, string(roots))
	require.JSONEq(t, `[["project","projection-output-a"],["project","projection-output-b"]]`, string(outputs))
	require.Equal(t, 7, rows)
	require.Equal(t, 6, reads)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, observe(output, 6, 6), &pgErr)
	require.Equal(t, "54000", pgErr.Code)

	require.NoError(t, observe("projection-absent", 0, 2))
	require.Nil(t, fingerprint)
	require.JSONEq(t, `[]`, string(roots))
	require.JSONEq(t, `[]`, string(outputs))
	require.Zero(t, rows)
	require.Equal(t, 2, reads)

	_, err = r.admin.Exec(r.ctx, `REVOKE UPDATE ON kaname.resource_reconcile_outbox FROM `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	require.ErrorAs(t, observe(output, 7, 6), &pgErr)
	require.Equal(t, "42501", pgErr.Code)
}

// Координата второго аккаунта появляется только в поколении отзыва.
// Штатный пересчёт удерживает её, сверяет отсутствие факта и закрывает поколение.
func TestResourceObjectCommitsGenerationOnlyOutput(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	r := f.r
	root := string(f.scenes[0].Project)
	output := string(f.scenes[1].Project)
	require.NotEqual(t, f.scenes[0].Account, f.scenes[1].Account)

	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels)
 VALUES ('iam.project',$1,'00000000-0000-4000-8000-000000000008','{}')`, root)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact
 (root_type,root_id,generation,object_type,object_id,relation,subject)
 SELECT root_type,root_id,generation,'project',$2,'viewer','user:prewait'
 FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.project' AND root_id=$1`, root, output)
	require.NoError(t, err)

	err = f.engine.ReconcileObject(r.ctx, "iam.project", root)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	var roots, facts int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.project' AND root_id=$1),
 (SELECT count(*) FROM kaname.authority_access_label_dirty_fact WHERE root_type='iam.project' AND root_id=$1)`, root).Scan(&roots, &facts))
	require.Zero(t, roots)
	require.Zero(t, facts)
	require.NoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", root))
	authorityWaitReleased(t, r.runtime)
}
