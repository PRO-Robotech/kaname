// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/access-label-custody/setup.sql
var accessLabelCustodySetup string

func accessLabelCustodyMigrations(t *testing.T) (string, string) {
	t.Helper()
	raw, err := migrations.FS.ReadFile(accessLabelFreshnessMigration)
	require.NoError(t, err)
	_, freshness, ok := strings.Cut(string(raw), "CREATE TABLE kaname.authority_access_label_dirty_root")
	require.True(t, ok)
	freshness, _, ok = strings.Cut(freshness, "CREATE FUNCTION kaname._authority_access_label_freshness_storage_v1")
	require.True(t, ok)
	raw, err = migrations.FS.ReadFile("20261124230000_access_label_metadata_freshness_program.sql")
	require.NoError(t, err)
	_, program, ok := strings.Cut(string(raw), "CREATE FUNCTION kaname._authority_metadata_access_label_carry_v1")
	require.True(t, ok)
	program, _, ok = strings.Cut(program, "DO $private$")
	require.True(t, ok)
	return "CREATE TABLE kaname.authority_access_label_dirty_root" + freshness, "CREATE FUNCTION kaname._authority_metadata_access_label_carry_v1" + program
}

const (
	exactAccessLabelWriteMigration = "20261125090000_access_label_metadata_exact_write.sql"
	generationB                    = "00000000-0000-4000-8000-000000000001"
	generationA                    = "00000000-0000-4000-8000-000000000002"
	generationRollback             = "00000000-0000-4000-8000-000000000003"
)

// Проверяем сохранение фактов и откат на SQL-фрагменте writer.
// Подготовленную программу источников задаёт fixture, сам протокол не запускается.
func TestResourceCustodyLegitimateABAAndRollback(t *testing.T) {
	for _, table := range []string{"accounts", "projects"} {
		t.Run(table, func(t *testing.T) {
			ctx := context.Background()
			dsn := pgtest.NewEmptyDB(t)
			owner, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer owner.Close(ctx)
			freshness, custody := accessLabelCustodyMigrations(t)
			raw, err := migrations.FS.ReadFile(exactAccessLabelWriteMigration)
			require.NoError(t, err)
			_, exactWrite, ok := strings.Cut(string(raw), "CREATE FUNCTION kaname.authority_metadata_access_label_write_v1")
			require.True(t, ok)
			exactWrite, _, ok = strings.Cut(exactWrite, "-- +goose StatementEnd")
			require.True(t, ok)
			for _, sql := range []string{accessLabelCustodySetup, freshness, custody,
				"CREATE FUNCTION kaname.authority_metadata_access_label_write_v1" + exactWrite, `
CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.accounts
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();
CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.projects
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();`} {
				_, err = owner.Exec(ctx, sql)
				require.NoError(t, err)
			}
			rootType, rootID := "iam.account", "account-1"
			if table == "projects" {
				rootType, rootID = "iam.project", "project-1"
			}
			role := "custody_reader_" + table
			_, err = owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+`;
GRANT USAGE ON SCHEMA kaname TO `+pgx.Identifier{role}.Sanitize()+`;
GRANT SELECT ON kaname.accounts,kaname.projects,kaname.relation_fact TO `+pgx.Identifier{role}.Sanitize()+`;
INSERT INTO kaname.relation_fact VALUES
('project','retained-A','viewer','user:holder'),
('project','retained-B','viewer','user:holder'),
('project','unaffected','viewer','user:holder')`)
			require.NoError(t, err)
			reader, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer reader.Close(ctx)
			_, err = reader.Exec(ctx, `SET ROLE `+pgx.Identifier{role}.Sanitize())
			require.NoError(t, err)
			read := func(labels string, visible []string) {
				t.Helper()
				var got string
				err := reader.QueryRow(ctx, `SELECT access_labels::text FROM kaname.`+table+` WHERE id=$1`, rootID).Scan(&got)
				require.NoError(t, err)
				require.JSONEq(t, labels, got)
				rows, err := reader.Query(ctx, `SELECT object_id FROM kaname.relation_fact
WHERE kaname.authority_access_label_fact_fresh_v1(object_type,object_id,relation,subject)
ORDER BY object_id COLLATE "C"`)
				require.NoError(t, err)
				ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
				require.NoError(t, err)
				require.Equal(t, visible, ids)
			}
			snapshot := func() string {
				t.Helper()
				var result string
				err := owner.QueryRow(ctx, `SELECT jsonb_build_object(
'roots',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY root_type,root_id),'[]'::jsonb) FROM kaname.authority_access_label_dirty_root r),
'facts',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY object_id),'[]'::jsonb) FROM kaname.authority_access_label_dirty_fact f),
'program',(SELECT to_jsonb(p) FROM pg_temp.kaname_authority_sequence_program p),
'row',(SELECT to_jsonb(r) FROM kaname.`+table+` r WHERE id=$1))::text`, rootID).Scan(&result)
				require.NoError(t, err)
				return result
			}
			kind := strings.TrimPrefix(rootType, "iam.")
			prepare := func(tx pgx.Tx, next, generation, key string) {
				t.Helper()
				var old, oldLabels, xmin, ctid, carry string
				err := tx.QueryRow(ctx, `SELECT to_jsonb(o)::text,access_labels::text,xmin::text,ctid::text
FROM kaname.`+table+` o WHERE id=$1 FOR UPDATE`, rootID).Scan(&old, &oldLabels, &xmin, &ctid)
				require.NoError(t, err)
				err = tx.QueryRow(ctx, `SELECT kaname._authority_metadata_access_label_carry_v1($1,$2,$3::jsonb,100,10)::text`, rootType, rootID, oldLabels).Scan(&carry)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `INSERT INTO pg_temp.kaname_authority_sequence_program(singleton,nonce,family,frozen)
SELECT true,$1::uuid,'metadata',jsonb_build_object('table',$2::text,
'command',jsonb_build_object('old',$4::jsonb,
'new',$4::jsonb || jsonb_build_object('access_labels',$5::jsonb,'name','changed','labels',jsonb_build_object('display','ok'))),
'access_label_root_physical',jsonb_build_object('table',$2::text,'id',$3::text,'xmin',$9::text,'ctid',$10::text),
'access_label_freshness',jsonb_build_object('root_type',$6::text,'root_id',$3::text,
'prior_generation',$7::jsonb->'prior_generation','facts',($7::jsonb->'prior_facts') || jsonb_build_array(
jsonb_build_object('object_type','project','object_id',$8::text,'relation','viewer','subject','user:holder'))))
ON CONFLICT(singleton) DO UPDATE SET nonce=excluded.nonce,family=excluded.family,frozen=excluded.frozen`, generation, table, rootID, old, next, rootType, carry, key, xmin, ctid)
				require.NoError(t, err)
			}
			transition := func(next, generation, key string, rollback bool, wantKeys []string) {
				t.Helper()
				tx, err := owner.Begin(ctx)
				require.NoError(t, err)
				defer tx.Rollback(ctx)
				prepare(tx, next, generation, key)
				var writeResult string
				err = tx.QueryRow(ctx, `SELECT kaname.authority_metadata_access_label_write_v1($1,$2)::text`, kind, rootID).Scan(&writeResult)
				require.NoError(t, err)
				require.JSONEq(t, fmt.Sprintf(`{"id":%q,"name":"changed","description":"","labels":{"display":"ok"},"access_labels":%s}`, rootID, next), writeResult)
				var installed, gotGeneration string
				err = tx.QueryRow(ctx, `SELECT frozen->>'access_label_freshness_installed' FROM pg_temp.kaname_authority_sequence_program`).Scan(&installed)
				require.NoError(t, err)
				require.Equal(t, generation, installed)
				err = tx.QueryRow(ctx, `SELECT generation::text FROM kaname.authority_access_label_dirty_root WHERE root_type=$1 AND root_id=$2`, rootType, rootID).Scan(&gotGeneration)
				require.NoError(t, err)
				require.Equal(t, generation, gotGeneration)
				rows, err := tx.Query(ctx, `SELECT object_id FROM kaname.authority_access_label_dirty_fact WHERE root_type=$1 AND root_id=$2 AND generation=$3::uuid ORDER BY object_id COLLATE "C"`, rootType, rootID, generation)
				require.NoError(t, err)
				keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
				require.NoError(t, err)
				require.Equal(t, wantKeys, keys)
				if rollback {
					// Ошибка следующей операции откатывает ресурс, отложенные факты и запись программы.
					_, err = tx.Exec(ctx, `SELECT 1/0`)
					require.Error(t, err)
					require.NoError(t, tx.Rollback(ctx))
					return
				}
				require.NoError(t, tx.Commit(ctx))
			}
			read(`{"env":"A"}`, []string{"retained-A", "retained-B", "unaffected"})
			transition(`{"env":"B"}`, generationB, "retained-A", false, []string{"retained-A"})
			read(`{"env":"B"}`, []string{"retained-B", "unaffected"})
			transition(`{"env":"A"}`, generationA, "retained-B", false, []string{"retained-A", "retained-B"})
			read(`{"env":"A"}`, []string{"unaffected"})
			before := snapshot()
			// Запоздалое завершение первого поколения сохраняет записи второго.
			tag, err := owner.Exec(ctx, `DELETE FROM kaname.authority_access_label_dirty_root WHERE root_type=$1 AND root_id=$2 AND generation=$3::uuid`, rootType, rootID, generationB)
			require.NoError(t, err)
			require.EqualValues(t, 0, tag.RowsAffected())
			require.JSONEq(t, before, snapshot())
			transition(`{"env":"B"}`, generationRollback, "unaffected", true, []string{"retained-A", "retained-B", "unaffected"})
			require.JSONEq(t, before, snapshot(), fmt.Sprintf("%s rollback must preserve second generation", table))
			read(`{"env":"A"}`, []string{"unaffected"})
			for _, rejected := range []struct{ name, change, code string }{
				{"physical_version", `UPDATE kaname.` + table + ` SET name=name`, "40001"},
				{"freshness_trigger_missing", `DROP TRIGGER access_labels_000_commit_freshness ON kaname.` + table, "42501"},
			} {
				t.Run(rejected.name, func(t *testing.T) {
					tx, err := owner.Begin(ctx)
					require.NoError(t, err)
					defer tx.Rollback(ctx)
					prepare(tx, `{"env":"B"}`, generationRollback, "unaffected")
					_, err = tx.Exec(ctx, rejected.change)
					require.NoError(t, err)
					_, err = tx.Exec(ctx, `SELECT kaname.authority_metadata_access_label_write_v1($1,$2)`, kind, rootID)
					var dbErr *pgconn.PgError
					require.ErrorAs(t, err, &dbErr)
					require.Equal(t, rejected.code, dbErr.Code)
					require.NoError(t, tx.Rollback(ctx))
					require.JSONEq(t, before, snapshot())
				})
			}
		})
	}
}

func TestResourceCustodyMigrationKeepsFunctionsPrivate(t *testing.T) {
	r := writerProtocolRig(t)
	for _, signature := range []string{
		"kaname._authority_metadata_access_label_origin_v1(text,text)",
		"kaname._authority_metadata_access_label_carry_v1(text,text,jsonb,integer,integer)",
		"kaname._authority_metadata_access_label_freshness_v1()",
		"kaname.authority_metadata_access_label_write_v1(text,text)",
	} {
		var ownerCanExecute, runtimeCanExecute bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT has_function_privilege($1::regprocedure, 'EXECUTE')`, signature).Scan(&ownerCanExecute))
		require.True(t, ownerCanExecute, signature)
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege($1::regprocedure, 'EXECUTE')`, signature).Scan(&runtimeCanExecute))
		require.False(t, runtimeCanExecute, signature)
	}
	var guardActive, writeTriggerInstalled bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname.authority_access_label_storage_valid_v1(),
 EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
 WHERE t.tgfoid='kaname._authority_metadata_access_label_freshness_v1()'::regprocedure)`).Scan(&guardActive, &writeTriggerInstalled))
	require.True(t, guardActive)
	require.False(t, writeTriggerInstalled, "Пока переход не подключён к подтверждённой записи")
}
