// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Номер выводится из фактической embedded цепи, без арифметики timestamp и
// предположения о непрерывной нумерации исторических миграций.
func sevenCRUDMigrationDB(t *testing.T, r protocolRig) (*sql.DB, int64, int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var own, previous, latest int64
	var versions []int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		head, _, ok := strings.Cut(entry.Name(), "_")
		require.True(t, ok)
		version, err := strconv.ParseInt(head, 10, 64)
		require.NoError(t, err)
		versions = append(versions, version)
		if version > latest {
			latest = version
		}
		if strings.HasSuffix(entry.Name(), "_full_crud_commands_compile_before_clock.sql") {
			require.Zero(t, own, "должен быть ровно один файл предмета")
			own = version
		}
	}
	require.NotZero(t, own)
	require.GreaterOrEqual(t, latest, own)
	for _, version := range versions {
		if version < own && version > previous {
			previous = version
		}
	}
	require.NotZero(t, previous)
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	// Новые append-миграции снимаются настоящим Goose только в nonfull GIVEN.
	// Сам предмет и прежние exact body/ACL assertions остаются без изменений.
	require.NoError(t, goose.DownTo(db, ".", own))
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", latest)) })
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	return db, own, previous
}

func sevenCRUDFunctionState(t *testing.T, r protocolRig) string {
	t.Helper()
	var state string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_object(
  'name',p.proname,'definition',pg_get_functiondef(p.oid),'acl',p.proacl,'owner',p.proowner)
  ORDER BY p.proname)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='kaname' AND p.proname IN ('authority_crud_storage_v3',
  '_authority_full_contract_storage_v3','authority_protocol_grant_runtime','authority_protocol_attestation',
  'authority_protocol_statement_guard','authority_resource_finalize_v2','authority_resource_prewait_v2',
  'authority_resource_assert_body_v2','authority_resource_fold_body_v2','_authority_resource_require_completion_v2',
  'resource_journal_emit','resource_journal_emit_member','authority_resource_journal_id_v3',
  'authority_fga_outbox_id_v3','authority_metadata_preflight_v3','authority_sa_state_preflight_v3',
  'authority_grant_mutation_preflight','authority_role_stage_epoch_lock','_authority_sequence_reserve_v3',
  'authority_binding_stage_sequence_capture_v3','authority_binding_stage_sequence_prepare_v3',
  'membership_mirror_from_user')`).Scan(&state))
	return state
}

func sevenCRUDMigrationPrivateACL(t *testing.T, r protocolRig) {
	t.Helper()
	var private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
  'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&private))
	require.False(t, private, "Down/Up не выдаёт LOGIN private verifier")
}

func TestSevenCRUDMigrationGooseRoundTripRestoresExactPreviousContract(t *testing.T) {
	r := writerProtocolRig(t)
	db, own, previous := sevenCRUDMigrationDB(t, r)
	before := sevenCRUDFunctionState(t, r)
	var mirrorBefore, mirrorAfter, mirrorBody string
	const mirrorStateSQL = `SELECT jsonb_build_object('owner',proowner,'acl',proacl,'definer',prosecdef,'volatility',provolatile,'config',proconfig)::text,encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname.membership_mirror_from_user()'::regprocedure`
	require.NoError(t, r.admin.QueryRow(r.ctx, mirrorStateSQL).Scan(&mirrorBefore, &mirrorBody))
	require.Equal(t, "d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405", mirrorBody)
	sevenCRUDMigrationPrivateACL(t, r)
	// Даже при раннем Fatal база возвращается к текущей цепи до cleanup фикстуры.
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."), "настоящий Goose Down, не ручное исполнение его SQL")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	require.NoError(t, r.admin.QueryRow(r.ctx, mirrorStateSQL).Scan(&mirrorAfter, &mirrorBody))
	require.Equal(t, mirrorBefore, mirrorAfter, "Down не меняет invoker/owner/ACL зеркала")
	require.Equal(t, "42de1b3eeb1c107b8c5b9ca10eea1485af7f68ac8c6b821a07c02817ef89be8d", mirrorBody, "Down возвращает точное прежнее тело")
	var absent bool
	var readiness, grants string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
  to_regprocedure('kaname.authority_crud_storage_v3()') IS NULL,
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname._authority_full_contract_storage_v3()'::regprocedure),
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure)`).Scan(&absent, &readiness, &grants))
	require.True(t, absent)
	// Декодер сокращает schema-visible regclass; exact sequence OID остаётся обязательным.
	var defaults int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE (a.attrelid='kaname.resource_journal'::regclass AND a.attname='sequence_no' AND pg_get_expr(d.adbin,d.adrelid) IN ('nextval(''kaname.resource_journal_sequence_no_seq''::regclass)','nextval(''resource_journal_sequence_no_seq''::regclass)') AND EXISTS(SELECT 1 FROM pg_depend dep WHERE dep.classid='pg_attrdef'::regclass AND dep.objid=d.oid AND dep.refclassid='pg_class'::regclass AND dep.refobjid='kaname.resource_journal_sequence_no_seq'::regclass))
 OR (a.attrelid='kaname.fga_outbox'::regclass AND a.attname='id' AND pg_get_expr(d.adbin,d.adrelid) IN ('nextval(''kaname.fga_outbox_id_seq''::regclass)','nextval(''fga_outbox_id_seq''::regclass)') AND EXISTS(SELECT 1 FROM pg_depend dep WHERE dep.classid='pg_attrdef'::regclass AND dep.objid=d.oid AND dep.refclassid='pg_class'::regclass AND dep.refobjid='kaname.fga_outbox_id_seq'::regclass))`).Scan(&defaults))
	require.Equal(t, 2, defaults, "Down восстановил оба прежних actual DEFAULT")
	// Точные prosrc предыдущих 28 pins и wrapper из последних SOURCE миграций.
	require.Equal(t, "968aed0579f53382ce929fa8d28882c811455bd33eb6c56ec0da2d90a0aec8f4", readiness)
	require.Equal(t, "8f7901051b28fc77e7ac9e9284110f89eb72776090782d56e250fc1bee3a9bf6", grants)
	sevenCRUDMigrationPrivateACL(t, r)
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "предыдущая цепь 28 pins действительно работоспособна")
	require.NoError(t, goose.UpTo(db, ".", own))
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.NoError(t, r.admin.QueryRow(r.ctx, mirrorStateSQL).Scan(&mirrorAfter, &mirrorBody))
	require.Equal(t, mirrorBefore, mirrorAfter)
	require.Equal(t, "d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405", mirrorBody, "Up возвращает исправленное тело")
	require.Equal(t, before, sevenCRUDFunctionState(t, r), "Up восстановил definition/owner/ACL прежних entry, dispatch и journal функций")
	sevenCRUDMigrationPrivateACL(t, r)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "текущая CRUD цепь с точными новыми pins восстановлена")
	var ordinaryReady bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ordinaryReady))
	require.True(t, ordinaryReady)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	writers, err := kanamepg.NewCRUDWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	require.NotNil(t, writers)
}

func TestSevenCRUDMigrationGooseDownRefusesActiveFullWithoutChanges(t *testing.T) {
	r := writerProtocolRig(t)
	db, own, _ := sevenCRUDMigrationDB(t, r)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
	var contract int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT required_contract FROM kaname.authority_writer_contract WHERE singleton`).Scan(&contract))
	require.Equal(t, 2, contract)
	before := rolePrelockMigrationSnapshot(t, r)
	err := goose.Down(db, ".")
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "P1036", pe.Code)
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.Equal(t, before, rolePrelockMigrationSnapshot(t, r), "отказ не изменяет ledger, schema, ACL, function bodies и authority state")
	sevenCRUDMigrationPrivateACL(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

// Каждая новая attachment проверяется отдельно в откатываемой owner GIVEN TX.
// Проверка не сводится к числу pg_trigger: actual readiness должна заметить
// снятие именно этого edge, затем вновь принять исходную схему.
func TestSevenCRUDReadinessRejectsEveryRemovedTriggerAndPrivateGrant(t *testing.T) {
	r := writerProtocolRig(t)
	rows, err := r.admin.Query(r.ctx, `SELECT c.relname,t.tgname FROM pg_trigger t
 JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='kaname' AND (t.tgname LIKE 'authority_crud_%'
 OR t.tgfoid='kaname.authority_sequence_origin_v3()'::regprocedure
 OR t.tgfoid='kaname.authority_sequence_program_applied_v3()'::regprocedure
 OR t.tgfoid='kaname.authority_binding_epoch_changed()'::regprocedure) ORDER BY c.relname,t.tgname`)
	require.NoError(t, err)
	var pairs [][2]string
	for rows.Next() {
		var p [2]string
		require.NoError(t, rows.Scan(&p[0], &p[1]))
		pairs = append(pairs, p)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Len(t, pairs, 145, "53 новых attachment и 92 существующих epoch edges")
	for _, pair := range pairs {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer tx.Rollback(r.ctx)
			_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.`+pgx.Identifier{pair[0]}.Sanitize()+` DISABLE TRIGGER `+pgx.Identifier{pair[1]}.Sanitize())
			require.NoError(t, err)
			var ready bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
			require.NoError(t, tx.Rollback(r.ctx))
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
			require.True(t, ready)
		})
	}
	for _, name := range []string{"resource_journal", "fga_outbox"} {
		t.Run("default/"+name, func(t *testing.T) {
			column, sequence := "sequence_no", "resource_journal_sequence_no_seq"
			if name == "fga_outbox" {
				column, sequence = "id", "fga_outbox_id_seq"
			}
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer tx.Rollback(r.ctx)
			_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.`+pgx.Identifier{name}.Sanitize()+` ALTER COLUMN `+pgx.Identifier{column}.Sanitize()+` SET DEFAULT nextval('kaname.`+sequence+`'::regclass)`)
			require.NoError(t, err)
			var ready bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
			require.False(t, ready)
		})
	}
	// Сохраняем остальные metadata trigger неизменными: readiness обязана
	// отвергать и отсутствие WHEN, и другое условие с теми же OLD/NEW строками.
	for _, name := range []string{"accounts_000_sequence_origin_update", "accounts_resource_journal_update_trg"} {
		for _, variant := range []string{"missing", "inverted"} {
			t.Run("qual/"+name+"/"+variant, func(t *testing.T) {
				tx, err := r.admin.Begin(r.ctx)
				require.NoError(t, err)
				defer tx.Rollback(r.ctx)
				var definition string
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_get_triggerdef(oid,false) FROM pg_trigger WHERE tgrelid='kaname.accounts'::regclass AND tgname=$1`, name).Scan(&definition))
				const original = " WHEN ((old.* IS DISTINCT FROM new.*))"
				require.Equal(t, 1, strings.Count(definition, original), "actual canonical trigger deparser format")
				replacement := ""
				if variant == "inverted" {
					replacement = " WHEN ((old.* IS NOT DISTINCT FROM new.*))"
				}
				_, err = tx.Exec(r.ctx, `DROP TRIGGER `+pgx.Identifier{name}.Sanitize()+` ON kaname.accounts`)
				require.NoError(t, err)
				_, err = tx.Exec(r.ctx, strings.Replace(definition, original, replacement, 1))
				require.NoError(t, err)
				var ready bool
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
				require.False(t, ready)
				require.NoError(t, tx.Rollback(r.ctx))
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
				require.True(t, ready)
			})
		}
	}
	t.Run("private-ACL", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		_, err = tx.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname._authority_crud_storage_v3() TO PUBLIC`)
		require.NoError(t, err)
		var ready bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
		require.False(t, ready)
	})
	t.Run("helper-body", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		_, err = tx.Exec(r.ctx, `CREATE OR REPLACE FUNCTION kaname._authority_crud_unique_key_v3(p_table text,p_row jsonb) RETURNS text
   LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS 'SELECT ''forged''::text'`)
		require.NoError(t, err)
		var ready bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
		require.False(t, ready)
	})
	var exposed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='kaname' AND (p.proname LIKE '\_authority\_crud\_%' ESCAPE '\'
  OR p.proname LIKE '\_authority\_resource\_crud\_%' ESCAPE '\'
  OR p.proname LIKE '\_authority\_sequence\_%' ESCAPE '\'
  OR p.proname LIKE '\_authority\_binding\_stage\_%' ESCAPE '\') AND has_function_privilege(current_user,p.oid,'EXECUTE'))`).Scan(&exposed))
	require.False(t, exposed)
}
