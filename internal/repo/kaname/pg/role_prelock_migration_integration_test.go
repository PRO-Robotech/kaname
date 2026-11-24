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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Номер выводится из фактической embedded цепи, без арифметики timestamp и
// предположения о непрерывной нумерации исторических миграций.
func rolePrelockMigrationDB(t *testing.T, r protocolRig) (*sql.DB, int64, int64) {
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
		if strings.HasSuffix(entry.Name(), "_role_prelock_admission_before_catalog_locks.sql") {
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

func rolePrelockFunctionState(t *testing.T, r protocolRig) string {
	t.Helper()
	var state string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_object(
  'name',p.proname,'definition',pg_get_functiondef(p.oid),'acl',p.proacl,'owner',p.proowner)
  ORDER BY p.proname)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='kaname' AND p.proname IN ('authority_role_prelock_admit_v3',
  '_authority_full_contract_storage_v3','authority_protocol_grant_runtime','authority_protocol_attestation')`).Scan(&state))
	return state
}

func rolePrelockMigrationPrivateACL(t *testing.T, r protocolRig) {
	t.Helper()
	var private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
  'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&private))
	require.False(t, private, "Down/Up не выдаёт LOGIN private verifier")
}

func TestRolePrelockMigrationGooseRoundTripRestoresExactPreviousContract(t *testing.T) {
	r, role := rolePrelockRig(t)
	db, own, previous := rolePrelockMigrationDB(t, r)
	before := rolePrelockFunctionState(t, r)
	rolePrelockMigrationPrivateACL(t, r)
	// Даже при раннем Fatal база возвращается к текущей цепи до cleanup фикстуры.
	t.Cleanup(func() { require.NoError(t, goose.UpTo(db, ".", own)) })
	require.NoError(t, goose.Down(db, "."), "настоящий Goose Down, не ручное исполнение его SQL")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version)
	var absent bool
	var readiness, grants string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
  to_regprocedure('kaname.authority_role_prelock_admit_v3()') IS NULL,
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname._authority_full_contract_storage_v3()'::regprocedure),
  (SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='kaname.authority_protocol_grant_runtime(regrole)'::regprocedure)`).Scan(&absent, &readiness, &grants))
	require.True(t, absent)
	// Точные prosrc предыдущих 23 pins и wrapper из последних SOURCE миграций.
	require.Equal(t, "ea0aac88263eb6f0f3afa6af05274331ea1d17387259c98d3d7f7a93233c5d82", readiness)
	require.Equal(t, "7482da00ae6ff53c668825c90dec5cfbadd8446d65c94a94ef9ccfc95ef8298a", grants)
	rolePrelockMigrationPrivateACL(t, r)
	var ready bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "предыдущая цепь 23 pins действительно работоспособна")
	require.NoError(t, goose.UpTo(db, ".", own))
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version)
	require.Equal(t, before, rolePrelockFunctionState(t, r), "Up восстановил definition/owner/ACL всех четырёх entry функций")
	rolePrelockMigrationPrivateACL(t, r)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
	require.True(t, ready, "текущая цепь 24 pins восстановлена")
	for _, method := range []string{"module", "selectors", "regrain"} {
		w, err := r.repo.Writer(r.ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = w.Rollback(r.ctx) })
		require.NoError(t, rolePrelockCall(r.ctx, w, method, role), "реальный LOGIN port после Goose Up: %s", method)
		require.NoError(t, w.Rollback(r.ctx))
	}
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivateBeforePublication(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

// Снимок включает реальный Goose ledger, authority rows и описание schema/ACL;
// отказ Down должен откатить всю попытку миграции, а не только оставить helper.
func rolePrelockMigrationSnapshot(t *testing.T, r protocolRig) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
  'ledger',(SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v),
  'protocol',(SELECT jsonb_agg(to_jsonb(v)) FROM kaname.authority_writer_protocol v),
  'contract',(SELECT jsonb_agg(to_jsonb(v)) FROM kaname.authority_writer_contract v),
  'identity',(SELECT jsonb_agg(to_jsonb(v)) FROM kaname.authority_semantic_identity v),
  'handoff',(SELECT jsonb_agg(to_jsonb(v)) FROM kaname.authority_bundle_handoff v),
  'functions',(SELECT jsonb_agg(to_jsonb(p) ORDER BY p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname'),
  'relations',(SELECT jsonb_agg(jsonb_build_object('oid',c.oid,'name',c.relname,'namespace',c.relnamespace,'owner',c.relowner,'kind',c.relkind,'persistence',c.relpersistence,'acl',c.relacl,'options',c.reloptions,'rowsecurity',c.relrowsecurity,'forcerowsecurity',c.relforcerowsecurity,'partition',c.relispartition) ORDER BY c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname'),
  'columns',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.attrelid,a.attnum) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname'),
  'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='kaname'),
  'triggers',(SELECT jsonb_agg(to_jsonb(t) ORDER BY t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname')
 )::text`).Scan(&snapshot))
	return snapshot
}

func TestRolePrelockMigrationGooseDownRefusesActiveFullWithoutChanges(t *testing.T) {
	r, _ := rolePrelockRig(t)
	db, own, _ := rolePrelockMigrationDB(t, r)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivateBeforePublication(t, r)
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
	rolePrelockMigrationPrivateACL(t, r)
	require.NoError(t, full.ValidateFullAuthorityBundle(r.ctx, r.bundle))
}
