// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

const mirrorUpdateABI = "resource-metadata-update/v1"
const mirrorGrant = "kaname._authority_metadata_mirror_grant_v1(regrole)"
const mirrorDiscover = "kaname.authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)"

var mirrorExports = []string{
	"kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)",
	mirrorDiscover,
	"kaname.authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)",
	"kaname.authority_metadata_mirror_ordinary_accept_v1(text,text)",
	"kaname.authority_metadata_mirror_apply_v1(text,text)",
	"kaname.authority_metadata_mirror_update_ready_v1(text)",
}

func TestExternalMetadataUpdateReadinessRequiresInstalledPrivileges(t *testing.T) {
	r := writerProtocolRig(t)
	role := pgx.Identifier{r.role}.Sanitize()
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := r.admin.Exec(r.ctx, sql, args...)
		require.NoError(t, err)
	}
	read := func(version string) bool {
		t.Helper()
		var installed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, "SELECT kaname.authority_metadata_mirror_update_ready_v1($1)", version).Scan(&installed))
		return installed
	}
	native := func() {
		t.Helper()
		var installed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, "SELECT kaname.authority_metadata_access_label_ready_v2('metadata-access-label/owner-retention-v2')").Scan(&installed))
		require.True(t, installed)
	}

	require.True(t, read(mirrorUpdateABI), "штатная установка на новом LOGIN")
	require.False(t, read("resource-metadata-update/unknown"))
	var private bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='kaname'
 AND (starts_with(p.proname,'_authority_metadata_mirror_') OR p.proname='authority_metadata_mirror_write_v1')
 AND has_function_privilege(current_user,p.oid,'EXECUTE'))`).Scan(&private))
	require.False(t, private)
	const complete = "kaname._authority_metadata_mirror_ordinary_complete_v1()"
	exec("GRANT EXECUTE ON FUNCTION " + complete + " TO " + role)
	require.False(t, read(mirrorUpdateABI))
	exec("REVOKE EXECUTE ON FUNCTION " + complete + " FROM " + role)
	require.True(t, read(mirrorUpdateABI))
	exec("REVOKE EXECUTE ON FUNCTION " + mirrorDiscover + " FROM " + role)
	native()
	require.False(t, read(mirrorUpdateABI))
	exec("SELECT kaname.authority_protocol_grant_runtime($1::regrole)", r.role)
	require.True(t, read(mirrorUpdateABI))
	exec("SELECT kaname.authority_protocol_grant_runtime($1::regrole)", r.role)
	require.True(t, read(mirrorUpdateABI))
}

func TestExternalMetadataRuntimeExecuteBackfillAndRollback(t *testing.T) {
	r := writerProtocolRig(t)
	actor, _, _ := roleActorFiniteLogin(t, r)
	// Отдельное подключение role writer не получает даже фасад готовности.
	var actorExecute bool
	require.NoError(t, actor.QueryRow(r.ctx, `SELECT bool_or(has_function_privilege(current_user,s,'EXECUTE'))
 FROM unnest($1::text[]) AS s`, mirrorExports).Scan(&actorExecute))
	require.False(t, actorExecute)

	const version int64 = 20261126120000
	db := stdlib.OpenDB(*r.admin.Config().ConnConfig)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	latest, err := provider.GetDBVersion(r.ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, latest, version)
	t.Cleanup(func() {
		_, err := provider.UpTo(r.ctx, latest)
		require.NoError(t, err)
	})

	// Каждый шаг миграции выполняет drain в своей свежей транзакции.
	_, err = provider.DownTo(r.ctx, version)
	require.NoError(t, err)
	exec := func(sql string) {
		t.Helper()
		_, err := r.admin.Exec(r.ctx, sql)
		require.NoError(t, err)
	}
	count := func(role string) int {
		t.Helper()
		var grants int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM unnest($2::text[]) f
 JOIN pg_catalog.pg_proc p ON p.oid=f::regprocedure CROSS JOIN LATERAL aclexplode(p.proacl) a
 WHERE a.grantee=$1::regrole AND a.privilege_type='EXECUTE' AND NOT a.is_grantable`, role, mirrorExports).Scan(&grants))
		return grants
	}
	actorName := actor.Config().ConnConfig.User
	require.Len(t, mirrorExports, 6)
	require.Equal(t, len(mirrorExports), count(r.role))
	removedMigration, err := provider.Down(r.ctx)
	require.NoError(t, err)
	require.Equal(t, version, removedMigration.Source.Version)
	require.Zero(t, count(r.role))
	var removed, valid bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_regprocedure($1) IS NULL,kaname._authority_full_contract_storage_v3()`, mirrorGrant).Scan(&removed, &valid))
	require.True(t, removed)
	require.True(t, valid)

	quoted := pgx.Identifier{r.role}.Sanitize()
	exec("REVOKE UPDATE ON kaname.operations FROM " + quoted)
	exec("ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO " + quoted)
	t.Cleanup(func() {
		exec("ALTER DEFAULT PRIVILEGES IN SCHEMA kaname REVOKE EXECUTE ON FUNCTIONS FROM " + quoted)
	})
	installed, err := provider.UpTo(r.ctx, version)
	require.NoError(t, err)
	require.Len(t, installed, 1)
	require.Equal(t, version, installed[0].Source.Version)
	require.Equal(t, len(mirrorExports), count(r.role))
	require.Zero(t, count(actorName))
	var tableWrite, grantHelper bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 has_table_privilege($1::name,'kaname.operations','UPDATE'),
 has_function_privilege($1::name,$2,'EXECUTE'),kaname._authority_full_contract_storage_v3()`,
		r.role, mirrorGrant).Scan(&tableWrite, &grantHelper, &valid))
	require.False(t, tableWrite, "обновление ACL не восстанавливает отозванный DML")
	require.False(t, grantHelper)
	require.True(t, valid)
}
