// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Каждый переход выполняет настоящий Goose provider в своей транзакции.
// SQL секции не копируются; ручной установки compiler или смены phase нет.
func TestResourcePublicCutoverGooseRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	const baseline int64 = 20261114100000
	const cutover int64 = 20261114130000
	_, err = provider.UpTo(ctx, baseline)
	require.NoError(t, err)
	// Существующий обычный профиль доступа должен точно пережить Up/Down.
	role := "resource_cutover_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{role}.Sanitize()
	password := ids.NewID("pwd")
	_, err = db.ExecContext(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = db.ExecContext(cleanup, "DROP OWNED BY "+quoted)
		_, _ = db.ExecContext(cleanup, "DROP ROLE "+quoted)
	})
	_, err = db.ExecContext(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, role)
	require.NoError(t, err)
	before := resourceCutoverSchemaState(t, ctx, db)
	up, err := provider.UpTo(ctx, cutover)
	require.NoError(t, err)
	require.Len(t, up, 3, "1100 private mapping, прежняя1200, полная1300")
	resourceCutoverStorageReady(t, ctx, db)
	for _, version := range []int64{cutover, 20261114120000, 20261114110000} {
		down, downErr := provider.Down(ctx)
		require.NoError(t, downErr)
		require.Equal(t, version, down.Source.Version)
	}
	actual, err := provider.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, baseline, actual)
	after := resourceCutoverSchemaState(t, ctx, db)
	require.JSONEq(t, string(before), string(after), "Восстановлены прежние функции, ACL, triggers, indexes и authority state; epochs не сброшены")
	var clean bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT
 to_regclass('kaname.authority_producer_population_latch') IS NULL AND
 to_regclass('kaname.authority_producer_acl_restore_v2') IS NULL AND
 to_regprocedure('kaname.authority_resource_prewait_v2(jsonb,integer,integer)') IS NULL AND
 to_regprocedure('kaname._authority_resource_module_identity_v2(text,text,text)') IS NULL AND
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgname='authority_resource_effect_applied')`).Scan(&clean))
	require.True(t, clean)
	reup, err := provider.UpTo(ctx, cutover)
	require.NoError(t, err)
	require.Len(t, reup, 3)
	resourceCutoverStorageReady(t, ctx, db)
	// Goose не должен менять semantic phase или enforcement.
	var phase, enforcement string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT a.phase,p.enforcement FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &enforcement))
	require.Equal(t, "uninitialized", phase)
	require.Equal(t, "compatibility", enforcement)
}

func resourceCutoverStorageReady(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	var ready bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&ready))
	require.True(t, ready)
}

// Сравниваются все прежние функции, включая тело и OID. ACL сохраняет owner,
// grantor, grantee и grant-option; игнорируется только порядок aclitem.
// Журнал версий Goose не является бизнес-состоянием и исключён.
func resourceCutoverSchemaState(t *testing.T, ctx context.Context, db *sql.DB) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object(
 'functions',(SELECT coalesce(jsonb_agg(jsonb_build_object(
  'identity',p.oid::regprocedure::text,'oid',p.oid,'owner',p.proowner,'body',p.prosrc,
  'config',p.proconfig,'security_definer',p.prosecdef,'volatility',p.provolatile,
  'strict',p.proisstrict,'returns',p.prorettype,'language',p.prolang,
  'acl',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY grantor,grantee,privilege_type,is_grantable),'[]') FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a)
 ) ORDER BY p.oid),'[]') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname'),
 'relations',(SELECT coalesce(jsonb_agg(jsonb_build_object(
  'name',c.relname,'kind',c.relkind,'owner',c.relowner,
  'acl',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY grantor,grantee,privilege_type,is_grantable),'[]') FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a)
 ) ORDER BY c.relname),'[]') FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p','v','m','f','S') AND c.relname<>'goose_db_version'),
 'triggers',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname),'[]') FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND NOT t.tgisinternal),
 'indexes',(SELECT coalesce(jsonb_agg(indexdef ORDER BY indexname),'[]') FROM pg_catalog.pg_indexes WHERE schemaname='kaname' AND tablename<>'goose_db_version'),
 'protocol',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_writer_protocol x),
 'identity',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_semantic_identity x),
 'policy_epochs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY key),'[]') FROM kaname.authority_policy_epoch x),
 'binding_epochs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY scope),'[]') FROM kaname.authority_binding_epoch x)
 )`).Scan(&raw))
	return raw
}
