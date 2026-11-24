// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/migratorrun"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// Не parallel: production migrator использует глобальную настройку Goose.
// Исходная база совпадает с прежним D1200: удалены только два НОВЫХ файла,
// все прежние SQL-байты переданы provider без редактирования.
func TestResourcePublicCutoverUpgradesExisting1200(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	const prerequisite = "20261114110000_resource_compilers_bind_module_identity.sql"
	const cutover = "20261114130000_resource_decisions_compile_before_clock.sql"
	prior := fstest.MapFS{}
	names, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	omitted := 0
	var appendedVersions []int64
	for _, name := range names {
		raw, readErr := migrations.FS.ReadFile(name)
		require.NoError(t, readErr)
		versionText, _, hasSeparator := strings.Cut(name, "_")
		require.True(t, hasSeparator, "имя миграции содержит числовую версию: %s", name)
		migrationVersion, parseErr := strconv.ParseInt(versionText, 10, 64)
		require.NoError(t, parseErr)
		if migrationVersion > 20261114120000 || name == prerequisite {
			appendedVersions = append(appendedVersions, migrationVersion)
		}
		if name == prerequisite || name == cutover {
			omitted++
			continue
		}
		prior[name] = &fstest.MapFile{Data: raw}
	}
	require.Equal(t, 2, omitted, "исключены ровно новые1100/1300")
	initial, err := goose.NewProvider(goose.DialectPostgres, db, prior,
		goose.WithTableName("public.goose_db_version"))
	require.NoError(t, err)
	_, err = initial.UpTo(ctx, 20261114120000)
	require.NoError(t, err)
	version, err := initial.GetDBVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(20261114120000), version)
	var absent bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT
 to_regprocedure('kaname._authority_resource_module_identity_v2(text,text,text)') IS NULL AND
 to_regprocedure('kaname.authority_resource_prewait_v2(jsonb,integer,integer)') IS NULL AND
 NOT EXISTS(SELECT 1 FROM public.goose_db_version WHERE version_id IN (20261114110000,20261114130000))`).Scan(&absent))
	require.True(t, absent, "предпосылка: старый1200 ещё не содержит Resource cutover")
	// Настоящее существующее состояние: tenant rows и законно активированный
	// текущий bundle. Ни phase, ни enforcement вручную не изменяются.
	pool, err := coredb.NewPool(ctx, pgtest.WithSearchPath(dsn, "kaname,public"))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	// Старый runtime создаётся ДО upgrade и получает только прежний1200 profile.
	role := "resource_existing_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{role}.Sanitize()
	password := ids.NewID("pwd")
	_, err = db.ExecContext(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, cleanupErr := db.ExecContext(cleanup, "DROP OWNED BY "+quoted)
		require.NoError(t, cleanupErr, "очистка grants старого runtime")
		_, cleanupErr = db.ExecContext(cleanup, "DROP ROLE "+quoted)
		require.NoError(t, cleanupErr, "удаление старого runtime LOGIN")
	})
	_, err = db.ExecContext(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, role)
	require.NoError(t, err)
	kac127SeedUserAndAccount(t, ctx, pool, "upgrade1200")
	bundle := semanticBundleDB(t, ctx, pool)
	owner := kanamepg.New(pool, nil)
	require.NoError(t, owner.StageAuthorityBundle(ctx, bundle))
	require.NoError(t, owner.ActivateAuthorityBundle(ctx, bundle))
	before := resourceExisting1200State(t, ctx, db)
	var oldHistory json.RawMessage
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM public.goose_db_version v`).Scan(&oldHistory))
	// Этот exact production executor сам выбирает WithAllowMissing. Тест не
	// подставляет её как собственную опцию и не переписывает таблицу версий.
	runner, err := migratorrun.New(migratorrun.Config{Service: "kaname", Dialect: "postgres", DSN: dsn, FS: migrations.FS, MigrationsDir: "."})
	require.NoError(t, err)
	require.NoError(t, runner.Up(ctx, ""))
	require.NoError(t, runner.Up(ctx, ""), "повторный production upgrade идемпотентен")
	var ready bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&ready))
	require.True(t, ready)
	// Никаких новых GRANT после upgrade: проверяется тот же настоящий LOGIN.
	cfg := pool.Config()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = password
	cfg.AfterConnect = nil
	runtime, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, runtime)
	var effective, session string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, role, effective)
	require.Equal(t, role, session)
	var elevated bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit OR has_schema_privilege(current_user,'kaname','CREATE') FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&elevated))
	require.False(t, elevated)
	require.NoError(t, runtime.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&ready))
	require.True(t, ready, "readiness доступна прежнему runtime LOGIN")
	// Реальный preclock population read тем же старым LOGIN, без новых GRANT.
	var populationGeneration, populationRevision string
	var populationRows int
	require.NoError(t, runtime.QueryRow(ctx, `SELECT generation,row_count,revision_sum FROM kaname.authority_policy_population_read(100000)`).Scan(&populationGeneration, &populationRows, &populationRevision))
	require.NotEmpty(t, populationGeneration)
	require.Positive(t, populationRows)
	require.NotEmpty(t, populationRevision)
	for _, signature := range []string{
		"authority_resource_storage_v2(jsonb)",
		"authority_policy_population_read(integer)",
		"authority_resource_enter_v2(text,text[],jsonb,text,text,text)",
		"authority_resource_source_enter_v2(text,text[],jsonb,text,text,text)",
		"authority_resource_prewait_v2(jsonb,integer,integer)",
		"authority_resource_finalize_v2(jsonb,integer,integer)",
		"authority_resource_assert_body_v2(jsonb)",
		"authority_resource_object_body_values_v2()",
		"authority_resource_object_step_v2(integer)",
		"authority_resource_registration_body_values_v2()",
		"authority_resource_registration_step_v2(integer)",
		"authority_resource_registration_command_values_v2(jsonb)",
	} {
		var allowed bool
		require.NoError(t, runtime.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.'||$1,'EXECUTE')`, signature).Scan(&allowed))
		require.True(t, allowed, "публичная функция %s", signature)
	}
	for _, signature := range []string{
		"_authority_resource_object_prepare_v2(jsonb,integer,integer)",
		"_authority_resource_registration_prepare_v2(jsonb,integer,integer)",
		"_authority_resource_registration_direct_prepare_v2(jsonb,integer,integer)",
		"_authority_resource_unregistration_prepare_v2(jsonb,integer,integer)",
		"_authority_resource_refusal_prepare_v2(jsonb,integer,integer)",
	} {
		var allowed bool
		require.NoError(t, runtime.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.'||$1,'EXECUTE')`, signature).Scan(&allowed))
		require.False(t, allowed, "private compiler %s остаётся закрытым", signature)
	}
	// Новая колонка не включает прежние ресурсы в пользовательскую регистрацию.
	// Нормализуем проверенное добавление NULL и сравниваем все остальные поля
	// и строки с состоянием до миграций.
	var after map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resourceExisting1200State(t, ctx, db), &after))
	var resources []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(after["catalog_resources"], &resources))
	require.NotEmpty(t, resources)
	for _, resource := range resources {
		require.Contains(t, resource, "child_registration", "upgrade добавил колонку политики")
		require.JSONEq(t, "null", string(resource["child_registration"]), "прежний ресурс не получил неявный opt-in")
		delete(resource, "child_registration")
	}
	after["catalog_resources"], err = json.Marshal(resources)
	require.NoError(t, err)
	normalizedAfter, err := json.Marshal(after)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(normalizedAfter), "tenant/catalog/bundle/phase/epochs сохранены без повторного seed/reset")
	var retainedHistory json.RawMessage
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)
 FROM public.goose_db_version v
 WHERE v.id IN (SELECT (old.entry->>'id')::bigint
                FROM jsonb_array_elements($1::jsonb) AS old(entry))`, string(oldHistory)).Scan(&retainedHistory))
	require.JSONEq(t, string(oldHistory), string(retainedHistory), "старые записи Goose не перенумерованы и не переписаны")
	// Старые строки сравниваются целиком по прежним ID; новые — по замкнутому
	// перечню версий реального FS. Последующие append не превращаются в «старые».
	var appendedRows int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*)
 FROM public.goose_db_version v
 WHERE v.id NOT IN (SELECT (old.entry->>'id')::bigint
                    FROM jsonb_array_elements($1::jsonb) AS old(entry))`, string(oldHistory)).Scan(&appendedRows))
	require.Equal(t, len(appendedVersions), appendedRows, "нет пропущенных, повторных или посторонних новых записей Goose")
	requiredVersions := append([]int64{20261114120000}, appendedVersions...)
	for _, v := range requiredVersions {
		var count int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM public.goose_db_version WHERE version_id=$1 AND is_applied`, v).Scan(&count))
		require.Equal(t, 1, count, "ровно одна применённая запись версии%d", v)
	}
	var phase, enforcement string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT a.phase,p.enforcement FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &enforcement))
	require.Equal(t, "active", phase)
	require.Equal(t, "strict", enforcement)
}

func resourceExisting1200State(t *testing.T, ctx context.Context, db *sql.DB) json.RawMessage {
	t.Helper()
	var raw json.RawMessage
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object(
 'accounts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.accounts x),
 'users',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.users x),
 'catalog_modules',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.catalog_module x),
 'catalog_resources',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.catalog_resource x),
 'catalog_verbs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]') FROM kaname.catalog_verb x),
 'protocol',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_writer_protocol x),
 'identity',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_semantic_identity x),
 'handoff',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.authority_bundle_handoff x),
 'policy_epochs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY key),'[]') FROM kaname.authority_policy_epoch x),
 'binding_epochs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY scope),'[]') FROM kaname.authority_binding_epoch x)
 )`).Scan(&raw))
	return raw
}
