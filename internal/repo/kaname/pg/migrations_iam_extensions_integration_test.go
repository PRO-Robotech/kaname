// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// migrations_iam_extensions_integration_test.go — интеграционные проверки миграций
// расширений iam через testcontainers Postgres 16.
//
// Проверяемые сценарии:
// - Чистое применение: миграции успешны; schema_migrations записывает базовую версию.
// - Идемпотентный повтор: второй goose.Up ничего не меняет (nil; DDL не повторяется).
// - Цикл Down + Up: откат и повторное применение.
// - Единственная строка clusters: одна строка посеяна; второй INSERT → SQLSTATE 23514.
// - Role нескольких областей: CHECK и частичный UNIQUE на область.
// - У access_bindings есть status / condition_id / expires_at / granted_by_user_id.
//
// Запуск: `go test -tags=integration ./internal/repo/kaname/pg/... -run Kac127 -race`.
// Skip с `-short`.

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// setupKac127TestDB отдаёт вызывающему СОБСТВЕННУЮ базу с полностью прогнанными
// миграциями на общем Postgres пакета. Возвращает *sql.DB, чтобы caller мог
// рантаймно проверять schema (information_schema, pg_constraint, и т.д.).
//
// Раньше на каждый вызов поднимался отдельный контейнер и заново проигрывалась
// вся цепочка. Теперь база клонируется из шаблона, который TestMain смигрировал
// один раз тем же `goose.Up(db, ".")` — состояние то же и изоляция та же (см.
// pkg/pgtest), а контейнер один на пакет.
//
// goose BaseFS/dialect выставляются здесь, а не в телах тестов: они сами зовут
// goose.Up / goose.DownTo на возвращённом *sql.DB и полагаются на эту настройку.
func setupKac127TestDB(t testing.TB) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	return db
}

// ── 6.1.1 — Чистое применение: 0011..0014 успешны; schema_migrations записывает новые версии.
func TestIamExt_Migrations_6_1_1_FreshApply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Объединённая база (0001_initial.sql): вся схема до удаления
	// свёрнута в одну миграцию. Проверяем лишь применение версии 1
	// и наличие начальных артефактов (единственный кластер и системные роли)
	// в схеме.
	var applied bool
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM goose_db_version WHERE version_id = 1 AND is_applied = true)").Scan(&applied))
	assert.True(t, applied, "squashed baseline migration 0001 must be applied")

	// Единственная строка clusters — ровно одна, id = cluster_root.
	var clusterCount int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kaname.clusters").Scan(&clusterCount))
	assert.Equal(t, 1, clusterCount, "exactly one cluster row seeded")

	var clusterID string
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT id FROM kaname.clusters").Scan(&clusterID))
	assert.Equal(t, "cluster_root", clusterID)

	// Две новые системные роли посеяны миграцией 0011.
	var sysRoleCount int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kaname.roles
		 WHERE is_system = true AND cluster_id = 'cluster_root'
		 AND id IN ($1, $2)`, domain.SystemAdminRoleID, domain.SystemViewerRoleID).Scan(&sysRoleCount))
	assert.Equal(t, 2, sysRoleCount, "two new system roles seeded")

	// Проверить наличие ожидаемых таблиц после миграций расширений (выборочная проверка).
	for _, table := range []string{
		"clusters", "cluster_admin_grants",
		"service_account_oauth_clients",
		"audit_outbox",
		"session_revocations",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kaname' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "table kaname.%s must exist", table)
	}

	// Снятые таблицы НЕ должны вернуться.
	//
	// 0065 drops `oidc_jwks_keys` — ПРЕЖНЕЕ хранилище подписных ключей: его
	// единственные писатели умерли вместе с ночной ротацией (713f7e1), а на
	// полностью рабочем стенде оно держало ноль строк, то есть выглядело
	// исправным всю свою жизнь.
	//
	// Здесь стояло «iam не владеет набором ключей (ничего не чеканит)» как ДОВОД в пользу
	// этого удаления. Довод пережил свой предмет и стал прямо ложным: ключница
	// у платформы есть, живёт в `kaname.token_signing_keys` (0001) и читается
	// подписантом. Снятая таблица — не «отсутствие ключницы», а её
	// ПРЕДШЕСТВЕННИК; смешивать их особенно дорого именно здесь, где перечень
	// снятого стоит рядом с живым.
	//
	// 0075 удаляет арендаторскую поверхность условий: таблицу ресурса и
	// наложение на привязку, у которого за всё время существования
	// не было боевого писателя.
	for _, table := range []string{
		"oidc_jwks_keys",
		"conditions",
		"access_binding_conditions",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kaname' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "retired table kaname.%s must be gone", table)
	}

	// Проверить новые колонки расширенных таблиц.
	for _, col := range []struct {
		table, column string
	}{
		{"roles", "cluster_id"},
		{"roles", "project_id"},
		{"access_bindings", "status"},
		{"access_bindings", "expires_at"},
		{"access_bindings", "granted_by_user_id"},
		{"access_bindings", "revoked_at"},
		{"access_bindings", "revoked_by_user_id"},
		// `service_accounts.project_id` из этого списка снят: колонку никто не
		// заполнял, и она ушла вместе с полем контракта (миграция 0071).
		{"service_accounts", "enabled"},
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.columns
			 WHERE table_schema = 'kaname'
			 AND table_name = $1 AND column_name = $2
			)`, col.table, col.column).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "column %s.%s must exist", col.table, col.column)
	}
}

// ── 6.1.2 — Идемпотентный повтор: второй goose.Up возвращает nil, DDL не повторяется.
func TestIamExt_Migrations_6_1_2_IdempotentReapply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Запомнить число кластеров и системных ролей ДО второго up.
	var beforeClusters, beforeRoles int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM kaname.clusters").Scan(&beforeClusters))
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kaname.roles WHERE is_system=true").Scan(&beforeRoles))

	// Второй goose.Up не должен ничего менять.
	require.NoError(t, goose.Up(db, "."))

	var afterClusters, afterRoles int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM kaname.clusters").Scan(&afterClusters))
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kaname.roles WHERE is_system=true").Scan(&afterRoles))

	assert.Equal(t, beforeClusters, afterClusters, "cluster count unchanged after re-apply")
	assert.Equal(t, beforeRoles, afterRoles, "system role count unchanged after re-apply")
}

// ── Цикл Down + Up: откат, затем повторное применение.
//
// Объединённая база (0001_initial.sql) сворачивает всю историю в
// одну миграцию: Down удаляет всю схему kaname, Up
// воссоздаёт её. Поэтому цикл проверяет это однократное
// удаление и воссоздание.
func TestIamExt_Migrations_6_1_RoundTripDownUp(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	// Историческая обратимая цепочка заканчивается до неизменяемой истории установки AW.
	require.NoError(t, goose.UpTo(db, ".", 20261031150000))
	ctx := context.Background()

	// Down до 0 — объединённая база удаляет всю схему kaname.
	require.NoError(t, goose.DownTo(db, ".", 0))

	// Проверить отсутствие таблиц.
	for _, table := range []string{
		"clusters",
		"audit_outbox",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kaname' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.False(t, exists, "table kaname.%s must be gone after Down", table)
	}

	// Снова Up — повторно применить объединённую базу.
	require.NoError(t, goose.UpTo(db, ".", 20261031150000))

	// Проверить возвращение таблиц. oidc_jwks_keys НЕ входит в набор: 0065 снимает её,
	// поэтому полный цикл Down до 0 и Up обязан оставить её удалённой.
	for _, table := range []string{
		"clusters",
		"audit_outbox",
	} {
		var exists bool
		err := db.QueryRowContext(ctx, `
			SELECT EXISTS(
			 SELECT 1 FROM information_schema.tables
			 WHERE table_schema = 'kaname' AND table_name = $1
			)`, table).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "table kaname.%s must be re-created", table)
	}
}

// ── 6.2.1 — Единственная строка clusters: второй INSERT отвергается CHECK.
func TestIamExt_Migrations_6_2_1_ClusterSingleton(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	_, err := db.ExecContext(ctx,
		"INSERT INTO kaname.clusters (id, name) VALUES ('cluster_other', 'other')")
	require.Error(t, err)
	// SQLSTATE 23514 (нарушение CHECK clusters_id_singleton_ck).
	assert.Contains(t, err.Error(), "23514", "expected CHECK violation 23514")

	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT count(*) FROM kaname.clusters").Scan(&count))
	assert.Equal(t, 1, count, "clusters table still has exactly one row")
}

// ── 6.4.4 — Role нескольких областей: две ненулевые колонки области → нарушение CHECK.
func TestIamExt_Migrations_6_4_4_RoleScopeXor_TwoScopesInvalid(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Создаём User → Account → Project (допустимые цели области).
	_, err := db.ExecContext(ctx, `
		INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
		VALUES ('usr_kac127test0001ab', 'ext_kac127_001', 'kac127@test.local', 'acc_kac127test001ab', 'ACTIVE')`)
	// Сначала Account через DEFERRABLE FK.
	// Простой план: INSERT user→account в одной TX с deferred FKs.
	require.Error(t, err, "expected FK violation since accounts not created yet")

	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "SET CONSTRAINTS ALL DEFERRED")
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ('acc_kac127test001ab', 'kac127-test-acc', 'usr_kac127test0001ab')`)
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
		VALUES ('usr_kac127test0001ab', 'ext_kac127_001', 'kac127@test.local', 'acc_kac127test001ab', 'ACTIVE')`)
	require.NoError(t, err)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO kaname.projects (id, account_id, name)
		VALUES ('prj_kac127test001ab', 'acc_kac127test001ab', 'kac127-test-prj')`)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, activewayin.FixtureSQL)
	require.NoError(t, err, "посев строки пароля личности фикстуры (kaname#608)")

	require.NoError(t, tx.Commit())

	// Теперь неверный INSERT: пользовательская роль с двумя ненулевыми областями (account_id + project_id).
	_, err = db.ExecContext(ctx, `
		INSERT INTO kaname.roles
		 (id, account_id, project_id, name, permissions)
		VALUES
		 ('rol_kac127twoscope1', 'acc_kac127test001ab', 'prj_kac127test001ab',
		 'invalid_two_scope', '["compute.instance.*.read"]'::jsonb)`)
	require.Error(t, err, "expected CHECK violation roles_definition_tier_xor")
	assert.Contains(t, err.Error(), "23514", "expected CHECK violation 23514")
	assert.Contains(t, strings.ToLower(err.Error()), "roles_definition_tier_xor",
		"expected violation на constraint roles_definition_tier_xor (renamed from roles_scope_xor in 0056)")

	// Valid project-scoped role работает.
	_, err = db.ExecContext(ctx, `
		INSERT INTO kaname.roles
		 (id, project_id, name, permissions)
		VALUES
		 ('rol_kac127prj00001a', 'prj_kac127test001ab',
		 'deployer', '["compute.instance.*.read","compute.instance.*.list"]'::jsonb)`)
	require.NoError(t, err, "valid project-scoped role insert must succeed")
}

// ── 6.5.0 — Обратная совместимость: старые access_bindings получают status='ACTIVE' по умолчанию.
func TestIamExt_Migrations_6_5_0_AccessBindingStatusDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupKac127TestDB(t)
	ctx := context.Background()

	// Проверяем что колонка status существует с NOT NULL + DEFAULT 'ACTIVE'.
	var isNullable, columnDefault string
	err := db.QueryRowContext(ctx, `
		SELECT is_nullable, COALESCE(column_default, '')
		 FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'access_bindings' AND column_name = 'status'
	`).Scan(&isNullable, &columnDefault)
	require.NoError(t, err)
	assert.Equal(t, "NO", isNullable, "access_bindings.status must be NOT NULL")
	assert.Contains(t, columnDefault, "ACTIVE", "default must be 'ACTIVE'")
}

// Проверки CHECK допустимости JIT удалены: таблица access_bindings_jit_eligibility
// удалена вместе с конвейером JIT.
