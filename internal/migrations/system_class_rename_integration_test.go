// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_class_rename_integration_test.go — переезд подстановки `user:*` на
// системные классы (приёмка anonymous-and-authenticated-are-subject-classes.md,
// отпечаток ae9ba373…0427f51 (редакция 4), сценарии SC-40, SC-42, SC-43, SC-44; задача
// PRO-Robotech/kaname#829).
//
// Посев П2: база поднята цепочкой ствола до его последней миграции
// (`trunkHeadMigration`, ствол bbbe33524), на ней заведены публичный и закрытый
// репозитории тем же писателем журнала, что у продукта; затем накатывается
// остаток цепочки — миграции изменения. Снимок «до» берётся на П2 до наката.
package migrations_test

import (
	"context"
	"database/sql"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// trunkHeadMigration — последняя миграция ствола bbbe33524: граница П2.
const trunkHeadMigration = "20261012120000_address_claimed_ends_the_sessions_of_the_previous_holder.sql"

// scSystemGrant — системная выдача чтения справочников (Р8).
const scSystemGrant = "acbc5d32d66fc8dc4952"

// changeMigrations — миграции дерева новее границы П2, по возрастанию версии.
func changeMigrations(t *testing.T) []int64 {
	t.Helper()
	head, _ := versionsOf(t, trunkHeadMigration)
	require.NotZero(t, head, "граница П2 %s в дереве не найдена — посев П2 не строится", trunkHeadMigration)
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var out []int64
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, perr := strconv.ParseInt(strings.SplitN(e.Name(), "_", 2)[0], 10, 64)
		require.NoError(t, perr, "номер миграции %s", e.Name())
		if v > head {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// scP2 — база П2 и её строка подключения.
type scP2 struct {
	db  *sql.DB
	dsn string
}

func openP2(t *testing.T) scP2 {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	head, _ := versionsOf(t, trunkHeadMigration)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", head), "П2: цепочка ствола до %d", head)
	return scP2{db: db, dsn: dsn}
}

// publish — публикация объекта писателем журнала продукта.
func (p scP2) publish(t *testing.T, object string, published bool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, p.dsn)
	require.NoError(t, err)
	defer func() { _ = conn.Close(ctx) }()
	_, err = conn.Exec(ctx, `SET search_path = kaname, public`)
	require.NoError(t, err)
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	require.NoError(t, fga_outbox.EmitPublicationTx(ctx, tx, published, object,
		pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}), "публикация %s", object)
	require.NoError(t, tx.Commit(ctx))
}

// wildcardCensus — перепись `*` как субъекта в четырёх местах SC-43.
func wildcardCensus(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for place, q := range map[string]string{
		"access_bindings":               `SELECT count(*) FROM kaname.access_bindings WHERE subject_type = 'user' AND subject_id = '*'`,
		"access_binding_subjects":       `SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type = 'user' AND subject_id = '*'`,
		"access_binding_emitted_tuples": `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE fga_user = 'user:*'`,
		"relation_fact":                 `SELECT count(*) FROM kaname.relation_fact WHERE subject = 'user:*'`,
	} {
		var n int
		require.NoError(t, db.QueryRow(q).Scan(&n), "перепись %s", place)
		out[place] = n
	}
	return out
}

func (p scP2) asker(t *testing.T) *relverdict.Asker {
	t.Helper()
	sep := "?"
	if strings.Contains(p.dsn, "?") {
		sep = "&"
	}
	pool, err := pgxpool.New(context.Background(), p.dsn+sep+"options=-c%20search_path%3Dkaname%2Cpublic")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return relverdict.NewAsker(pool)
}

func allowed(t *testing.T, a *relverdict.Asker, subject, objType, objID, relation string) bool {
	t.Helper()
	ok, err := a.Allowed(context.Background(), subject, objType, objID, relation, nil)
	require.NoErrorf(t, err, "вопрос %s %s %s:%s", subject, relation, objType, objID)
	return ok
}

// scSeedPerson — человек ствола для вопросов `user:…`.
func scSeedPerson(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	return serSeedPerson(t, db, tag)
}

// SC-40 — системная выдача чтения справочников переехала на класс
// `authenticated`; id, отношение, системность и защита от удаления прежние.
func TestSystemClass_SC40_SystemGrantMovedToAuthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)
	var st, sid string
	require.NoError(t, p.db.QueryRow(`SELECT subject_type, subject_id FROM kaname.access_bindings WHERE id = $1`, scSystemGrant).Scan(&st, &sid),
		"SC-40 Дано: системная выдача на П2")
	require.Equal(t, []string{"user", "*"}, []string{st, sid}, "SC-40 Дано: до переезда — подстановка")

	require.NoError(t, goose.Up(p.db, "."), "SC-40: накат миграций изменения")
	var rel, scope string
	var system, protected bool
	require.NoError(t, p.db.QueryRow(`
		SELECT subject_type, subject_id, granted_relation, is_system, deletion_protection, resource_type
		  FROM kaname.access_bindings WHERE id = $1`, scSystemGrant).Scan(&st, &sid, &rel, &system, &protected, &scope),
		"SC-40: id выдачи сохранён")
	assert.Equal(t, "system_class", st, "SC-40: вид субъекта")
	assert.Equal(t, "authenticated", sid, "SC-40: имя класса")
	assert.Equal(t, "viewer", rel)
	assert.True(t, system)
	assert.True(t, protected)
	assert.Equal(t, "cluster", scope)
	var subs []string
	rows, err := p.db.Query(`SELECT subject_type || '/' || subject_id FROM kaname.access_binding_subjects WHERE binding_id = $1`, scSystemGrant)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		subs = append(subs, s)
	}
	assert.Equal(t, []string{"system_class/authenticated"}, subs, "SC-40: субъекты выдачи")
}

// SC-42 — публичный репозиторий после переезда прежний: аноним и вошедший
// читают публичный, закрытый закрыт обоим; тот же ответ, что до миграции.
func TestSystemClass_SC42_PublicRepositoryUnchangedAcrossTheMove(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)
	person := "user:" + scSeedPerson(t, p.db, "sc42")
	p.publish(t, "registry_repository:r-pub", true)
	a := p.asker(t)

	// Снимок «до» на П2: публичный читает вошедший (через подстановку).
	beforePub := allowed(t, a, person, "registry_repository", "r-pub", "v_get")
	beforePriv := allowed(t, a, person, "registry_repository", "r-priv", "v_get")
	require.True(t, beforePub, "SC-42 Дано: до переезда вошедший читает публичный")
	require.False(t, beforePriv, "SC-42 Дано: до переезда закрытый закрыт")

	require.NotEmpty(t, changeMigrations(t), "SC-42: миграции переезда в дереве нет")
	require.NoError(t, goose.Up(p.db, "."), "SC-42: накат")
	assert.True(t, allowed(t, a, "system_class:anonymous", "registry_repository", "r-pub", "v_get"), "SC-42: аноним читает публичный")
	assert.Equal(t, beforePub, allowed(t, a, person, "registry_repository", "r-pub", "v_get"), "SC-42: вошедший — как до")
	assert.False(t, allowed(t, a, "system_class:anonymous", "registry_repository", "r-priv", "v_get"), "SC-42: закрытый аноним")
	assert.Equal(t, beforePriv, allowed(t, a, person, "registry_repository", "r-priv", "v_get"), "SC-42: закрытый вошедший — как до")
}

// SC-43 — подстановки как субъекта больше нет: перепись четырёх мест — 0; до
// миграции на П2 — 1, 1, 1 и (1 + публикации).
func TestSystemClass_SC43_WildcardSubjectIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)
	p.publish(t, "registry_repository:r-pub43", true)
	before := wildcardCensus(t, p.db)
	require.Equal(t, map[string]int{
		"access_bindings": 1, "access_binding_subjects": 1, "access_binding_emitted_tuples": 1, "relation_fact": 2,
	}, before, "SC-43 Дано: перепись на П2 до миграции")

	require.NoError(t, goose.Up(p.db, "."), "SC-43: накат")
	assert.Equal(t, map[string]int{
		"access_bindings": 0, "access_binding_subjects": 0, "access_binding_emitted_tuples": 0, "relation_fact": 0,
	}, wildcardCensus(t, p.db), "SC-43: перепись после миграции")
}

// SC-44 — миграция повторно безвредна: повтор шага подъёма (версии изменения
// сняты с учёта goose и накатаны вновь) не меняет состояния SC-40…43.
func TestSystemClass_SC44_MoveMigrationIsRepeatable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)
	p.publish(t, "registry_repository:r-pub44", true)
	change := changeMigrations(t)
	require.NotEmpty(t, change, "SC-44: миграции переезда в дереве нет — повторять нечего")
	require.NoError(t, goose.Up(p.db, "."), "SC-44: первый накат")
	first := wildcardCensus(t, p.db)
	var st1, sid1 string
	require.NoError(t, p.db.QueryRow(`SELECT subject_type, subject_id FROM kaname.access_bindings WHERE id = $1`, scSystemGrant).Scan(&st1, &sid1))

	for _, v := range change {
		_, err := p.db.Exec(`DELETE FROM goose_db_version WHERE version_id = $1`, v)
		require.NoError(t, err, "SC-44: снять версию %d с учёта", v)
	}
	require.NoError(t, goose.Up(p.db, "."), "SC-44: повтор шага подъёма без ошибок")
	assert.Equal(t, first, wildcardCensus(t, p.db), "SC-44: перепись не изменилась")
	var st2, sid2 string
	require.NoError(t, p.db.QueryRow(`SELECT subject_type, subject_id FROM kaname.access_bindings WHERE id = $1`, scSystemGrant).Scan(&st2, &sid2))
	assert.Equal(t, []string{"system_class", "authenticated"}, []string{st2, sid2}, "SC-44: состояние SC-40 после повтора")
	assert.Equal(t, []string{st1, sid1}, []string{st2, sid2})
}
