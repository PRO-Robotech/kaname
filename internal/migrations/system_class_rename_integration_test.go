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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
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

// publish — публикация объекта В ФОРМЕ СТВОЛА: строка журнала, которую клал
// писатель публикации на `bbbe33524`, — кортеж `user:* #v_get` с версией
// владельца. Писатель головы ветки для П2 не годится: он кладёт уже хранимого
// субъекта класса (`domain.PublicationSubject`), и «до переезда» описывало бы
// базу, которой на стволе не было.
func (p scP2) publish(t *testing.T, object string, published bool) {
	t.Helper()
	event := "fga.tuple.delete"
	if published {
		event = "fga.tuple.write"
	}
	_, err := p.db.Exec(`
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ($1, jsonb_build_object('user', 'user:*', 'relation', 'v_get',
		                               'object', $2::text, 'source_version', '-infinity'::timestamptz),
		        now())`, event, object)
	require.NoError(t, err, "публикация %s в форме ствола", object)
}

// trunkPublicRead — ответ СТВОЛА на чтение объекта вошедшим: на стволе форма
// вердикта добавляла подстановку всякому говорящему, поэтому объект читался
// ровно тогда, когда на нём стоял факт `user:* #v_get`. Голова ветки этой
// подстановки уже не добавляет, и спросить её о базе П2 значило бы получить
// ответ, которого ствол не давал.
func trunkPublicRead(t *testing.T, db *sql.DB, objType, objID string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = 'v_get' AND subject = 'user:*'`,
		objType, objID).Scan(&n))
	return n > 0
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

	// Снимок «до» на П2 — ответ ствола: публичный читает вошедший (через
	// подстановку).
	beforePub := trunkPublicRead(t, p.db, "registry_repository", "r-pub")
	beforePriv := trunkPublicRead(t, p.db, "registry_repository", "r-priv")
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

// CE-21 — переезд не знает написания якоря кластера: на установке, где якорь
// переписан (`kaname.rename_cluster_anchor`), системная выдача и её факты
// переезжают так же, как на П2 (близнец — SC-40/SC-43 на якоре как есть).
// Предикат с литералом якоря переписал бы здесь ноль строк и прошёл молча.
func TestSystemClass_CE21_MoveFollowsARenamedClusterAnchor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	p := openP2(t)
	var anchor string
	require.NoError(t, p.db.QueryRow(`SELECT kaname.cluster_anchor()`).Scan(&anchor), "якорь П2")
	const renamed = "cluster_ce21_elsewhere"
	_, err := p.db.Exec(`SELECT * FROM kaname.rename_cluster_anchor($1, $2)`, anchor, renamed)
	require.NoError(t, err, "CE-21 Дано: якорь переписан объявленным переписчиком")
	require.Equal(t, map[string]int{
		"access_bindings": 1, "access_binding_subjects": 1, "access_binding_emitted_tuples": 1, "relation_fact": 1,
	}, wildcardCensus(t, p.db), "CE-21 Дано: подстановка стоит на переписанном якоре")

	require.NoError(t, goose.Up(p.db, "."), "CE-21: накат")
	assert.Equal(t, map[string]int{
		"access_bindings": 0, "access_binding_subjects": 0, "access_binding_emitted_tuples": 0, "relation_fact": 0,
	}, wildcardCensus(t, p.db), "CE-21: подстановки не осталось")
	var facts int
	require.NoError(t, p.db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'cluster' AND object_id = $1 AND relation = 'viewer'
		   AND subject = 'system_class:authenticated'`, renamed).Scan(&facts))
	assert.Equal(t, 1, facts, "CE-21: факт чтения справочников переехал на класс на переписанном якоре")
	var st, sid, rid string
	require.NoError(t, p.db.QueryRow(`SELECT subject_type, subject_id, resource_id FROM kaname.access_bindings WHERE id = $1`,
		scSystemGrant).Scan(&st, &sid, &rid))
	assert.Equal(t, []string{"system_class", "authenticated", renamed}, []string{st, sid, rid}, "CE-21: системная выдача")
}
