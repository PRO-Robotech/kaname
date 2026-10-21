// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// emitted_tuple_carries_its_member_integration_test.go — строка реестра
// выпущенного несёт координату своего члена, и держит это база (kaname#933).
//
// Пробы, каждая — сырыми операторами в обход писателя:
//
//  1. НАКАТ на засеянном до него состоянии: строке члена с ТОЧНЫМ совпадением
//     проставлена координата; СИРОТА снята вместе с фактом строкой снятия;
//     строка уровня выдачи осталась с пустой координатой.
//  2. НЕОДНОЗНАЧНО (член с тем же идентификатором, тип модели другой): накат
//     отказывает дословным текстом с числами классов, версия не сдвигается;
//     близнец — та же база без неоднозначной строки — накатывается.
//  3. ПРОВЕРКА на живой схеме: строка члена без координаты, с координатой,
//     несогласной с объектом, и строка уровня выдачи с координатой — отказ по
//     имени ограничения; согласная строка — принята.
//  4. КЛЮЧ: один кортеж от двух координат одной выдачи — две строки.
//  5. ОТКАТ возвращает прежний ключ, дубли схлопнуты; повторный накат проходит.
//
// Испытуемый ищется по содержанию: первая по возрастанию версий миграция, чей
// накат заводит `access_binding_emitted_tuples_member_coordinate`.
package migrations_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// etcConstraint — проверка координаты, по которой опознаётся испытуемый.
const etcConstraint = "access_binding_emitted_tuples_member_coordinate"

func etcReadCatalog(t *testing.T) absCatalog {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций читается")
	var c absCatalog
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): имя миграции %s без версии", name)
		v, err := strconv.ParseInt(prefix, 10, 64)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): версия миграции %s", name)
		c.versions = append(c.versions, v)
		body, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): тело миграции %s", name)
		up := migrations.MigrationUpSection(string(body))
		if strings.Contains(up, "ADD CONSTRAINT "+etcConstraint) && (c.subject == 0 || v < c.subject) {
			c.subject, c.file = v, name
		}
	}
	require.NotEmpty(t, c.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст — судить нечего")
	if c.subject == 0 {
		t.Fatalf("ИСПЫТУЕМОГО НЕТ: в каталоге из %d миграций (голова %d) нет миграции, чей накат заводит %s — "+
			"координату члена строки реестра не держит никто", len(c.versions), c.head(), etcConstraint)
	}
	return c
}

// etcOwnerRole — роль владельца из цепи посева (та же, что берёт absInsertBinding).
const etcOwnerRole = "'rol' || substr(md5('owner'), 1, 17)"

func etcMember(t *testing.T, db *sql.DB, binding, dotted, id string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO kaname.access_binding_target_members
	    (binding_id, role_id, rule_fp, object_type, object_id, verification_status)
	  VALUES ($1, `+etcOwnerRole+`, 'fp933', $2, $3, 'ACTIVE')`, binding, dotted, id)
	require.NoError(t, err, "Дано: член %s:%s", dotted, id)
}

// etcGrant — строка реестра прежней формы и строка журнала, которой выдача её
// выпустила (из неё свёртка кладёт прямой факт).
func etcGrant(t *testing.T, db *sql.DB, binding, user, object, source string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
	  VALUES ($1, $2, 'viewer', $3, $4)`, binding, user, object, source)
	require.NoError(t, err, "Дано: строка реестра %s", object)
	_, err = db.Exec(`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
	  VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', 'viewer', 'object', $2::text), now())`,
		user, object)
	require.NoError(t, err, "Дано: строка журнала %s", object)
}

func etcFacts(t *testing.T, db *sql.DB, user, object string) int {
	t.Helper()
	typ, id, _ := strings.Cut(object, ":")
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.relation_fact
	   WHERE object_type = $1 AND object_id = $2 AND subject = $3`, typ, id, user).Scan(&n))
	return n
}

// etcRows — координаты строк реестра выдачи на объекте, «тип|id» по порядку.
func etcRows(t *testing.T, db *sql.DB, binding, object string) (coords []string) {
	t.Helper()
	rows, err := db.Query(`SELECT member_object_type || '|' || member_object_id FROM kaname.access_binding_emitted_tuples
	   WHERE binding_id = $1 AND object = $2 ORDER BY 1`, binding, object)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		coords = append(coords, s)
	}
	require.NoError(t, rows.Err())
	return coords
}

// etcSeed — выдача с членами compute.instance:iExact и vpc.network:iAmb (если amb),
// строки реестра: точная, сирота, уровня выдачи и (если amb) неоднозначная.
func etcSeed(t *testing.T, db *sql.DB, tag string, amb bool) absBinding {
	t.Helper()
	b := absSeed(t, db, tag)
	absWithSet(t, db, b)
	user := "user:" + b.person
	etcMember(t, db, b.id, "compute.instance", "iExact")
	etcGrant(t, db, b.id, user, "compute_instance:iExact", "member")
	etcGrant(t, db, b.id, user, "compute_instance:iOrphan", "member")
	etcGrant(t, db, b.id, user, "compute_instance:iBinding", "binding")
	if amb {
		etcMember(t, db, b.id, "vpc.network", "iAmb")
		etcGrant(t, db, b.id, user, "compute_instance:iAmb", "member")
	}
	require.Positive(t, etcFacts(t, db, user, "compute_instance:iOrphan"), "ПРЕДПОСЫЛКА: факт сироты сложен свёрткой")
	return b
}

func TestEmittedTupleCoordinate_MigrationAssignsExactAndRevokesOrphans(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := etcReadCatalog(t)
	db := serOpenAt(t, c.preceding())
	b := etcSeed(t, db, "etc9331", false)
	user := "user:" + b.person

	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s", c.file)

	assert.Equal(t, []string{"compute.instance|iExact"}, etcRows(t, db, b.id, "compute_instance:iExact"),
		"точное совпадение: координата проставлена")
	assert.Empty(t, etcRows(t, db, b.id, "compute_instance:iOrphan"), "сирота: строка снята")
	assert.Zero(t, etcFacts(t, db, user, "compute_instance:iOrphan"), "сирота: факт снят строкой снятия — доступ без члена")
	assert.Positive(t, etcFacts(t, db, user, "compute_instance:iExact"), "точное совпадение: факт на месте")
	assert.Equal(t, []string{"|"}, etcRows(t, db, b.id, "compute_instance:iBinding"), "строка уровня выдачи: координата пуста")

	// 4. Ключ: тот же кортеж второй координатой — вторая строка.
	_, err := db.Exec(`INSERT INTO kaname.access_binding_emitted_tuples
	    (binding_id, member_object_type, member_object_id, fga_user, relation, object, source)
	  VALUES ($1, 'compute.server', 'iExact', $2, 'viewer', 'compute_instance:iExact', 'member')`, b.id, user)
	require.NoError(t, err, "кортеж второй координаты принят отдельной строкой")
	assert.Equal(t, []string{"compute.instance|iExact", "compute.server|iExact"}, etcRows(t, db, b.id, "compute_instance:iExact"))

	// 5. Откат: прежний ключ, дубль схлопнут; повторный накат проходит.
	require.NoError(t, goose.DownTo(db, ".", c.preceding()), "откат испытуемого")
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.access_binding_emitted_tuples
	   WHERE binding_id = $1 AND object = 'compute_instance:iExact'`, b.id).Scan(&n))
	assert.Equal(t, 1, n, "откат: строки одного кортежа схлопнуты в одну")
	require.NoError(t, goose.UpTo(db, ".", c.subject), "повторный накат")
	assert.Equal(t, []string{"compute.instance|iExact"}, etcRows(t, db, b.id, "compute_instance:iExact"),
		"повторный накат: координата выведена заново")
}

func TestEmittedTupleCoordinate_AmbiguousRowRefusesTheMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := etcReadCatalog(t)
	db := serOpenAt(t, c.preceding())
	b := etcSeed(t, db, "etc9332", true)

	err := goose.UpTo(db, ".", c.subject)
	require.Error(t, err, "накат на базе с неоднозначной строкой обязан отказать")
	require.Contains(t, err.Error(),
		"реестр выпущенного: строк членов, чью координату не вывести однозначно, — 1 (неоднозначных 1, без двоеточия 0)",
		"текст отказа наката дословно")
	got, verr := goose.GetDBVersion(db)
	require.NoError(t, verr)
	require.Equal(t, c.preceding(), got, "версия не сдвинулась")
	var orphans int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.access_binding_emitted_tuples
	   WHERE binding_id = $1 AND object = 'compute_instance:iOrphan'`, b.id).Scan(&orphans))
	assert.Equal(t, 1, orphans, "откат наката: сирота не снята")

	// Близнец: неоднозначная строка снята — накат проходит.
	_, err = db.Exec(`DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1 AND object = 'compute_instance:iAmb'`, b.id)
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат без неоднозначной строки")
}

func TestEmittedTupleCoordinate_CheckRefusesARowThatDisagreesWithItsObject(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	c := etcReadCatalog(t)
	db := serOpenAt(t, c.preceding())
	b := absSeed(t, db, "etc9333")
	absWithSet(t, db, b)
	require.NoError(t, goose.UpTo(db, ".", c.subject), "накат %s", c.file)
	user := "user:" + b.person
	const q = `INSERT INTO kaname.access_binding_emitted_tuples
	    (binding_id, member_object_type, member_object_id, fga_user, relation, object, source)
	  VALUES ($1, $2, $3, $4, 'viewer', $5, $6)`

	_, err := db.Exec(q, b.id, "compute.instance", "iOk", user, "compute_instance:iOk", "member")
	require.NoError(t, err, "близнец: согласная строка члена принята")
	_, err = db.Exec(q, b.id, "", "", user, "account:etc9333", "binding")
	require.NoError(t, err, "близнец: строка уровня выдачи с пустой координатой принята")

	for _, bad := range []struct{ what, typ, id, object, source string }{
		{"строка члена без координаты", "", "", "compute_instance:iNo", "member"},
		{"координата без типа", "", "iNoType", "compute_instance:iNoType", "member"},
		{"тип без точки", "compute", "iUndotted", "compute_instance:iUndotted", "member"},
		{"идентификатор не тот, что у объекта", "compute.instance", "iOther", "compute_instance:iMismatch", "member"},
		{"объект без двоеточия", "compute.instance", "iNoColon", "iNoColon", "member"},
		{"строка уровня выдачи с координатой", "compute.instance", "iBind", "compute_instance:iBind", "binding"},
	} {
		_, err := db.Exec(q, b.id, bad.typ, bad.id, user, bad.object, bad.source)
		require.Errorf(t, err, "%s: строка принята", bad.what)
		pgErr := pgErrorOf(err)
		require.NotNilf(t, pgErr, "%s: отказ не от базы: %v", bad.what, err)
		assert.Equalf(t, "23514", pgErr.Code, "%s: код отказа (%s)", bad.what, pgErr.Message)
		assert.Equalf(t, etcConstraint, pgErr.ConstraintName, "%s: имя ограничения (%s)", bad.what, pgErr.Message)
	}
}
