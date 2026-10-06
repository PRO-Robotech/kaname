// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authz_rev_fenced_tables_integration_test.go — колонка версии прав `authz_rev`
// на таблицах, которые читает вопрос об аудитории с оградой (приёмка NTF-3,
// kacho#2918, Р30 «Колонка версии прав», редакция 39; сценарии NTF3-181 (б),
// NTF3-183 в части базы; решения Д133, Д134; полоса K1).
//
// # Предмет
//
// Каждая таблица исходных строк прав несёт `authz_rev xid8` — идентификатор
// транзакции, последней ИЗМЕНИВШЕЙ ПРАВО этой строки. Ставит его триггер
// `BEFORE INSERT OR UPDATE`, а не умолчание столбца: на INSERT — всегда, в том
// числе поверх явного значения; на UPDATE — только если `NEW IS DISTINCT FROM
// OLD` по значимым столбцам строки права, иначе `OLD.authz_rev` остаётся.
//
// # Чего эти пробы НЕ утверждают
//
// Ни вопроса об аудитории (полоса Resolve), ни гейта совпадения множеств
// (`internal/repohygiene`, NTF3-180): здесь — только поведение строки под
// записью, и порядок версий под конкурирующими транзакциями.
//
// # Порядок внутри каждой пробы несущий
//
// Сначала фикстура доказывает своё (строка посеяна, правка взяла ровно одну
// строку, значимое значение действительно сменилось), потом спрашивается
// предмет. Обратный порядок дал бы сломанной фикстуре выдать себя за
// отсутствующую колонку.
//
// # Значимые и служебные столбцы — откуда взяты
//
// Значимые — дословно из Р30 («у привязки — роль, область, выбор объектов,
// субъект, статус, срок; у роли — её глаголы и правила сужения; у членства —
// группа и член; у кортежа — объект, отношение, субъект, условие»); у таблиц
// меток видов iam значимы метки (ось меток `relverdict/labelaxis.go`).
// Служебные — `updated_at` (Р30 называет его прямо) и столбцы, которые права не
// определяют: момент добавления члена, порядковый номер субъекта, время
// записи факта, защита от удаления привязки, описание объекта iam. Выбор
// служебных столбцов — толкование Р30 полосой RED, вынесенное в возврат.
package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Идентификаторы мира пробы: приставка `arv` (authz_rev), отличимая от любого
// посева миграций.
const (
	arvAccount  = "accarvprobe0000001"
	arvOwner    = "usrarvprobeowner01"
	arvMember   = "usrarvprobemember1"
	arvProject  = "prjarvprobe0000001"
	arvGroup    = "grparvprobe0000001"
	arvSA       = "svaarvprobe0000001"
	arvRole     = "rolarvprobe0000001"
	arvBinding  = "acbarvprobe0000001"
	arvFactObj  = "netarvprobe0000001"
	arvRuleFP   = "fp-arv-probe-1"
	arvRuleFP2  = "fp-arv-probe-2"
	arvClusterR = "cluster_root"
)

// fencedRow — одна таблица вопроса с оградой и её строка в мире пробы.
type fencedRow struct {
	// table — полное имя таблицы.
	table string
	// where — отбор строки пробы (ровно одна строка).
	where string
	// significant — SET, меняющий значимый столбец строки права.
	significant string
	// insignificant — SET, меняющий ТОЛЬКО служебный столбец ("" — у таблицы
	// служебного столбца нет).
	insignificant string
	// noop — SET, переписывающий строку тем же содержимым.
	noop string
	// explicitInsert — вставка ВТОРОЙ строки с явным `authz_rev`, и её отбор.
	explicitInsert, explicitWhere string
}

// fencedRows — перепись таблиц полосы K1 (задание полосы и Р30): привязка и
// её субъекты, глаголы роли, правила сужения роли, членство, факты, таблицы
// меток собственных видов iam.
func fencedRows(t *testing.T, ctx context.Context, db *sql.DB) []fencedRow {
	t.Helper()
	objType, verb := liveRoleVerbPair(t, ctx, db)
	secondType := liveCatalogTypes(t, ctx, db)[1]
	return []fencedRow{
		{
			table:         "kaname.access_bindings",
			where:         "id = '" + arvBinding + "'",
			significant:   "expires_at = now() + interval '30 days'",
			insignificant: "deletion_protection = NOT deletion_protection",
			noop:          "status = status, expires_at = expires_at",
			explicitInsert: `INSERT INTO kaname.access_bindings
				   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, authz_rev)
				 VALUES ('acbarvprobe0000002', 'user', '` + arvOwner + `', '` + arvRole + `', 'project', '` + arvProject + `', 'ACTIVE', '1'::xid8)`,
			explicitWhere: "id = 'acbarvprobe0000002'",
		},
		{
			table:         "kaname.access_binding_subjects",
			where:         "binding_id = '" + arvBinding + "' AND subject_type = 'user'",
			significant:   "subject_id = '" + arvOwner + "'",
			insignificant: "ordinal = ordinal + 1",
			noop:          "subject_id = subject_id",
			explicitInsert: `INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, authz_rev)
				 VALUES ('` + arvBinding + `', 'group', '` + arvGroup + `', '1'::xid8)`,
			explicitWhere: "binding_id = '" + arvBinding + "' AND subject_id = '" + arvGroup + "'",
		},
		{
			table: "kaname.role_verb",
			where: fmt.Sprintf("role_id = '%s' AND object_type = '%s' AND verb = '%s'", arvRole, objType, verb),
			// У строки глагола все столбцы значимы, кроме постоянной `live`:
			// значимая правка — смена глагола на тот же (`verb` — часть ключа),
			// поэтому значимую сторону держит INSERT/DELETE, а здесь — только
			// переписывание тем же содержимым.
			noop: "verb = verb, object_type = object_type",
			explicitInsert: fmt.Sprintf(`INSERT INTO kaname.role_verb (role_id, object_type, verb, authz_rev)
				 VALUES ('%s', '%s', '%s', '1'::xid8)`, arvRole, secondType, verb),
			explicitWhere: fmt.Sprintf("role_id = '%s' AND object_type = '%s' AND verb = '%s'", arvRole, secondType, verb),
		},
		{
			table:         "kaname.role_rule_selectors",
			where:         "role_id = '" + arvRole + "' AND rule_fp = '" + arvRuleFP + "'",
			significant:   "arm = 'names', resource_names = ARRAY['arv-name']",
			insignificant: "updated_at = updated_at + interval '1 second'",
			noop:          "object_types = object_types, match_labels = match_labels",
			explicitInsert: fmt.Sprintf(`INSERT INTO kaname.role_rule_selectors (role_id, rule_fp, object_types, match_labels, arm, authz_rev)
				 VALUES ('%s', '%s', ARRAY['%s'], '{}'::jsonb, 'anchor', '1'::xid8)`, arvRole, arvRuleFP2, objType),
			explicitWhere: "role_id = '" + arvRole + "' AND rule_fp = '" + arvRuleFP2 + "'",
		},
		{
			table:         "kaname.group_members",
			where:         "group_id = '" + arvGroup + "' AND member_type = 'user'",
			significant:   "member_id = '" + arvOwner + "'",
			insignificant: "added_at = added_at + interval '1 second'",
			noop:          "member_id = member_id",
			explicitInsert: `INSERT INTO kaname.group_members (group_id, member_type, member_id, authz_rev)
				 VALUES ('` + arvGroup + `', 'service_account', '` + arvSA + `', '1'::xid8)`,
			explicitWhere: "group_id = '" + arvGroup + "' AND member_id = '" + arvSA + "'",
		},
		{
			table:         "kaname.relation_fact",
			where:         "object_type = 'vpc_network' AND object_id = '" + arvFactObj + "'",
			significant:   "subject = 'user:" + arvOwner + "'",
			insignificant: "created_at = created_at + interval '1 second'",
			noop:          "subject = subject, relation = relation",
			explicitInsert: `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject, authz_rev)
				 VALUES ('vpc_network', 'netarvprobe0000002', 'v_get', 'user:` + arvMember + `', '1'::xid8)`,
			explicitWhere: "object_type = 'vpc_network' AND object_id = 'netarvprobe0000002'",
		},
		labelRow("kaname.accounts", "id = '"+arvAccount+"'", ""),
		labelRow("kaname.projects", "id = '"+arvProject+"'",
			`INSERT INTO kaname.projects (id, account_id, name, authz_rev)
			 VALUES ('prjarvprobe0000002', '`+arvAccount+`', 'arv-prj-2', '1'::xid8)`),
		labelRow("kaname.groups", "id = '"+arvGroup+"'",
			`INSERT INTO kaname.groups (id, account_id, name, authz_rev)
			 VALUES ('grparvprobe0000002', '`+arvAccount+`', 'arv-grp-2', '1'::xid8)`),
		labelRow("kaname.service_accounts", "id = '"+arvSA+"'",
			`INSERT INTO kaname.service_accounts (id, account_id, name, authz_rev)
			 VALUES ('svaarvprobe0000002', '`+arvAccount+`', 'arv-sa-2', '1'::xid8)`),
		labelRow("kaname.roles", "id = '"+arvRole+"'",
			`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id, authz_rev)
			 VALUES ('rolarvprobe0000002', 'arv-role-2', '["iam.role.*.get"]'::jsonb, '[]'::jsonb, '`+arvClusterR+`', '1'::xid8)`),
		{
			table:         "kaname.users",
			where:         "id = '" + arvMember + "'",
			significant:   `labels = '{"arv":"changed"}'::jsonb`,
			insignificant: "display_name = display_name || '-x'",
			noop:          "labels = labels",
			explicitInsert: `INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status, authz_rev)
				 VALUES ('usrarvprobemember2', 'ext-arv-m2', 'arv-m2@probe.invalid', 'arv', '` + arvAccount + `', 'ACTIVE', '1'::xid8)`,
			explicitWhere: "id = 'usrarvprobemember2'",
		},
	}
}

// labelRow — таблица меток вида iam: значимы метки, служебно описание.
// У аккаунта вторую строку без пары «владелец ↔ аккаунт» не вставить, поэтому
// явная вставка у него проверяется на прочих таблицах этого рода.
func labelRow(table, where, explicitInsert string) fencedRow {
	r := fencedRow{
		table:         table,
		where:         where,
		significant:   `labels = '{"arv":"changed"}'::jsonb`,
		insignificant: "description = description || '-x'",
		noop:          "labels = labels",
	}
	if explicitInsert != "" {
		r.explicitInsert = explicitInsert
		id := explicitInsert[strings.Index(explicitInsert, "VALUES ('")+len("VALUES ('"):]
		r.explicitWhere = "id = '" + id[:strings.Index(id, "'")] + "'"
	}
	return r
}

// arvVerb — глагол строк проекции пробы. Ключ `role_verb_type_fk` судит тип,
// а не глагол, поэтому глагол выбран один на обе строки.
const arvVerb = "get"

// liveCatalogTypesSQL — живые типы каталога в точечной форме: на них ссылается
// ключ `role_verb_type_fk`, и строка пробы не будет отвергнута ЧУЖИМ отказом.
const liveCatalogTypesSQL = `SELECT dotted FROM kaname.catalog_resource WHERE live ORDER BY dotted LIMIT 2`

// liveRoleVerbPair — пара «тип объекта × глагол» строки пробы.
func liveRoleVerbPair(t *testing.T, ctx context.Context, db *sql.DB) (string, string) {
	t.Helper()
	types := liveCatalogTypes(t, ctx, db)
	return types[0], arvVerb
}

// liveCatalogTypes — два живых типа каталога (второй — для явной вставки).
func liveCatalogTypes(t *testing.T, ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) []string {
	t.Helper()
	rows, err := q.QueryContext(ctx, liveCatalogTypesSQL)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	require.Lenf(t, out, 2, "фикстура: посев миграций дал %d живых типов каталога, нужно два", len(out))
	return out
}

// seedFencedWorld сеет мир пробы ОДНОЙ транзакцией и возвращает её
// идентификатор: им обязана быть помечена каждая посеянная строка (INSERT
// ставит версию всегда).
func seedFencedWorld(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var xid string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))

	objType, verb := liveCatalogTypes(t, ctx, tx)[0], arvVerb

	steps := []struct{ what, sql string }{
		{"владелец", `INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ('` + arvOwner + `', 'ext-arv-owner', 'arv-owner@probe.invalid', 'arv', '` + arvAccount + `', 'ACTIVE')`},
		{"член", `INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ('` + arvMember + `', 'ext-arv-member', 'arv-member@probe.invalid', 'arv', '` + arvAccount + `', 'ACTIVE')`},
		{"аккаунт", `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('` + arvAccount + `', 'arv-acc', '` + arvOwner + `')`},
		{"проект", `INSERT INTO kaname.projects (id, account_id, name) VALUES ('` + arvProject + `', '` + arvAccount + `', 'arv-prj')`},
		{"группа", `INSERT INTO kaname.groups (id, account_id, name) VALUES ('` + arvGroup + `', '` + arvAccount + `', 'arv-grp')`},
		{"членство", `INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ('` + arvGroup + `', 'user', '` + arvMember + `')`},
		{"служебная учётка", `INSERT INTO kaname.service_accounts (id, account_id, name) VALUES ('` + arvSA + `', '` + arvAccount + `', 'arv-sa')`},
		{"роль", `INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
			VALUES ('` + arvRole + `', 'arv-role', '["iam.role.*.get"]'::jsonb, '[]'::jsonb, '` + arvClusterR + `')`},
		{"глагол роли", fmt.Sprintf(`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ('%s', '%s', '%s')`, arvRole, objType, verb)},
		{"правило сужения", fmt.Sprintf(`INSERT INTO kaname.role_rule_selectors (role_id, rule_fp, object_types, match_labels, arm)
			VALUES ('%s', '%s', ARRAY['%s'], '{}'::jsonb, 'anchor')`, arvRole, arvRuleFP, objType)},
		{"привязка", `INSERT INTO kaname.access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			VALUES ('` + arvBinding + `', 'user', '` + arvMember + `', '` + arvRole + `', 'project', '` + arvProject + `', 'ACTIVE')`},
		{"субъект привязки", `INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			VALUES ('` + arvBinding + `', 'user', '` + arvMember + `')`},
		{"факт", `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			VALUES ('vpc_network', '` + arvFactObj + `', 'v_get', 'user:` + arvMember + `')`},
	}
	for _, s := range steps {
		_, err := tx.ExecContext(ctx, s.sql)
		require.NoErrorf(t, err, "фикстура: посев «%s» отвергнут — вердикт о версии беспредметен", s.what)
	}
	require.NoError(t, tx.Commit(), "фикстура: посев мира не закоммичен")
	return xid
}

// requireOneRow — положительный контроль отбора: ровно одна строка. Без него
// «версия не изменилась» читалась бы и на отборе, не нашедшем ничего.
func requireOneRow(t *testing.T, ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, r fencedRow, where string) {
	t.Helper()
	var n int
	require.NoError(t, q.QueryRowContext(ctx, `SELECT count(*) FROM `+r.table+` WHERE `+where).Scan(&n))
	require.Equalf(t, 1, n, "фикстура: отбор %q в %s даёт %d строк, а не одну", where, r.table, n)
}

// fingerprintSQL — содержимое строки без версии прав и (для переписывания тем
// же содержимым) без отметки времени правки: её ставит триггер касания
// таблицы, и она служебная (Р30).
func fingerprintSQL(r fencedRow, withoutTouch bool) string {
	drop := `'authz_rev'`
	if withoutTouch {
		drop = `ARRAY['authz_rev','updated_at']`
	}
	return `SELECT (to_jsonb(x) - ` + drop + `)::text FROM ` + r.table + ` x WHERE ` + r.where
}

// rowFingerprint — доказательство того, что правка фикстуры действительно
// сменила (или не сменила) значение.
func rowFingerprint(t *testing.T, ctx context.Context, db *sql.DB, r fencedRow, withoutTouch bool) string {
	t.Helper()
	var fp string
	require.NoError(t, db.QueryRowContext(ctx, fingerprintSQL(r, withoutTouch)).Scan(&fp))
	return fp
}

// authzRevOf — версия прав строки. Отказ чтения — красный С ИМЕНЕМ таблицы:
// колонки нет — это и есть отсутствующая возможность.
func authzRevOf(t *testing.T, ctx context.Context, db *sql.DB, table, where string) string {
	t.Helper()
	var rev sql.NullString
	err := db.QueryRowContext(ctx, `SELECT authz_rev::text FROM `+table+` WHERE `+where).Scan(&rev)
	require.NoErrorf(t, err, "версия прав строки %s не читается (Р30 «Колонка версии прав»: "+
		"каждая таблица вопроса с оградой несёт authz_rev xid8)", table)
	require.Truef(t, rev.Valid, "у строки %s версия прав пуста — строка вне ограды молча", table)
	return rev.String
}

// updateInOwnTx — правка одной строки собственной транзакцией; возвращает её xid.
func updateInOwnTx(t *testing.T, ctx context.Context, db *sql.DB, r fencedRow, set string) string {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	var xid string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	res, err := tx.ExecContext(ctx, `UPDATE `+r.table+` SET `+set+` WHERE `+r.where)
	require.NoErrorf(t, err, "фикстура: правка %s (%s) отвергнута базой", r.table, set)
	n, _ := res.RowsAffected()
	require.EqualValuesf(t, 1, n, "фикстура: правка %s взяла %d строк, а не одну", r.table, n)
	require.NoError(t, tx.Commit())
	return xid
}

// requireFixtureEditsLand — сухой прогон КАЖДОЙ правки фикстуры в
// откатываемой транзакции ДО вопроса о предмете: правка принята базой, взяла
// ровно одну строку и (кроме переписывания тем же содержимым) сменила
// содержимое; явная вставка без колонки версии принята. Поломка фикстуры
// краснеет здесь своим текстом и не выдаёт себя за отсутствующую колонку.
func requireFixtureEditsLand(t *testing.T, ctx context.Context, db *sql.DB, r fencedRow) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	fp := func(withoutTouch bool) string {
		var s string
		require.NoError(t, tx.QueryRowContext(ctx, fingerprintSQL(r, withoutTouch)).Scan(&s))
		return s
	}
	for _, e := range []struct {
		set     string
		changes bool
	}{{r.noop, false}, {r.insignificant, true}, {r.significant, true}} {
		if e.set == "" {
			continue
		}
		before := fp(!e.changes)
		res, err := tx.ExecContext(ctx, `UPDATE `+r.table+` SET `+e.set+` WHERE `+r.where)
		require.NoErrorf(t, err, "фикстура: правка %s (%s) отвергнута базой", r.table, e.set)
		n, _ := res.RowsAffected()
		require.EqualValuesf(t, 1, n, "фикстура: правка %s (%s) взяла %d строк", r.table, e.set, n)
		require.Equalf(t, e.changes, before != fp(!e.changes), "фикстура: правка %s (%s) — смена содержимого не та, что заявлена", r.table, e.set)
	}
	if r.explicitInsert != "" {
		bare := strings.Replace(strings.Replace(r.explicitInsert, ", authz_rev)", ")", 1), ", '1'::xid8", "", 1)
		_, err := tx.ExecContext(ctx, bare)
		require.NoErrorf(t, err, "фикстура: вторая строка %s отвергнута базой и без колонки версии", r.table)
		var n int
		require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM `+r.table+` WHERE `+r.explicitWhere).Scan(&n))
		require.Equalf(t, 1, n, "фикстура: отбор второй строки %s даёт %d строк", r.table, n)
	}
}

func newFencedWorld(t *testing.T) (context.Context, *sql.DB, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("интеграционная проба: нужен Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	db := freshIamSchema(t)
	seedXID := seedFencedWorld(t, ctx, db)
	return ctx, db, seedXID
}

// TestNTF3181b_InsertStampsTheWritingTransactionEvenOverAnExplicitValue —
// INSERT ставит версию ВСЕГДА: посеянная строка несёт xid транзакции посева, а
// явное значение в INSERT умолчание обошло бы, триггер — нет (NTF3-180 (б)).
func TestNTF3181b_InsertStampsTheWritingTransactionEvenOverAnExplicitValue(t *testing.T) {
	ctx, db, seedXID := newFencedWorld(t)
	for _, r := range fencedRows(t, ctx, db) {
		t.Run(strings.TrimPrefix(r.table, "kaname."), func(t *testing.T) {
			requireOneRow(t, ctx, db, r, r.where)
			requireFixtureEditsLand(t, ctx, db, r)
			require.Equalf(t, seedXID, authzRevOf(t, ctx, db, r.table, r.where),
				"%s: версия посеянной строки — не транзакция посева", r.table)

			if r.explicitInsert == "" {
				return
			}
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var xid string
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
			_, err = tx.ExecContext(ctx, r.explicitInsert)
			require.NoErrorf(t, err, "%s: вставка строки с явным authz_rev отвергнута", r.table)
			require.NoError(t, tx.Commit())
			requireOneRow(t, ctx, db, r, r.explicitWhere)
			require.Equalf(t, xid, authzRevOf(t, ctx, db, r.table, r.explicitWhere),
				"%s: явное authz_rev в INSERT прошло мимо триггера — версию ставит умолчание, а не триггер", r.table)
		})
	}
}

// TestNTF3181b_SignificantEditMovesTheVersionAndNoOtherEditDoes — правка
// значимого столбца ставит версию транзакции правки (NTF3-181 (б): срок
// привязки); близнецы по одному факту — та же строка переписана тем же
// содержимым и правка только служебного столбца: версия прежняя (Р30, ред. 39).
func TestNTF3181b_SignificantEditMovesTheVersionAndNoOtherEditDoes(t *testing.T) {
	ctx, db, seedXID := newFencedWorld(t)
	for _, r := range fencedRows(t, ctx, db) {
		t.Run(strings.TrimPrefix(r.table, "kaname."), func(t *testing.T) {
			requireOneRow(t, ctx, db, r, r.where)
			requireFixtureEditsLand(t, ctx, db, r)

			// (1) Переписывание тем же содержимым: содержимое не изменилось
			// (фикстура), версия прежняя (предмет).
			before := rowFingerprint(t, ctx, db, r, true)
			updateInOwnTx(t, ctx, db, r, r.noop)
			require.Equalf(t, before, rowFingerprint(t, ctx, db, r, true), "фикстура: «та же строка» сменила содержимое")
			require.Equalf(t, seedXID, authzRevOf(t, ctx, db, r.table, r.where),
				"%s: UPDATE без изменения значимых столбцов сдвинул версию — досев на старте сузил бы аудиторию", r.table)

			// (2) Правка только служебного столбца: содержимое сменилось
			// (фикстура), версия прежняя (предмет).
			if r.insignificant != "" {
				pre := rowFingerprint(t, ctx, db, r, false)
				updateInOwnTx(t, ctx, db, r, r.insignificant)
				require.NotEqualf(t, pre, rowFingerprint(t, ctx, db, r, false), "фикстура: служебная правка ничего не сменила")
				require.Equalf(t, seedXID, authzRevOf(t, ctx, db, r.table, r.where),
					"%s: правка служебного столбца (%s) сдвинула версию прав", r.table, r.insignificant)
			}

			// (3) Значимая правка: версия — транзакция правки.
			if r.significant != "" {
				mid := rowFingerprint(t, ctx, db, r, false)
				xid := updateInOwnTx(t, ctx, db, r, r.significant)
				require.NotEqualf(t, mid, rowFingerprint(t, ctx, db, r, false), "фикстура: значимая правка ничего не сменила")
				require.Equalf(t, xid, authzRevOf(t, ctx, db, r.table, r.where),
					"%s: правка значимого столбца (%s) прошла мимо ограды — версия не сдвинулась", r.table, r.significant)
			}
		})
	}
}

// TestNTF3181b_EditCommittedAfterTheTokenIsOutsideTheToken — порядок версий
// под конкурирующими транзакциями. Правка срока привязки идёт и держит строку,
// пока ДРУГАЯ сессия снимает токен (полный снимок); правка коммитится после
// токена — её версия в снимке не видна, ограда относит правку к «после R».
// Близнец по одному факту: правка закоммичена ДО снятия токена — видна.
func TestNTF3181b_EditCommittedAfterTheTokenIsOutsideTheToken(t *testing.T) {
	ctx, db, _ := newFencedWorld(t)
	r := fencedRows(t, ctx, db)[0]
	require.Equal(t, "kaname.access_bindings", r.table, "фикстура: первая строка переписи — привязка")
	requireOneRow(t, ctx, db, r, r.where)
	requireFixtureEditsLand(t, ctx, db, r)

	takeToken := func() string {
		var tok string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_current_snapshot()::text`).Scan(&tok))
		return tok
	}
	visibleIn := func(tok string) bool {
		var v sql.NullBool
		err := db.QueryRowContext(ctx,
			`SELECT pg_visible_in_snapshot(authz_rev, $1::pg_snapshot) FROM `+r.table+` WHERE `+r.where, tok).Scan(&v)
		require.NoErrorf(t, err, "%s: видимость версии в снимке не вычисляется — колонки версии прав нет", r.table)
		require.True(t, v.Valid, "видимость версии пуста")
		return v.Bool
	}

	t.Run("правка в полёте при снятии токена", func(t *testing.T) {
		holder, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = holder.Rollback() }()
		var holderXID string
		require.NoError(t, holder.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&holderXID))
		_, err = holder.ExecContext(ctx, `UPDATE `+r.table+` SET expires_at = now() + interval '31 days' WHERE `+r.where)
		require.NoError(t, err, "фикстура: правка срока отвергнута")
		tok := takeToken()
		// Фикстура: транзакция правки действительно шла в момент снимка.
		var inFlight bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT NOT pg_visible_in_snapshot($1::xid8, $2::pg_snapshot)`, holderXID, tok).Scan(&inFlight))
		require.True(t, inFlight, "фикстура: правка не была в полёте при снятии токена — порядок не управляется")
		require.NoError(t, holder.Commit())

		require.Equalf(t, holderXID, authzRevOf(t, ctx, db, r.table, r.where), "%s: версия — не транзакция правки", r.table)
		require.Falsef(t, visibleIn(tok), "%s: правка, закоммиченная после снятия токена, видна в нём — ограда её пропустила бы", r.table)
	})

	t.Run("близнец: правка закоммичена до токена", func(t *testing.T) {
		xid := updateInOwnTx(t, ctx, db, r, "expires_at = now() + interval '32 days'")
		tok := takeToken()
		require.Equal(t, xid, authzRevOf(t, ctx, db, r.table, r.where))
		require.Truef(t, visibleIn(tok), "%s: правка, закоммиченная до токена, в нём не видна", r.table)
	})
}

// TestNTF3181b_ConcurrentEditsLeaveTheVersionOfTheSurvivingContent — N
// транзакций правят срок одной привязки одновременно; строка остаётся с
// содержимым ОДНОЙ из них, и её версия — xid ровно этой транзакции (версия не
// отстаёт от содержимого ни при каком порядке фиксаций). Близнец по одному
// факту: шторм переписываний тем же содержимым — версия прежняя.
func TestNTF3181b_ConcurrentEditsLeaveTheVersionOfTheSurvivingContent(t *testing.T) {
	ctx, db, seedXID := newFencedWorld(t)
	const writers = 8
	db.SetMaxOpenConns(writers + 2)
	r := fencedRows(t, ctx, db)[0]
	require.Equal(t, "kaname.access_bindings", r.table)
	requireOneRow(t, ctx, db, r, r.where)
	requireFixtureEditsLand(t, ctx, db, r)

	storm := func(set func(i int) string) map[string]string {
		var (
			wg    sync.WaitGroup
			mu    sync.Mutex
			start = make(chan struct{})
			byVal = map[string]string{}
			errs  = make([]error, writers)
		)
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					errs[i] = err
					return
				}
				defer func() { _ = tx.Rollback() }()
				var xid, val string
				if err = tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid); err != nil {
					errs[i] = err
					return
				}
				if err = tx.QueryRowContext(ctx, `UPDATE `+r.table+` SET `+set(i)+` WHERE `+r.where+
					` RETURNING coalesce(expires_at::text, '')`).Scan(&val); err != nil {
					errs[i] = err
					return
				}
				if err = tx.Commit(); err != nil {
					errs[i] = err
					return
				}
				mu.Lock()
				byVal[val] = xid
				mu.Unlock()
			}(i)
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			require.NoErrorf(t, err, "фикстура: писатель %d шторма отказал", i)
		}
		return byVal
	}

	t.Run("близнец: шторм переписываний тем же содержимым", func(t *testing.T) {
		storm(func(int) string { return "expires_at = expires_at, status = status" })
		require.Equalf(t, seedXID, authzRevOf(t, ctx, db, r.table, r.where),
			"%s: переписывания тем же содержимым под конкуренцией сдвинули версию", r.table)
	})

	t.Run("шторм значимых правок", func(t *testing.T) {
		byVal := storm(func(i int) string {
			return fmt.Sprintf("expires_at = date_trunc('second', now()) + interval '%d days'", 40+i)
		})
		require.Lenf(t, byVal, writers, "фикстура: значения шторма совпали — победителя не различить")
		var final string
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT coalesce(expires_at::text, '') FROM `+r.table+` WHERE `+r.where).Scan(&final))
		winner, ok := byVal[final]
		require.Truef(t, ok, "фикстура: итоговое значение %q не принадлежит ни одному писателю", final)
		require.Equalf(t, winner, authzRevOf(t, ctx, db, r.table, r.where),
			"%s: версия строки — не транзакция, чьё содержимое в строке осталось", r.table)
	})
}
