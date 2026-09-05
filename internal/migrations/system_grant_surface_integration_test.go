// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_grant_surface_integration_test.go — У СВЕЖЕЙ ПЛАТФОРМЫ НЕТ ДЕЙСТВУЮЩЕГО
// ДОСТУПА ПОМИМО ПОВЕРХНОСТИ ВЫДАЧ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Администратор отвечает на вопрос «кому что выдано» перечислением выдач. Пока
// часть действующих оснований заведена помимо этой поверхности — прямыми
// фактами посева, — ответ неполон ровно на всё встроенное, и «ничего не выдано»
// неотличимо от «выдано в обход». Отозвать такое тоже нечем: отзыв работает над
// выдачей, а её нет.
//
// Здесь это свойство измеряется, а не утверждается: проба поднимает пустую базу,
// прогоняет всю цепочку миграций и требует, чтобы у КАЖДОГО основания доступа
// была парная действующая системная выдача.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОСНОВАНИЕМ ДОСТУПА ЗДЕСЬ НЕ СЧИТАЕТСЯ — И ПОЧЕМУ ЭТО НАЗВАНО, А НЕ УМОЛЧАНО
//
// ЧЛЕНСТВО (`member` на объекте группы) — не выдача, а состав группы, и у него
// СВОЯ поверхность: состав виден перечислением членов. Требовать под него выдачу
// значило бы завести второе место об одном предмете.
//
// КЛАСТЕРНЫЙ АДМИНИСТРАТОР живёт отдельной таблицей со своей поверхностью
// (выдать / отозвать / перечислить), и она остаётся раздельной по решению
// (#914, решение 2 в `docs/engineering/architecture/grant-surface-boundaries.md`):
// его выдают и отзывают иначе, и это единственный доступ, обязанный работать,
// когда сломано всё остальное. Сведено ЧТЕНИЕ — перечисление выдач возвращает и
// его записи, называя вид, — а выдача осталась своей. Перепись его СЧИТАЕТ и
// печатает, чтобы «не покрыт» было отличимо от «не существует».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ НА СВЕЖЕЙ БАЗЕ, А НЕ НА ЖИВОЙ
//
// На работающей платформе прямые факты производит ещё и регистрация ресурса:
// владение, поставленное в момент создания, и указатель на предка. Это НЕ
// встроенный доступ платформы, у него другой производитель и другой предикат.
// Свежая база содержит ровно то, что заводит посев, — то есть ровно предмет
// этой пробы, и ничего сверх него.

package migrations_test

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// membershipRelation — отношение состава группы. Одно из двух, что перепись
// выводит из-под требования, и потому названо константой, а не литералом в
// запросе: исключение обязано быть видно там, где его читают.
const membershipRelation = "member"

// hierarchyAnchors — якоря, на которых выдача выразима. Второе названное
// исключение: факт на объекте ВНЕ иерархии этой формой не выражается, потому что
// у такого якоря нет ни яруса, ни владельца, который мог бы отозвать. Перепись
// его считает и печатает отдельным числом — «не покрыт» обязано быть отличимо от
// «не существует».
const hierarchyAnchors = `('cluster', 'account', 'project')`

// accessBasis — одно действующее основание доступа в том виде, в каком его
// читает вердикт.
type accessBasis struct {
	ObjectType string
	ObjectID   string
	Relation   string
	Subject    string
}

func (a accessBasis) String() string {
	return fmt.Sprintf("%s:%s#%s@%s", a.ObjectType, a.ObjectID, a.Relation, a.Subject)
}

// grantSurfaceCensus — что перепись прочитала. Печатается ВСЕГДА: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type grantSurfaceCensus struct {
	Bases          int // оснований доступа всего
	Membership     int // из них членство (своя поверхность — состав группы)
	OffHierarchy   int // из них на якоре вне иерархии (выдачей не выражается)
	Subject        int // из них предмет требования
	Matched        int // из предмета — с парной действующей системной выдачей
	SystemGrants   int // системных выдач в таблице выдач
	OrdinaryGrants int // обычных выдач
	ClusterAdmins  int // строк отдельной таблицы кластерных администраторов
	Findings       []accessBasis
}

func (c grantSurfaceCensus) report() string {
	return fmt.Sprintf(
		"осмотрено: оснований доступа %d = предмет %d + членство %d + вне иерархии %d; "+
			"из предмета с парной системной выдачей %d; "+
			"выдач системных %d, обычных %d; кластерных администраторов отдельной таблицей %d",
		c.Bases, c.Subject, c.Membership, c.OffHierarchy, c.Matched,
		c.SystemGrants, c.OrdinaryGrants, c.ClusterAdmins)
}

// upAllIAMMigrations доводит цепочку до конца.
func upAllIAMMigrations(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."),
		"цепочка обязана доходить до конца — иначе перепись говорит не о том дереве")
	return db
}

// subjectRefSQL — субъект выдачи в той же форме, в какой он лежит у основания.
// Форма ОДНА и производится в дереве `domain.FGASubjectRef`; здесь она
// воспроизведена запросом, потому что перепись идёт по базе, а не по коду.
const subjectRefSQL = `CASE b.subject_type
                         WHEN 'service_account' THEN 'service_account:' || b.subject_id
                         WHEN 'group'           THEN 'group:' || b.subject_id || '#member'
                         ELSE                        'user:' || b.subject_id
                       END`

// censusOfEffectiveAccess перечисляет основания доступа и сверяет каждое с
// поверхностью выдач.
func censusOfEffectiveAccess(t *testing.T, db queryer) grantSurfaceCensus {
	t.Helper()
	var c grantSurfaceCensus

	// subjectWhere — предмет требования: основание доступа, выразимое выдачей.
	// Оба вычета названы классом, а не перечнем строк, и оба считаются отдельно.
	const subjectWhere = `f.relation <> $1 AND f.object_type IN ` + hierarchyAnchors

	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kacho_iam.relation_fact`).Scan(&c.Bases))
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.relation_fact WHERE relation = $1`, membershipRelation).
		Scan(&c.Membership))
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.relation_fact f WHERE `+subjectWhere, membershipRelation).
		Scan(&c.Subject))
	// Третий класс считается АРИФМЕТИКОЙ, а не отрицательным отбором. Список
	// «всё, кроме перечисленного» стареет молча: он растёт от работы, к переписи
	// отношения не имеющей, и, исключив лишнее, даёт «ноль», не посмотрев ни на
	// одну строку. Здесь остаток выводится из двух положительно отобранных
	// величин и целого, поэтому слепой зоны нет by construction.
	c.OffHierarchy = c.Bases - c.Membership - c.Subject
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE is_system`).Scan(&c.SystemGrants))
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE NOT is_system`).Scan(&c.OrdinaryGrants))
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants`).Scan(&c.ClusterAdmins))

	matchSQL := `
		SELECT 1 FROM kacho_iam.access_bindings b
		 WHERE b.is_system
		   AND b.status = 'ACTIVE'
		   AND b.revoked_at IS NULL
		   AND b.granted_relation = f.relation
		   AND b.resource_type    = f.object_type
		   AND b.resource_id      = f.object_id
		   AND ` + subjectRefSQL + ` = f.subject`

	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kacho_iam.relation_fact f
		 WHERE `+subjectWhere+` AND EXISTS (`+matchSQL+`)`, membershipRelation).Scan(&c.Matched))

	rows, err := db.Query(`
		SELECT f.object_type, f.object_id, f.relation, f.subject
		  FROM kacho_iam.relation_fact f
		 WHERE `+subjectWhere+`
		   AND NOT EXISTS (`+matchSQL+`)
		 ORDER BY 1, 2, 3, 4`, membershipRelation)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var b accessBasis
		require.NoError(t, rows.Scan(&b.ObjectType, &b.ObjectID, &b.Relation, &b.Subject))
		c.Findings = append(c.Findings, b)
	}
	require.NoError(t, rows.Err())
	return c
}

// TestIntegration_R893_NoEffectiveAccessOutsideTheGrantSurface — предикат снятия
// #893/#895: у свежеразвёрнутой платформы нет действующего основания доступа,
// которого не видно перечислением выдач.
func TestIntegration_R893_NoEffectiveAccessOutsideTheGrantSurface(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	c := censusOfEffectiveAccess(t, db)
	t.Log(c.report())

	// Предпосылка переписи. «Ноль находок» на пустой таблице истинно
	// тождественно, поэтому объём осмотренного утверждается ОТДЕЛЬНО.
	require.NotZero(t, c.Subject,
		"предмет требования пуст — перепись беспредметна, и её молчание ничего не значит. %s", c.report())
	require.NotZero(t, c.SystemGrants,
		"системных выдач ноль — встроенный доступ на поверхность не переехал. %s", c.report())

	// Якорь вне иерархии — предмет решения 1 (#914,
	// docs/engineering/architecture/grant-surface-boundaries.md). Решено:
	// словарь якорей выдачи за пределы трёх ярусов НЕ растёт, а способность
	// модуля писать кортежи выражается КЛАСТЕРНЫМ отношением и обычной
	// системной выдачей. Значит остаток обязан быть нулевым: основание на
	// якоре, у которого нет ни яруса, ни владельца, отозвать нечем, и
	// перечисление выдач о нём молчит.
	require.Zero(t, c.OffHierarchy,
		"основание доступа на якоре ВНЕ иерархии: такую выдачу некому отозвать и не видно "+
			"перечислением. Решение 1 задачи #914 — перенести способность на кластерное "+
			"отношение. %s", c.report())

	if len(c.Findings) > 0 {
		names := make([]string, 0, len(c.Findings))
		for _, f := range c.Findings {
			names = append(names, f.String())
		}
		sort.Strings(names)
		t.Fatalf("действующий доступ помимо поверхности выдач: %d\n  %s\n%s\n\n"+
			"Каждое такое основание невидимо перечислению выдач и не отзывается штатно: "+
			"отзыв работает над выдачей, а её нет. Заведите системную выдачу "+
			"(granted_relation + is_system) — факт производится из неё.",
			len(c.Findings), strings.Join(names, "\n  "), c.report())
	}
}

// queryer — то немногое от базы, что нужно переписи. Инъекция гоняет её внутри
// транзакции, чтобы возврат состояния держался откатом, а не второй правкой:
// правка «обратно» может быть неверной и молча оставить дерево испорченным.
type queryer interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// TestIntegration_R893_TheCensusCanFail — инъекция в обе стороны, два случая.
//
// Утверждение об ОТСУТСТВИИ молчит и когда предмета нет, и когда сам запрос
// сломан. Поэтому проба воспроизводит ровно то состояние, ради которого гейт
// написан, — доступ есть, выдачи нет, — и требует, чтобы перепись назвала
// основание ПОИМЁННО. Второй случай отдельный и не сводится к первому: выдача на
// месте, но ОТОЗВАНА; отозванная выдача поверхностью не является, и перепись
// обязана это различать.
//
// Обратная сторона у обоих одна: после отката перепись молчит — то есть она
// ловит предмет, а не форму запроса.
func TestIntegration_R893_TheCensusCanFail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	before := censusOfEffectiveAccess(t, db)
	require.Empty(t, before.Findings, "предпосылка инъекции: до неё находок нет. %s", before.report())

	var id, subject, relation, objType, objID string
	require.NoError(t, db.QueryRow(`
		SELECT b.id, `+subjectRefSQL+`, b.granted_relation, b.resource_type, b.resource_id
		  FROM kacho_iam.access_bindings b
		 WHERE b.is_system AND b.status = 'ACTIVE'
		 ORDER BY b.id
		 LIMIT 1`).Scan(&id, &subject, &relation, &objType, &objID),
		"инъекции нечего снимать — системных выдач нет")

	want := accessBasis{ObjectType: objType, ObjectID: objID, Relation: relation, Subject: subject}

	injections := []struct {
		name string
		stmt string
	}{
		{
			name: "выдачи нет вовсе",
			stmt: `DELETE FROM kacho_iam.access_bindings WHERE id = $1`,
		},
		{
			name: "выдача отозвана",
			stmt: `UPDATE kacho_iam.access_bindings
				   SET status = 'REVOKED', revoked_at = now()
				 WHERE id = $1`,
		},
	}

	for _, inj := range injections {
		t.Run(inj.name, func(t *testing.T) {
			tx, err := db.Begin()
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()

			_, err = tx.Exec(inj.stmt, id)
			require.NoError(t, err)

			after := censusOfEffectiveAccess(t, tx)
			require.Contains(t, after.Findings, want,
				"перепись обязана назвать основание, чью выдачу %s. %s", inj.name, after.report())

			require.NoError(t, tx.Rollback())

			// Законный близнец: то же основание при живой выдаче — не находка.
			restored := censusOfEffectiveAccess(t, db)
			require.Empty(t, restored.Findings,
				"живая выдача обязана закрывать основание — иначе перепись ловит не тот предмет. %s",
				restored.report())
		})
	}
}
