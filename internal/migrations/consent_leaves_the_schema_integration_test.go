// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// consent_leaves_the_schema_integration_test.go — СОГЛАСИЕ СУБЪЕКТА ПОКИДАЕТ
// СХЕМУ (задача PRO-Robotech/kaname#404, решение К8 волны #358; миграция
// `20260923225650_consent_leaves_the_schema.sql`).
//
// Проба написана ДО миграции и красна на дереве, где предмет ещё лежит:
// таблица согласий стоит, а причина отзыва семейства `consent-withdrawn`
// принимается ограничением словаря.
//
// # Что утверждают пробы
//
//   - ТАБЛИЦЫ НЕТ, и вместе с ней нет ни одного её отношения и ограничения.
//     Спрашивается каталог живой базы, а не текст миграций; рядом стоит якорь —
//     таблица семейств, которая обязана остаться;
//   - ПРИЧИНЫ НЕТ в словаре базы: отзыв семейства с ней отвергается
//     ограничением словаря, а близнец, отличающийся ОДНОЙ причиной, проходит;
//   - СЛОВАРЬ ДОМЕНА И СЛОВАРЬ БАЗЫ СОВПАДАЮТ в обе стороны. Это класс, а не
//     экземпляр: сузить одно место и забыть второе нельзя ни в какую сторону;
//   - НАКАТ ОТКАЗЫВАЕТ, пока лежит семейство со снимаемой причиной: целиком,
//     не сдвигая версию и не переписывая причину. Близнец — та же строка с
//     законной причиной — проходит;
//   - ОТКАТ возвращает СТРОЕНИЕ, снятое накатом, ровно таким, каким оно стояло:
//     сравниваются две базы — поднятая до предмета и откаченная с головы.
//     Строк откат не возвращает — их неоткуда взять. На откаченной базе сверка
//     словарей обязана НАЙТИ расхождение, и это доказательство того, что она
//     читает живой каталог, а не молчит.
package migrations_test

import (
	"database/sql"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// consentLeavesMigration — файл, снимающий предмет. Имя стоит одним литералом:
// по нему вычисляется версия обратного хода.
const consentLeavesMigration = "20260923225650_consent_leaves_the_schema.sql"

// withdrawnReason — снятое значение словаря причин отзыва семейства.
const withdrawnReason = "consent-withdrawn"

// revokedReasonConstraint — ограничение-близнец словаря домена.
const revokedReasonConstraint = "token_families_revoked_reason_ck"

func consentLeavesDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

// kanameRelationCount — сколько отношений схемы `kaname` названо ровно так.
// Одним запросом и для предмета, и для якоря: запрос, не видящий якоря, не
// вправе утверждать отсутствие предмета.
func kanameRelationCount(t *testing.T, db *sql.DB, name string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'kaname' AND c.relname = $1`, name).Scan(&n))
	return n
}

// TestIntegration_ConsentTableLeavesTheSchema — таблицы согласий нет, и ничего
// её не пережило.
func TestIntegration_ConsentTableLeavesTheSchema(t *testing.T) {
	db := consentLeavesDB(t)

	require.Equal(t, 1, kanameRelationCount(t, db, "token_families"),
		"якорь: таблица семейств обязана стоять — иначе запрос не видит схему, "+
			"и отсутствие предмета ниже было бы отсутствием чтения")

	require.Zero(t, kanameRelationCount(t, db, "consent_grants"),
		"таблица согласий обязана покинуть схему (решение К8)")

	// Отношения и ограничения, названные именем предмета, — индексы, ключи,
	// проверки. Снос таблицы уносит их сам; остаток означал бы, что снята не та
	// таблица либо её строение пережило её под чужим именем.
	var rels, cons int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'kaname' AND c.relname LIKE 'consent\_grants%'`).Scan(&rels))
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_constraint WHERE conname LIKE 'consent\_grants%'`).Scan(&cons))
	t.Logf("перепись: отношений предмета %d, ограничений предмета %d", rels, cons)
	require.Zero(t, rels, "отношений, названных именем предмета, остаться не должно")
	require.Zero(t, cons, "ограничений, названных именем предмета, остаться не должно")
}

// revokeFamilySQL — отзыв семейства ТОЙ ЖЕ формой, что у слоя доступа: отметка,
// причина и живость одним оператором (пары держат ограничения схемы).
const revokeFamilySQL = `
UPDATE kaname.token_families
   SET revoked_at = now(), revoked_reason = $2, live = false
 WHERE id = $1`

// TestIntegration_ConsentWithdrawnLeavesTheRevocationVocabulary — снятая причина
// отвергается базой; близнец, отличающийся одной причиной, проходит.
func TestIntegration_ConsentWithdrawnLeavesTheRevocationVocabulary(t *testing.T) {
	db := consentLeavesDB(t)
	_, _, _, family := acScene(t, db, "cgxrsn")

	_, err := db.Exec(revokeFamilySQL, family, withdrawnReason)
	requirePgRefusal(t, err, "23514", revokedReasonConstraint,
		"снятая причина обязана быть отвергнута словарём базы")

	// БЛИЗНЕЦ: та же строка, тот же оператор, другая причина. Без него «отзыв
	// отвергнут» было бы истинно и в мире, где отзыв невыразим вовсе.
	_, err = db.Exec(revokeFamilySQL, family, string(domain.FamilyRevokedByClientRemoval))
	require.NoError(t, err, "законная причина обязана проходить тем же оператором")
}

// reasonLiteralRe — литерал словаря в определении ограничения, как его
// печатает каталог: `'<значение>'::text`.
var reasonLiteralRe = regexp.MustCompile(`'([^']*)'::text`)

// dbRevocationReasons — словарь причин, который ЖИВАЯ база принимает сегодня:
// литералы ограничения-близнеца, прочитанные из каталога.
func dbRevocationReasons(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var def string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class r ON r.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'kaname' AND r.relname = 'token_families'
		   AND c.conname = $1`, revokedReasonConstraint).Scan(&def),
		"ограничение %s не найдено — сверять словарь базы не с чем", revokedReasonConstraint)
	var out []string
	for _, m := range reasonLiteralRe.FindAllStringSubmatch(def, -1) {
		out = append(out, m[1])
	}
	require.NotEmpty(t, out,
		"в определении %s не разобрано ни одного значения — разбор читает не то.\nопределение: %s",
		revokedReasonConstraint, def)
	sort.Strings(out)
	return out
}

// domainRevocationReasons — словарь домена строками.
func domainRevocationReasons() []string {
	var out []string
	for _, r := range domain.FamilyRevocationReasons() {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// revocationVocabularyFindings — расхождения двух объявлений словаря, в ОБЕ
// стороны. Половина сравнения пропускала бы свою сторону молча.
func revocationVocabularyFindings(dbSide, domainSide []string) []string {
	inDomain := make(map[string]bool, len(domainSide))
	for _, v := range domainSide {
		inDomain[v] = true
	}
	inDB := make(map[string]bool, len(dbSide))
	var out []string
	for _, v := range dbSide {
		inDB[v] = true
		if !inDomain[v] {
			out = append(out, fmt.Sprintf("%q: база принимает, домен не знает", v))
		}
	}
	for _, v := range domainSide {
		if !inDB[v] {
			out = append(out, fmt.Sprintf("%q: домен объявляет, база отвергает", v))
		}
	}
	return out
}

// reasonAccepted — принимает ли база причину на живой строке. Транзакция
// откатывается: семейство остаётся неотозванным для следующего значения.
func reasonAccepted(t *testing.T, db *sql.DB, family, reason string) error {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(revokeFamilySQL, family, reason)
	return err
}

// TestIntegration_RevocationVocabularyAgreesWithTheDomain — словарь домена и
// словарь базы совпадают, и каждое значение принимается живой строкой.
func TestIntegration_RevocationVocabularyAgreesWithTheDomain(t *testing.T) {
	db := consentLeavesDB(t)
	_, _, _, family := acScene(t, db, "cgxagr")

	dbSide := dbRevocationReasons(t, db)
	domainSide := domainRevocationReasons()
	t.Logf("перепись: значений у базы %d (%s) · у домена %d (%s)",
		len(dbSide), strings.Join(dbSide, " "), len(domainSide), strings.Join(domainSide, " "))

	require.Empty(t, revocationVocabularyFindings(dbSide, domainSide),
		"словарь причин отзыва семейства объявлен дважды и разошёлся")

	// Разобранное — то, что база действительно ПРИНИМАЕТ, а не случайные
	// литералы определения: каждое значение проходит на живой строке.
	for _, v := range dbSide {
		require.NoError(t, reasonAccepted(t, db, family, v),
			"значение %q разобрано из ограничения, но база его не принимает", v)
	}
}

// TestRevocationVocabularyComparator_SeesBothDirections — сравнение падает по
// каждой оси и молчит на законном близнеце.
func TestRevocationVocabularyComparator_SeesBothDirections(t *testing.T) {
	agreed := []string{"code-replay", "logout"}
	require.Empty(t, revocationVocabularyFindings(agreed, agreed),
		"законный близнец: совпадающие словари обязаны давать ноль находок")

	wider := revocationVocabularyFindings([]string{"code-replay", "logout", withdrawnReason}, agreed)
	require.Len(t, wider, 1, "у базы лишнее значение — находка ровно одна")
	require.Contains(t, wider[0], withdrawnReason, "находка обязана назвать лишнее значение")

	narrower := revocationVocabularyFindings([]string{"code-replay"}, agreed)
	require.Len(t, narrower, 1, "база потеряла значение домена — находка ровно одна")
	require.Contains(t, narrower[0], "logout", "находка обязана назвать потерянное значение")
}

// TestIntegration_ConsentLeavingRefusesAFamilyCarryingTheWithdrawnReason —
// строка с причиной, которую накат снимает, ОТКАЗЫВАЕТ накату целиком, а не
// переписывается в другую причину и не остаётся под ограничением без проверки.
// Близнец отличается одной причиной у той же строки — и накат проходит.
func TestIntegration_ConsentLeavingRefusesAFamilyCarryingTheWithdrawnReason(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, consentLeavesMigration)

	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", previous), "цепочка обязана дойти до версии перед предметом")

	_, _, _, family := acScene(t, db, "cgxrfs")
	_, err = db.Exec(revokeFamilySQL, family, withdrawnReason)
	require.NoError(t, err, "до наката снимаемая причина обязана приниматься — иначе отказывать нечему")

	requirePgRefusal(t, goose.UpTo(db, ".", own), "23514", revokedReasonConstraint,
		"накат обязан отказать, пока лежит строка с причиной, которую он снимает")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version, "отказавший накат не вправе сдвинуть версию цепочки")
	require.Equal(t, 1, kanameRelationCount(t, db, "consent_grants"),
		"отказавший накат обязан откатиться целиком: таблица согласий на месте")
	var reason string
	require.NoError(t, db.QueryRow(
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, family).Scan(&reason))
	require.Equal(t, withdrawnReason, reason, "отказавший накат не вправе переписать причину")

	// БЛИЗНЕЦ: та же строка, другая причина — накат проходит.
	_, err = db.Exec(`UPDATE kaname.token_families SET revoked_reason = $2 WHERE id = $1`,
		family, string(domain.FamilyRevokedByClientRemoval))
	require.NoError(t, err)
	require.NoError(t, goose.UpTo(db, ".", own), "без строки со снимаемой причиной накат обязан проходить")
	require.Zero(t, kanameRelationCount(t, db, "consent_grants"), "после наката таблицы согласий быть не должно")
}

// consentStructure — строение, которое снимает накат: столбцы, ограничения,
// индексы и комментарий таблицы согласий, и определение ограничения словаря.
// Каждая строка — один факт каталога; порядок устойчив.
func consentStructure(t *testing.T, db *sql.DB) (lines []string, columns, constraints, indexes int) {
	t.Helper()
	collect := func(kind, query string) int {
		rows, err := db.Query(query)
		require.NoError(t, err, "строение: %s", kind)
		defer func() { _ = rows.Close() }()
		n := 0
		for rows.Next() {
			var a, b string
			require.NoError(t, rows.Scan(&a, &b))
			lines = append(lines, kind+" "+a+" "+b)
			n++
		}
		require.NoError(t, rows.Err())
		return n
	}
	columns = collect("column", `
		SELECT column_name,
		       data_type || ' ' || is_nullable || ' ' || coalesce(column_default, '')
		  FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'consent_grants'
		 ORDER BY ordinal_position`)
	constraints = collect("constraint", `
		SELECT conname, pg_get_constraintdef(oid)
		  FROM pg_constraint
		 WHERE conrelid = to_regclass('kaname.consent_grants')
		 ORDER BY conname`)
	indexes = collect("index", `
		SELECT indexname, indexdef FROM pg_indexes
		 WHERE schemaname = 'kaname' AND tablename = 'consent_grants'
		 ORDER BY indexname`)
	collect("comment", `
		SELECT 'consent_grants', coalesce(obj_description(to_regclass('kaname.consent_grants'), 'pg_class'), '')`)
	collect("vocabulary", `
		SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conname = '`+revokedReasonConstraint+`'`)
	return lines, columns, constraints, indexes
}

// TestIntegration_ConsentLeavingRollsBackToTheSameStructure — откат возвращает
// ровно то строение, которое стояло до наката, и накат снимает его снова.
func TestIntegration_ConsentLeavingRollsBackToTheSameStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, consentLeavesMigration)

	// База ДО предмета: цепочка остановлена на версии перед ним.
	before, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = before.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(before, ".", previous), "цепочка обязана дойти до версии перед предметом")
	want, cols, cons, idx := consentStructure(t, before)
	t.Logf("строение до наката: столбцов %d, ограничений %d, индексов %d", cols, cons, idx)
	require.NotZero(t, cols, "до наката таблица согласий обязана стоять — сравнивать иначе не с чем")
	require.NotZero(t, cons, "до наката у таблицы согласий обязаны быть ограничения")
	require.NotZero(t, idx, "до наката у таблицы согласий обязаны быть индексы")

	// База С ГОЛОВЫ, откаченная на ту же версию.
	after := consentLeavesDB(t)
	require.NoError(t, goose.DownTo(after, ".", previous), "обратный ход обязан проходить")
	got, _, _, _ := consentStructure(t, after)
	require.Equal(t, want, got,
		"откат обязан вернуть строение ровно таким, каким оно стояло до наката")

	// Сверка словарей на ОТКАЧЕННОЙ базе обязана найти расхождение: база снова
	// принимает снятую причину, а домен её уже не знает. Молчание здесь значило
	// бы, что сверка не читает живой каталог.
	findings := revocationVocabularyFindings(dbRevocationReasons(t, after), domainRevocationReasons())
	require.Len(t, findings, 1, "на откаченной базе расхождение обязано быть ровно одно: %v", findings)
	require.Contains(t, findings[0], withdrawnReason, "расхождение обязано назвать снятую причину")

	// Повторный накат снимает предмет снова.
	require.NoError(t, goose.Up(after, "."), "цепочка обязана накатываться снова")
	require.Zero(t, kanameRelationCount(t, after, "consent_grants"),
		"после повторного наката таблицы согласий быть не должно")
	require.Empty(t, revocationVocabularyFindings(dbRevocationReasons(t, after), domainRevocationReasons()),
		"после повторного наката словари обязаны снова совпадать")
	version, err := goose.GetDBVersion(after)
	require.NoError(t, err)
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}
