// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_functions_leave_the_brand_integration_test.go — ДЕРЖАТЕЛЬ оси
// «таблицы» условия «имя платформы не остаётся на поверхности службы»
// (kacho#2076, предикат C, п. 3): функции схемы `kaname` после ВСЕЙ цепочки
// миграций не носят имени платформы, кроме двух, отрисованных шаблоном
// фундамента и названных ведомостью решённого остаться.
//
// # Почему проба по живой базе, а не чтение миграций
//
// Пять собственных функций (счёт учёта, жизненный цикл носителя, отказ и счёт
// темпа, проверка меток) заведены применённым сводом `0001_initial.sql`, а его
// не правят (ban #5). Переименование — новой миграцией: текст свода остаётся
// прежним, объект в базе — уже нет. Ось поэтому держалась точным числом
// вхождений в файлах (88 в 5), и число это к нулю не шло НИКОГДА, то есть
// условие было недостижимо by construction. Здесь спрашивается ИМЯ ОБЪЕКТА у
// базы после цепочки; судья — `supplyhygiene.JudgeSchemaFunctionNames`, его
// способность упасть доказана инъекцией рядом с ним.
//
// # Сценарии (идентификаторы — KAN-FN-NN; приёмки с Given-When-Then под
// переименование функций в дереве нет, сценарии выведены из п. 3 предиката C и
// строки оси «таблицы» переписи `platform_name_axes_test.go`)
//
//   - KAN-FN-01 — Дано: цепочка миграций применена целиком. Когда: перечислены
//     функции схемы. Тогда: имя платформы носят ровно те, что названы
//     ведомостью, и каждая запись ведомости имеет предмет;
//   - KAN-FN-02 — Дано: то же. Когда: перечислены зависимые объекты
//     (триггеры и ограничения CHECK). Тогда: каждый указывает на функцию под
//     ОБЪЯВЛЕННЫМ именем, и число зависимых сходится с графом свода;
//   - KAN-FN-03 — Дано: то же. Когда: переименованные функции зовутся —
//     проверкой меток через CHECK, отказом темпа напрямую. Тогда: они решают
//     как прежде, тело счётчика темпа зовёт отказ ОБЪЯВЛЕННЫМ именем и остаётся
//     телом Ф4 (носитель ключа нашей полосы — голова `own:`), а не свода;
//   - KAN-FN-04 — Дано: цепочка применена. Когда: откат до версии ниже
//     переименования и повторный накат. Тогда: откат возвращает прежние имена,
//     накат снова сходится.
package migrations_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/supplyhygiene"
)

// schemaFunctionsDecidedToStay — ведомость решённого остаться.
//
// Обе функции отрисованы шаблоном фундамента corelib `quota/refusal.sql.tmpl`,
// один текст на шесть владельцев; имя выбирает шаблон, а не служба. Решение —
// kacho#2538 («остаться»); расхождение решения с п. 3 предиката C поднято
// владельцу (kacho#2076). Запись самоистекает: судья называет находкой запись
// без функции.
var schemaFunctionsDecidedToStay = []supplyhygiene.SchemaFunctionStay{
	{Name: "kacho_quota_refuse", Why: "отрисована шаблоном фундамента corelib quota/refusal.sql.tmpl, " +
		"одним текстом на шесть владельцев; имя выбирает шаблон — kacho#2538"},
	{Name: "kacho_quota_admit", Why: "отрисована тем же шаблоном фундамента; имя выбирает шаблон — kacho#2538"},
}

// schemaFunctionTransition — одна переименованная функция: прежнее имя,
// объявленное, сигнатура (для `ALTER FUNCTION`) и число зависимых объектов по
// графу свода, которое переименование обязано оставить неподвижным.
type schemaFunctionTransition struct {
	previous   string
	declared   string
	signature  string
	dependents int
}

// schemaFunctionTransitions — пять собственных функций службы. Числа зависимых
// сняты с графа свода: десять ограничений CHECK на проверке меток;
// триггеры списания у аккаунтов, у двух таблиц клиентов и у таблицы ключей
// доступа (Ф7, kacho#1273 — четвёртый зависимый заведён ПОСЛЕ переименования,
// своей миграцией, и стоит здесь как зависимый объявленного имени); жизненный
// цикл носителя у людей и служебных учёток; отложенный триггер темпа у
// аккаунтов; отказ темпа зовётся из тела счётчика, а не объектом.
var schemaFunctionTransitions = []schemaFunctionTransition{
	{previous: "kacho_labels_valid", declared: "labels_valid", signature: "(jsonb)", dependents: 10},
	{previous: "kacho_quota_count", declared: "quota_count", signature: "()", dependents: 4},
	{previous: "kacho_quota_carrier_lifecycle", declared: "quota_carrier_lifecycle", signature: "()", dependents: 2},
	{previous: "kacho_admission_rate_count", declared: "admission_rate_count", signature: "()", dependents: 1},
	{previous: "kacho_rate_refuse", declared: "rate_refuse", signature: "(text, text)", dependents: 0},
}

// schemaFunctionNames — `proname` каждой функции схемы службы.
func schemaFunctionNames(t *testing.T, db queryer) []string {
	t.Helper()
	rows, err := db.Query(`SELECT p.proname
	                         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
	                        WHERE n.nspname = 'kaname'
	                        ORDER BY 1`)
	require.NoError(t, err)
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		names = append(names, n)
	}
	require.NoError(t, rows.Err())
	return names
}

// dependentsOf — зависимые от функции объекты: триггеры (по `tgfoid`) и
// ограничения (по `pg_depend`), каждый — именем.
func dependentsOf(t *testing.T, db queryer, fn string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT 'trigger ' || t.tgname
		  FROM pg_trigger t
		  JOIN pg_proc p ON p.oid = t.tgfoid
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'kaname' AND p.proname = $1 AND NOT t.tgisinternal
		UNION ALL
		SELECT 'constraint ' || c.conname
		  FROM pg_depend d
		  JOIN pg_constraint c ON c.oid = d.objid AND d.classid = 'pg_constraint'::regclass
		  JOIN pg_proc p ON p.oid = d.refobjid AND d.refclassid = 'pg_proc'::regclass
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'kaname' AND p.proname = $1
		ORDER BY 1`, fn)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		require.NoError(t, rows.Scan(&d))
		out = append(out, d)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestSchemaFunctions_CarryNoForeignBrandAfterTheChain — KAN-FN-01.
func TestSchemaFunctions_CarryNoForeignBrandAfterTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	names := schemaFunctionNames(t, db)
	census, findings := supplyhygiene.JudgeSchemaFunctionNames(names, schemaFunctionsDecidedToStay)
	t.Logf("перепись схемы kaname: функций %d · несущих имя платформы %d · из них решено остаться %d",
		census.Functions, census.Branded, census.Stayed)
	require.NotZero(t, census.Functions, "функций прочитано ноль — спросили не ту схему")
	for _, f := range findings {
		t.Errorf("%s", f)
	}
	for _, tr := range schemaFunctionTransitions {
		require.Contains(t, names, tr.declared,
			"функции %q в схеме нет: переименование %q не состоялось либо объявленное имя иное",
			tr.declared, tr.previous)
	}
}

// TestSchemaFunctions_DependentsFollowTheRenamedFunction — KAN-FN-02.
//
// Триггер и ограничение ссылаются на функцию идентификатором и переживают
// переименование by construction — но это утверждение о механизме базы, а не о
// цепочке: миграция могла бы снять и завести функцию заново, и зависимые
// потерялись бы молча. Поэтому число зависимых сверяется с графом свода.
func TestSchemaFunctions_DependentsFollowTheRenamedFunction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	for _, tr := range schemaFunctionTransitions {
		deps := dependentsOf(t, db, tr.declared)
		t.Logf("%s: зависимых %d — %s", tr.declared, len(deps), strings.Join(deps, ", "))
		require.Len(t, deps, tr.dependents,
			"у функции %q зависимых %d при %d по графу свода — переименование сдвинуло зависимые",
			tr.declared, len(deps), tr.dependents)
		require.Empty(t, dependentsOf(t, db, tr.previous),
			"объект всё ещё указывает на функцию под прежним именем %q", tr.previous)
	}

	// Определение ограничения печатает ОБЪЯВЛЕННОЕ имя: так его видит оператор
	// в `\d` своей таблицы. Квалификатор схемы разбор опускает, когда схема стоит
	// в пути поиска сеанса, поэтому утверждается имя функции, а не его запись с
	// квалификатором.
	var def string
	require.NoError(t, db.QueryRow(
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'roles_labels_valid'`).Scan(&def))
	require.Contains(t, def, "labels_valid(labels)")
	require.NotContains(t, def, "kacho_")
}

// TestSchemaFunctions_RenamedFunctionsStillDecide — KAN-FN-03.
func TestSchemaFunctions_RenamedFunctionsStillDecide(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	// Проверка меток по-прежнему ОТВЕРГАЕТ — и по-прежнему принимает; одностороннее
	// утверждение зеленело бы на функции, отвергающей всё.
	var ok bool
	require.NoError(t, db.QueryRow(`SELECT kaname.labels_valid('{"env":"prod"}'::jsonb)`).Scan(&ok))
	require.True(t, ok, "законные метки отвергнуты")
	require.NoError(t, db.QueryRow(`SELECT kaname.labels_valid('{"Env":"prod"}'::jsonb)`).Scan(&ok))
	require.False(t, ok, "ключ с заглавной принят")

	// Отказ темпа под объявленным именем производит тот же контракт: SQLSTATE
	// KQ005 при неназванной величине.
	_, err := db.Exec(`SELECT kaname.rate_refuse('identity-probe', 'kind.without.rate')`)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "отказ темпа не произвёл ошибки базы: %v", err)
	require.Equal(t, "KQ005", pgErr.Code)

	// Тело счётчика темпа зовёт отказ ОБЪЯВЛЕННЫМ именем: вызов внутри тела
	// разрешается при исполнении, и прежнее имя там означало бы отказ
	// «функции нет» на первом же входе.
	var src string
	require.NoError(t, db.QueryRow(
		`SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		  WHERE n.nspname = 'kaname' AND p.proname = 'admission_rate_count'`).Scan(&src))
	require.Contains(t, src, "kaname.rate_refuse(")
	require.NotContains(t, src, "kacho_rate_refuse")

	// И тело — тело Ф4 (`20260917120000`), а не свода: переименование идёт
	// ПОСЛЕ замещения тела по имени и переписывает его заново, поэтому обязано
	// нести носитель ключа нашей полосы. Без этого утверждения переименование,
	// вернувшее тело свода, зеленело бы: отказ зовётся верным именем, а ключ
	// носителя потерян молча.
	require.Contains(t, src, "external_id LIKE 'own:%'",
		"тело счётчика темпа после цепочки не несёт головы нашей полосы — переименование вернуло тело свода")
}

// schemaFunctionsVersion — версия миграции переименования. Названа ЧИСЛОМ, а не
// выведена из положения в каталоге: положение — допущение, которое уже ломалось
// (`own_ceilings_down_roundtrip_integration_test.go`).
const schemaFunctionsVersion int64 = 20260917130000

// TestSchemaFunctions_DownRestoresThePlatformNamesAndReapplyConverges — KAN-FN-04.
func TestSchemaFunctions_DownRestoresThePlatformNamesAndReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < schemaFunctionsVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, schemaFunctionsVersion)

	names := schemaFunctionNames(t, db)
	for _, tr := range schemaFunctionTransitions {
		require.Contains(t, names, tr.previous, "откат не вернул прежнего имени %q", tr.previous)
		require.NotContains(t, names, tr.declared, "после отката осталось объявленное имя %q", tr.declared)
	}

	require.NoError(t, goose.Up(db, "."), "повторный накат обязан сходиться")
	names = schemaFunctionNames(t, db)
	_, findings := supplyhygiene.JudgeSchemaFunctionNames(names, schemaFunctionsDecidedToStay)
	require.Empty(t, findings, "после повторного наката судья снова обязан молчать")
}
