// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// trigger_body_matches_row_shape_integration_test.go — гейт на КЛАСС: тело
// триггера называет только те поля строки, которые у строки ЕСТЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// `DROP COLUMN` не уносит триггер, который эту колонку писал, и не может унести:
// тело plpgsql разбирается при ИСПОЛНЕНИИ, поэтому база не видит связи между
// снятой колонкой и обращением `NEW.<колонка>` в теле. Схема после такой правки
// применяется без единого предупреждения и ломается на ПЕРВОЙ ЖЕ ВСТАВКЕ:
//
//	ERROR: record "new" has no field "<колонка>" (SQLSTATE 42703)
//
// Наблюдалось (kacho#1033): миграция сняла с журнала намерений iam ключ
// упорядочивания вместе с его индексами — величину, у которой с 2026-08-21 не
// осталось читателя, — а писавший её триггер `BEFORE INSERT` остался. Отвергнута
// оказалась каждая вставка в журнал, то есть каждая выдача и каждый отзыв
// доступа: путь мутации, а не пробы. Видно это стало в пяти пробах переписи
// источников области, которые о триггерах не знают ничего и упали на посеве.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ ПО СХЕМЕ, А НЕ ПРОБА НА ОДНУ ТАБЛИЦУ
//
// Проба «журнал принимает вставку» ниже закрывает СВОЙ экземпляр и молчит про
// остальные таблицы схемы. Радиус же берётся по имени механизма, а не по месту,
// где дефект заметили: триггеров в `kacho_iam` десятки, и следующий `DROP COLUMN`
// придёт в другую таблицу. Поэтому разбор идёт по ВСЕЙ схеме и печатает объём
// осмотренного — «ноль находок» обязано быть отличимо от «ноль прочитанного».
//
// Способность гейта упасть и смолчать доказана инъекцией в обе стороны на
// синтетической схеме (см. TestTriggerBodyFieldRefsProvenByInjection): дефектный
// триггер обязан быть НАЗВАН по имени, законный близнец той же формы — пропущен
// молча. Без второй половины гейт ловил бы форму (`NEW.` в тексте), а не
// существо, и первое же ложное срабатывание его отключило бы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДНА ФУНКЦИЯ НА НЕСКОЛЬКО ТАБЛИЦ — ЗАКОННАЯ ФОРМА, И ГЕЙТ ЕЁ ЗНАЕТ
//
// Первая редакция разбора судила обращение по ОДНОЙ таблице и немедленно дала
// ложную находку: `kacho_iam.subject_ref_exists()` навешена и на `access_bindings`,
// и на `access_binding_subjects`, а `NEW.binding_id` называет колонку только
// второй — под явной веткой `TG_TABLE_NAME = 'access_binding_subjects'`. Гейт с
// такой находкой был бы снят первым же читателем, и вместе с ней ушла бы
// настоящая.
//
// Поэтому обращение судится по ВСЕМ таблицам, которые обслуживает функция, и
// правил два:
//
//	A. поле не принадлежит НИ ОДНОЙ из них — находка безусловно: исполнение
//	   отвергнет строку на любой из таблиц;
//	B. поле принадлежит СОСЕДНЕЙ таблице, но не этой, и тело НИ РАЗУ не называет
//	   `TG_TABLE_NAME` — находка: различать таблицы нечем, значит ветка выполнится
//	   и на той, у которой поля нет.
//
// ГРАНИЦА НАЗВАНА ЧЕСТНО: гейт не судит, ВЕРНО ли расставлены ветки. Функция на
// двух таблицах, называющая `TG_TABLE_NAME` хотя бы раз, признаётся различающей —
// разбирать поток управления plpgsql он не берётся, и притворяться, что берётся,
// было бы хуже, чем сказать это вслух.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// triggerFieldCensus — объём осмотренного. Печатается ВСЕГДА: перепись отделяет
// «находок нет» от «читать было нечего».
type triggerFieldCensus struct {
	Triggers int // сколько триггеров разобрано
	Refs     int // сколько обращений NEW./OLD.<поле> проверено
	Tables   int // сколько таблиц несут разобранные триггеры
}

func (c triggerFieldCensus) String() string {
	return fmt.Sprintf("осмотрено триггеров: %d на %d таблицах; проверено обращений к полям строки: %d",
		c.Triggers, c.Tables, c.Refs)
}

var (
	// Обращение к полю записи в теле plpgsql. Регистр в plpgsql не значим,
	// поэтому разбор нечувствителен к нему.
	triggerFieldRefRe = regexp.MustCompile(`(?i)\b(NEW|OLD)\.([a-z_][a-z0-9_]*)`)

	sqlBlockCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	sqlLineCommentRe  = regexp.MustCompile(`--[^\n]*`)
	sqlStringLiteral  = regexp.MustCompile(`'(?:[^']|'')*'`)
)

// stripSQLNoise убирает то, что телом не является: комментарии и строковые
// литералы.
//
// Порядок обязателен. Комментарии снимаются ПЕРВЫМИ: апостроф внутри
// комментария («ключ не читается — он больше никому не нужен») иначе открыл бы
// мнимый литерал и съел половину тела, а гейт молча перестал бы видеть
// обращения. Разбор без этого шага краснел бы на СОБСТВЕННОМ объяснении рядом
// с защитой — тот самый класс, который правила запрещают.
func stripSQLNoise(body string) string {
	body = sqlBlockCommentRe.ReplaceAllString(body, " ")
	body = sqlLineCommentRe.ReplaceAllString(body, " ")
	return sqlStringLiteral.ReplaceAllString(body, "''")
}

// triggerRow — один триггер: чью строку он получает, какой функцией и каким
// телом её читает.
type triggerRow struct {
	Table   string
	Trigger string
	FuncOID uint32
	Body    string
}

// loadTriggers читает НЕслужебные триггеры схемы вместе с телом их функции.
func loadTriggers(ctx context.Context, t *testing.T, pool *pgxpool.Pool, schema string) []triggerRow {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT c.relname, t.tgname, p.oid::int8, pg_get_functiondef(p.oid)
		  FROM pg_trigger   t
		  JOIN pg_class     c ON c.oid = t.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  JOIN pg_proc      p ON p.oid = t.tgfoid
		 WHERE NOT t.tgisinternal
		   AND n.nspname = $1
		 ORDER BY c.relname, t.tgname`, schema)
	require.NoError(t, err)
	defer rows.Close()

	var out []triggerRow
	for rows.Next() {
		var r triggerRow
		var oid int64
		require.NoError(t, rows.Scan(&r.Table, &r.Trigger, &oid, &r.Body))
		r.FuncOID = uint32(oid)
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// loadColumns читает состав колонок каждой таблицы схемы.
func loadColumns(ctx context.Context, t *testing.T, pool *pgxpool.Pool, schema string) map[string]map[string]bool {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT table_name, column_name
		  FROM information_schema.columns
		 WHERE table_schema = $1`, schema)
	require.NoError(t, err)
	defer rows.Close()

	byTable := map[string]map[string]bool{}
	for rows.Next() {
		var table, column string
		require.NoError(t, rows.Scan(&table, &column))
		if byTable[table] == nil {
			byTable[table] = map[string]bool{}
		}
		byTable[table][strings.ToLower(column)] = true
	}
	require.NoError(t, rows.Err())
	return byTable
}

// findTriggerFieldDrift — разбор: обращение к полю, которого у строки нет.
//
// Правила A и B описаны в шапке файла; здесь они только исполняются.
func findTriggerFieldDrift(ctx context.Context, t *testing.T, pool *pgxpool.Pool, schema string) ([]string, triggerFieldCensus) {
	t.Helper()
	triggers := loadTriggers(ctx, t, pool, schema)
	columns := loadColumns(ctx, t, pool, schema)

	// Какие таблицы обслуживает каждая функция: обращение судится по их СОВОКУПНОСТИ,
	// а не по той таблице, на которой оно встретилось.
	served := map[uint32]map[string]bool{}
	for _, tr := range triggers {
		if served[tr.FuncOID] == nil {
			served[tr.FuncOID] = map[string]bool{}
		}
		served[tr.FuncOID][tr.Table] = true
	}

	var findings []string
	census := triggerFieldCensus{Triggers: len(triggers)}
	tables := map[string]bool{}

	for _, tr := range triggers {
		tables[tr.Table] = true
		body := stripSQLNoise(tr.Body)
		discriminates := strings.Contains(strings.ToUpper(body), "TG_TABLE_NAME")

		seen := map[string]bool{}
		for _, m := range triggerFieldRefRe.FindAllStringSubmatch(body, -1) {
			field := strings.ToLower(m[2])
			census.Refs++
			if columns[tr.Table][field] || seen[field] {
				continue
			}

			// Правило A: поле не принадлежит ни одной обслуживаемой таблице.
			sibling := ""
			for other := range served[tr.FuncOID] {
				if other != tr.Table && columns[other][field] {
					sibling = other
					break
				}
			}
			if sibling != "" {
				// Правило B: сосед есть, но различать таблицы нечем.
				if discriminates {
					continue
				}
				seen[field] = true
				findings = append(findings, fmt.Sprintf(
					"%s.%s: триггер %q обращается к %s.%s; колонка %q есть у соседней таблицы %q, "+
						"которую обслуживает та же функция, но тело НИ РАЗУ не называет TG_TABLE_NAME — "+
						"различать таблицы нечем, и ветка выполнится на той, у которой поля нет (42703)",
					schema, tr.Table, tr.Trigger, strings.ToUpper(m[1]), field, field, sibling))
				continue
			}

			seen[field] = true
			findings = append(findings, fmt.Sprintf(
				"%s.%s: триггер %q обращается к %s.%s, а колонки %q нет НИ У ОДНОЙ таблицы, которую "+
					"обслуживает его функция — вставка отвергнется на исполнении (42703), и текст отказа "+
					"не назовёт ни таблицы, ни триггера",
				schema, tr.Table, tr.Trigger, strings.ToUpper(m[1]), field, field))
		}
	}
	census.Tables = len(tables)
	sort.Strings(findings)
	return findings, census
}

// TestTriggerBodyMatchesRowShape — по ВСЕЙ схеме iam: ни один триггер не называет
// поля, которого у его строки нет.
func TestTriggerBodyMatchesRowShape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	findings, census := findTriggerFieldDrift(ctx, t, pool, "kacho_iam")
	t.Log(census)

	// Предпосылка гейта. Схема без триггеров сделала бы «ноль находок»
	// тождественно истинным, и молчание перестало бы что-либо означать.
	require.NotZero(t, census.Triggers,
		"в схеме kacho_iam не разобрано НИ ОДНОГО триггера: гейт беспредметен, "+
			"а его молчание неотличимо от исправности")
	require.NotZero(t, census.Refs,
		"ни одного обращения NEW./OLD.<поле> не разобрано: тела прочитаны, но "+
			"разбор их не читает — молчание гейта ничего не утверждает")

	for _, f := range findings {
		t.Error(f)
	}
}

// TestJournalAcceptsAWriteAfterEveryMigration — конкретный экземпляр класса, тот
// самый, на котором он был найден (kacho#1033).
//
// Утверждается ИСХОД пути мутации, а не наличие или отсутствие триггера: набор
// колонок здесь дословно тот, который вставляет `fga_outbox.EmitWriteTx`, то
// есть проба спрашивает у базы ровно то же, что спросит выдача доступа. Гейт
// выше нашёл бы тот же дефект раньше и по всей схеме; эта проба остаётся, потому
// что она называет ПОСЛЕДСТВИЕ («выдать доступ нельзя»), а гейт — причину.
func TestJournalAcceptsAWriteAfterEveryMigration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at)
		 VALUES ('fga.tuple.write',
		         '{"user":"user:usr01","relation":"v_get","object":"vpc_network:net01"}'::jsonb,
		         now())`)
	require.NoError(t, err,
		"журнал намерений обязан принимать строку тем же набором колонок, каким её "+
			"вставляет fga_outbox.EmitWriteTx. Отказ здесь означает, что отвергнута "+
			"КАЖДАЯ выдача и КАЖДЫЙ отзыв доступа, а не только эта проба")
}

// TestTriggerBodyFieldRefsProvenByInjection — доказательство в ОБЕ стороны, по
// каждому из двух правил.
//
// (а) верни дефект — разбор краснеет и НАЗЫВАЕТ координату (таблицу, триггер,
//
//	поле);
//
// (б) поставь рядом законный близнец той же формы — разбор молчит.
//
// Без (б) гейт утверждал бы «в теле встречается NEW.» — форму, а не существо: тела
// триггеров состоят из таких обращений, и первое же ложное срабатывание сняло бы
// гейт целиком. Близнец здесь не выдуман: это ДОСЛОВНАЯ форма
// `kacho_iam.subject_ref_exists()`, на которой первая редакция разбора и дала
// ложную находку — одна функция на двух таблицах, поле только у второй, ветка по
// TG_TABLE_NAME.
//
// Инъекция идёт в СВОЮ схему, а не в kacho_iam: проба не вправе править
// состояние, которого не заводила, и её падение не должно оставлять после себя
// сломанную таблицу продукта.
func TestTriggerBodyFieldRefsProvenByInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const schema = "kacho_iam_trigger_probe"
	for _, stmt := range []string{
		`CREATE SCHEMA ` + schema,
		`CREATE TABLE ` + schema + `.widgets (id bigserial PRIMARY KEY, payload jsonb, label text)`,
		`CREATE TABLE ` + schema + `.widget_parts (id bigserial PRIMARY KEY, payload jsonb, widget_id bigint)`,

		// (б1) законный близнец правила A: тело называет колонки, которые у строки
		// есть, и рядом — апостроф в комментарии и строковый литерал, на которых
		// наивный разбор споткнулся бы.
		`CREATE FUNCTION ` + schema + `.widgets_lawful() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
		     -- ключ строки — это label, и он у неё есть
		     NEW.label := coalesce(NEW.payload->>'user', 'anonymous');
		     RETURN NEW;
		 END; $fn$`,
		`CREATE TRIGGER widgets_lawful_trigger BEFORE INSERT ON ` + schema + `.widgets
		 FOR EACH ROW EXECUTE FUNCTION ` + schema + `.widgets_lawful()`,

		// (б2) законный близнец правила B: ОДНА функция на ДВУХ таблицах, поле есть
		// только у второй, и тело различает таблицы явно. Это форма
		// kacho_iam.subject_ref_exists(); разбор обязан её пропустить.
		`CREATE FUNCTION ` + schema + `.shared_discriminating() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
		     IF TG_TABLE_NAME = 'widget_parts' THEN
		         PERFORM 1 FROM ` + schema + `.widgets WHERE id = NEW.widget_id;
		     END IF;
		     RETURN NEW;
		 END; $fn$`,
		`CREATE TRIGGER widgets_shared_ok_trigger BEFORE INSERT ON ` + schema + `.widgets
		 FOR EACH ROW EXECUTE FUNCTION ` + schema + `.shared_discriminating()`,
		`CREATE TRIGGER parts_shared_ok_trigger BEFORE INSERT ON ` + schema + `.widget_parts
		 FOR EACH ROW EXECUTE FUNCTION ` + schema + `.shared_discriminating()`,

		// (а1) дефект правила A: тело называет поле, которого нет ни у одной
		// обслуживаемой таблицы.
		`CREATE FUNCTION ` + schema + `.widgets_drifted() RETURNS trigger LANGUAGE plpgsql AS $fn$
		 BEGIN
		     NEW.tuple_key := NEW.payload->>'user';
		     RETURN NEW;
		 END; $fn$`,
		`CREATE TRIGGER widgets_drifted_trigger BEFORE INSERT ON ` + schema + `.widgets
		 FOR EACH ROW EXECUTE FUNCTION ` + schema + `.widgets_drifted()`,
	} {
		_, err := pool.Exec(ctx, stmt)
		require.NoError(t, err, "синтетическая схема не создана: инъекция ничего не доказывает")
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})

	findings, census := findTriggerFieldDrift(ctx, t, pool, schema)
	t.Log(census)
	require.Equal(t, 4, census.Triggers, "разобраны не все триггеры синтетической схемы")

	require.Len(t, findings, 1,
		"разбор обязан назвать РОВНО дефектный триггер: одна находка на дефект и "+
			"молчание на обоих законных близнецах.\nнайдено:\n%s", strings.Join(findings, "\n"))
	require.Contains(t, findings[0], "widgets_drifted_trigger",
		"находка обязана НАЗЫВАТЬ координату — без имени триггера её не по чему искать")
	require.Contains(t, findings[0], "tuple_key",
		"находка обязана называть поле, которого у строки нет")

	// Вторая половина названа отдельными утверждениями, а не выведена из числа:
	// «находка одна» осталось бы верным и в случае, когда разбор нашёл законный
	// триггер, а дефектный пропустил.
	require.NotContains(t, findings[0], "widgets_lawful_trigger",
		"законный триггер, называющий только свои колонки, обязан быть пропущен молча")
	require.NotContains(t, findings[0], "shared_ok_trigger",
		"общая функция, различающая таблицы по TG_TABLE_NAME, обязана быть пропущена молча")

	// Правило B обязано УМЕТЬ сработать. Без этого утверждения оно было бы
	// объявлено и никогда не проверено: его молчание выше неотличимо от того, что
	// оно не исполняется вовсе.
	_, err = pool.Exec(ctx, `CREATE OR REPLACE FUNCTION `+schema+`.shared_discriminating() RETURNS trigger LANGUAGE plpgsql AS $fn$
	 BEGIN
	     PERFORM 1 FROM `+schema+`.widgets WHERE id = NEW.widget_id;
	     RETURN NEW;
	 END; $fn$`)
	require.NoError(t, err)
	blind, _ := findTriggerFieldDrift(ctx, t, pool, schema)
	require.Len(t, blind, 2,
		"сняв ветку TG_TABLE_NAME с общей функции, мы оставили обращение к полю, которого у "+
			"одной из её таблиц нет: правило B обязано это назвать.\nнайдено:\n%s",
		strings.Join(blind, "\n"))
	joined := strings.Join(blind, "\n")
	require.Contains(t, joined, "widgets_shared_ok_trigger",
		"правило B обязано назвать ту таблицу, у которой поля НЕТ")
	require.NotContains(t, joined, "parts_shared_ok_trigger",
		"у widget_parts колонка widget_id есть — на ней правило B обязано молчать")

	// Дефект обязан быть НАСТОЯЩИМ: если синтетическая вставка проходит, инъекция
	// воспроизвела не тот класс, и зелёный гейт ничего не значит.
	_, err = pool.Exec(ctx, `INSERT INTO `+schema+`.widgets (payload) VALUES ('{"user":"u"}'::jsonb)`)
	require.Error(t, err, "инъекция не воспроизвела класс: вставка прошла, значит дефекта не было")
	require.Contains(t, err.Error(), "42703",
		"инъекция обязана давать ТОТ ЖЕ отказ, ради которого гейт заведён")
}
