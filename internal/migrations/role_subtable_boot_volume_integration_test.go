// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// role_subtable_boot_volume_integration_test.go — ПОЧЕМУ три подтаблицы роли
// (`role_verb`, `role_rule_ref`, `role_rule_selectors`) событий НЕ эмитят, тогда
// как три подтаблицы состава (`group_members`, `memberships`,
// `access_binding_subjects`) эмитят правку владельца.
//
// Задача #73. Решение записано в шапке владельца журнала
// (`internal/subscriptionjournal/journal.go`,
// §«Подтаблицы РОЛИ событий НЕ эмитят»); здесь —
// ПРОИЗВОДИТЕЛЬ его числа и пара, на которой решение стоит.
//
// # Что опровергает предикат задачи
//
// Задача предлагала завести триггеры «с тем же сужением, что у трёх живых
// подтаблиц», а мерой брала долю строк, меняющих существо
// (`OLD.* IS DISTINCT FROM NEW.*`). Замер опровергает обе половины постановки:
//
//   - сужения, о котором речь, у трёх ЖИВЫХ подтаблиц НЕТ вовсе — их триггеры
//     объявлены `AFTER INSERT OR DELETE` без `WHEN`. Сужение по существу стоит
//     на семи ОСНОВНЫХ таблицах, а не на подтаблицах;
//   - к двум таблицам из трёх оно НЕПРИМЕНИМО by construction: оператора
//     `UPDATE` над ними не существует ни одного, обе пишутся ПОЛНОЙ ЗАМЕНОЙ
//     («снять всё по роли, положить текущее»), то есть событиями DELETE+INSERT,
//     которых предикат существа не касается;
//   - к третьей оно ИНЕРТНО: досев старта кладёт строку `ON CONFLICT DO UPDATE
//     … updated_at = now()`, поэтому `OLD.* IS DISTINCT FROM NEW.*` истинно
//     ВСЕГДА, даже когда не изменилось ничего.
//
// Отсюда исход: триггеры не заводятся. Не потому, что «доля велика», а потому
// что сужение отсекает НОЛЬ, и подъём на неизменном мире рождал бы полный объём
// проекции событиями, в которых ничего не произошло.
//
// # Чего эта проба НЕ утверждает
//
// Она не судит прод-код: что КАЖДЫЙ путь, меняющий состав роли, пишет строку
// роли той же транзакцией, — свойство девяти вызовов трёх `Replace*`, и держится
// оно адъюдикацией в шапке владельца, а не отсюда. Проба утверждает свойство
// СХЕМЫ: правка строки роли событие даёт, холостой подъём — не даёт, а запись
// подтаблицы в обход строки роли не даёт его тоже (остаток, названный в §3).

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// roleSubtables — три подтаблицы роли, чьё молчание и есть предмет пробы.
var roleSubtables = []string{"role_verb", "role_rule_ref", "role_rule_selectors"}

// freshIamPool — своя база с целиком накатанной цепью миграций и пул к ней.
//
// Пул, а не `*sql.DB`: полосы подъёма принимают `*pgxpool.Pool`. Цепь катается
// здесь, потому что шаблон этого пакета ПУСТ намеренно (страж сноса ходит по
// цепи сам) — взять мигрированную базу из шаблона тут нечем.
func freshIamPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(db, "."), "цепь миграций обязана накатиться целиком")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// installRowCensus вешает на три подтаблицы счётчики строковых событий.
//
// Осей четыре, и две последние — ПАРА: `UPDATE_ALL` считает все правки, а
// `UPDATE_DISTINCT` — только прошедшие то самое сужение, которое предлагала
// задача. Одна ось без другой не отличила бы «сужение отсекло» от «правок не
// было»: обе дали бы одно число.
func installRowCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
CREATE TABLE kaname.row_census (tbl text, op text, n bigint, PRIMARY KEY (tbl, op));
CREATE FUNCTION kaname.row_census_bump() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO kaname.row_census (tbl, op, n) VALUES (TG_TABLE_NAME, TG_ARGV[0], 1)
    ON CONFLICT (tbl, op) DO UPDATE SET n = kaname.row_census.n + 1;
  RETURN NULL;
END; $$;`)
	require.NoError(t, err)

	for _, tbl := range roleSubtables {
		for _, stmt := range []string{
			`CREATE TRIGGER row_census_insert_trg AFTER INSERT ON kaname.%s
			   FOR EACH ROW EXECUTE FUNCTION kaname.row_census_bump('INSERT')`,
			`CREATE TRIGGER row_census_delete_trg AFTER DELETE ON kaname.%s
			   FOR EACH ROW EXECUTE FUNCTION kaname.row_census_bump('DELETE')`,
			`CREATE TRIGGER row_census_update_trg AFTER UPDATE ON kaname.%s
			   FOR EACH ROW EXECUTE FUNCTION kaname.row_census_bump('UPDATE_ALL')`,
			// Ровно тот предикат, который предлагала задача.
			`CREATE TRIGGER row_census_update_distinct_trg AFTER UPDATE ON kaname.%s
			   FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*)
			   EXECUTE FUNCTION kaname.row_census_bump('UPDATE_DISTINCT')`,
		} {
			_, err := pool.Exec(ctx, fmt.Sprintf(stmt, tbl))
			require.NoError(t, err)
		}
	}
}

// readRowCensus снимает перепись и обнуляет её для следующего подъёма.
func readRowCensus(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (map[string]int64, int64) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT tbl, op, n FROM kaname.row_census`)
	require.NoError(t, err)
	defer rows.Close()

	census := map[string]int64{}
	var total int64
	for rows.Next() {
		var tbl, op string
		var n int64
		require.NoError(t, rows.Scan(&tbl, &op, &n))
		census[tbl+"/"+op] = n
		// `UPDATE_DISTINCT` — подмножество `UPDATE_ALL`, и в сумму строковых
		// событий не идёт: иначе одна правка считалась бы дважды.
		if op != "UPDATE_DISTINCT" {
			total += n
		}
	}
	require.NoError(t, rows.Err())

	_, err = pool.Exec(ctx, `DELETE FROM kaname.row_census`)
	require.NoError(t, err)
	return census, total
}

// logRowCensus печатает перепись — без неё «ноль событий журнала» неотличимо от
// «подъём не тронул ни одной строки», то есть от вакуумного отрицания.
func logRowCensus(t *testing.T, label string, census map[string]int64, total int64) {
	t.Helper()
	keys := make([]string, 0, len(census))
	for k := range census {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("перепись строковых событий, %s: всего %d", label, total)
	for _, k := range keys {
		t.Logf("    %-34s %d", k, census[k])
	}
}

// journalRowsOfKind — сколько событий журнала про предмет этого вида.
func journalRowsOfKind(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kind string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_journal WHERE resource_kind = $1`, kind).Scan(&n))
	return n
}

// truncateJournal — обнуление ленты между частями пробы.
func truncateJournal(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `DELETE FROM kaname.resource_journal`)
	require.NoError(t, err)
}

// runBootLanes — три полосы подъёма, ровно те и в том порядке, в каком их зовёт
// композиционный корень (`cmd/kaname/serve.go`): досев селекторов, пересчёт
// проекции глаголов, пересчёт проекции сегментов правила.
//
// Каталог берётся НАСТОЯЩИЙ — снимок наполняется теми же строками, что читает
// страж паритета на старте. Фикстура каталога дала бы другое число пар, и замер
// говорил бы о ней, а не о продукте.
func runBootLanes(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	catalogRepo := kanamepg.NewCatalogRepo(pool)
	parity, err := seed.AssertCatalogParity(ctx, catalogRepo, seed.ImageAnchor())
	require.NoError(t, err, "страж паритета каталога")
	snapshot, err := catalog.NewSnapshot(parity.Live, catalogRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))
	verbs, err := seed.ReseedSystemRoleVerbs(
		ctx, kanamepg.New(pool, nil), pool, snapshot.Facts(), nil)
	require.NoError(t, err)
	refs, err := seed.ReseedSystemRoleRuleRefs(ctx, kanamepg.New(pool, nil), pool, nil)
	require.NoError(t, err)

	t.Logf("перепись досева: ролей осмотрено %d, пар %d, сегментов %d",
		verbs.Examined, verbs.Pairs, refs.Refs)
	require.NotZero(t, verbs.Examined,
		"системных ролей ноль: подъём беспредметен, и всякое отрицание ниже "+
			"выполнилось бы тривиально")
}

// TestIntegration_RoleCompositionIsObservableThroughTheRoleRow — #73.
func TestIntegration_RoleCompositionIsObservableThroughTheRoleRow(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := freshIamPool(t, ctx)

	// Первый подъём наполняет проекции: он не устоявшийся и мерой не служит.
	installRowCensus(t, ctx, pool)
	runBootLanes(t, ctx, pool)
	_, firstTotal := readRowCensus(t, ctx, pool)
	t.Logf("первый подъём (наполнение проекций): строковых событий %d", firstTotal)

	// ── §1. ЗАМЕР: устоявшийся подъём, в мире не изменилось НИЧЕГО ──────────
	truncateJournal(t, ctx, pool)
	runBootLanes(t, ctx, pool)
	census, total := readRowCensus(t, ctx, pool)
	logRowCensus(t, "устоявшийся подъём", census, total)

	require.NotZero(t, total,
		"подъём не тронул ни одной строки трёх подтаблиц — отрицание ниже "+
			"стало бы вакуумным, а замер беспредметным")

	// Сужение, предложенное задачей, отсекает НОЛЬ: над двумя таблицами правок
	// нет вовсе, а над третьей все правки проходят предикат существа.
	var narrowedAway int64
	for _, tbl := range roleSubtables {
		all, distinct := census[tbl+"/UPDATE_ALL"], census[tbl+"/UPDATE_DISTINCT"]
		narrowedAway += all - distinct
	}
	assert.Zero(t, narrowedAway,
		"сужение `OLD.* IS DISTINCT FROM NEW.*` отсекло бы %d строковых событий "+
			"из %d: над двумя таблицами оператора UPDATE нет вовсе (полная замена "+
			"даёт DELETE+INSERT), а досев селекторов двигает `updated_at = now()`, "+
			"поэтому предикат существа на нём истинен всегда", narrowedAway, total)

	assert.Zero(t, journalRowsOfKind(t, ctx, pool, "iam_role"),
		"холостой подъём родил события журнала: ничего не изменилось, а "+
			"подписчик получил бы %d правок роли", total)

	// ── §2. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: правка строки роли событие ДАЁТ ─────────
	//
	// Без него отрицание выше зеленело бы и на журнале, который не пишет НИЧЕГО
	// и ни при каких условиях.
	truncateJournal(t, ctx, pool)
	var roleID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.roles ORDER BY id LIMIT 1`).Scan(&roleID))
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.roles SET description = description || ' (правка)', updated_at = now()
		  WHERE id = $1`, roleID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())

	assert.EqualValues(t, 1, journalRowsOfKind(t, ctx, pool, "iam_role"),
		"правка строки роли обязана дать РОВНО одно событие: на ней и стоит "+
			"наблюдаемость состава — путь арендатора пишет строку роли той же "+
			"транзакцией, что и подтаблицы")

	// ── §3. ОСТАТОК, НАЗВАННЫЙ ВСЛУХ ────────────────────────────────────────
	//
	// Запись подтаблицы В ОБХОД строки роли события не даёт. Производитель у
	// этого в продукте ОДИН — путь последствий каталога: снятие строки каталога
	// отбирает у роли глагол либо сегмент (`role_verb`/`role_rule_ref` →
	// `role_grant_orphan`, `role_rule_selectors` → `role_selector_prune`), и
	// строку роли он не трогает НИ ОДНИМ оператором.
	//
	// Утверждение ПРИБИТО намеренно: пока оно зелено, остаток жив. Закроет его
	// своя задача — и эта половина перевернётся вместе с ней, а не тихо
	// разойдётся с деревом.
	truncateJournal(t, ctx, pool)
	del, err := pool.Exec(ctx,
		`DELETE FROM kaname.role_verb WHERE role_id = $1`, roleID)
	require.NoError(t, err)
	require.NotZero(t, del.RowsAffected(),
		"у роли не оказалось строк проекции: утверждение ниже стало бы вакуумным")

	assert.Zero(t, journalRowsOfKind(t, ctx, pool, "iam_role"),
		"ОСТАТОК: отзыв права через подтаблицу в обход строки роли подписчику "+
			"не виден — это названный остаток решения #73, а не находка пробы")
}
