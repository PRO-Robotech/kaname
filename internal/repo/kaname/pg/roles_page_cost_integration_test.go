// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// roles_page_cost_integration_test.go — задача #1964: страница фиксированного
// размера обязана стоить одинаково при любой населённости таблицы ролей.
//
// # Что здесь утверждается
//
// Конвенция продукта (`api-conventions.md` §Pagination) объявляет курсор
// `(created_at, id)` и порядок по нему. Смысл курсора в том, что N-я страница
// стоит как первая. Держится это НЕ конвенцией, а путём доступа: без
// упорядоченного пути планировщик обязан отсортировать всё, что пережило
// отбор, чтобы отдать сто строк, — и тогда цена страницы принадлежит таблице,
// а не странице.
//
// Несущая величина — БЛОКИ, а не миллисекунды: время есть свойство машины,
// блоки — свойство плана.
//
// # Почему рядом стоит контроль с выключенным индексным путём
//
// Утверждение «не растёт» зелено и на пробе, которая роста не увидела бы
// НИКОГДА — например если населённость слишком мала, чтобы различие
// проявилось. Поэтому та же величина снимается ещё раз при запрещённом
// индексном доступе: там она обязана вырасти. Контроль, не показавший роста,
// роняет пробу — он доказывает, что измеряется не то, что объявлено.
//
// # Чем это НЕ является
//
// Не проверкой существования индекса — это свойство схемы, и его держит
// перепись `TestListCursor_EveryPagedTableHasItsIndex`. Здесь спрашивается
// ИСХОД: во что этот индекс обходится странице.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// Запросы страницы — обе полосы пути чтения ролей: порядок по курсору, окно
// на страницу плюс строка предпросмотра.
//
// Полос ДВЕ, и мерить надо обе. Полоса администратора облака набор кандидатов
// не сужает вовсе; полоса арендатора несёт дизъюнкт кандидатов, который
// индексом не обслуживается НИ ПРИ КАКОМ индексе, — и если бы он заставлял
// планировщик бросать упорядоченный путь, свойство «цена принадлежит странице»
// держалось бы только у администратора. Одна из двух полос молчала бы о второй.
//
// Столбцы взяты звёздочкой намеренно: предмет пробы — ПУТЬ ДОСТУПА, а он один
// и тот же на любом перечне столбцов, тогда как выписанный перечень разошёлся
// бы с репозиторием на первой же новой колонке и стал бы вторым местом об
// одном предмете.
var rolesPageStatements = map[string]string{
	"администратор облака: набор кандидатов не сужается": `
		SELECT * FROM kaname.roles
		 ORDER BY created_at ASC, id ASC LIMIT 101`,
	"арендатор: дизъюнкт кандидатов, индексом не обслуживаемый": `
		SELECT * FROM kaname.roles
		 WHERE (is_system OR account_id = ANY(ARRAY['acc-nonexistent']) OR id = ANY(ARRAY['rol-nonexistent']))
		 ORDER BY created_at ASC, id ASC LIMIT 101`,
}

// planShape — то, что проба читает из разбора плана.
type planShape struct {
	blocks    int
	nodeTypes []string
	indexes   []string
}

// explainRolesPage снимает план страницы и его буферы.
//
// `settings` применяются как `SET LOCAL` в той же транзакции, поэтому контроль
// не может протечь в следующий замер.
func explainRolesPage(ctx context.Context, t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, statement string, settings ...string) planShape {
	t.Helper()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	for _, s := range settings {
		_, err = tx.Exec(ctx, s)
		require.NoError(t, err, "не применилась настройка плана: %s", s)
	}

	var raw []byte
	require.NoError(t, tx.QueryRow(ctx,
		`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+statement).Scan(&raw))

	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &plans))
	require.Len(t, plans, 1, "разбор плана пуст — мерить нечего")

	root := plans[0].Plan
	shape := planShape{}
	// Буферы верхнего узла в JSON-разборе включают потомков, поэтому корня
	// достаточно и суммировать по дереву не надо.
	for _, k := range []string{"Shared Hit Blocks", "Shared Read Blocks"} {
		if v, ok := root[k].(float64); ok {
			shape.blocks += int(v)
		}
	}
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		if nt, ok := node["Node Type"].(string); ok {
			shape.nodeTypes = append(shape.nodeTypes, nt)
		}
		if ix, ok := node["Index Name"].(string); ok {
			shape.indexes = append(shape.indexes, ix)
		}
		kids, ok := node["Plans"].([]any)
		if !ok {
			return
		}
		for _, kid := range kids {
			if m, ok := kid.(map[string]any); ok {
				walk(m)
			}
		}
	}
	walk(root)
	return shape
}

func TestRolesPage_CostBelongsToThePageNotToThePopulation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Точки сетки — те же три, на которых задача #1964 назвала рост.
	populations := []int{1000, 2000, 4000}

	type point struct {
		rows      int
		indexed   planShape
		unindexed planShape
	}

	// Полосы обходятся ПО ИМЕНИ множества, а не выписанным списком: полоса,
	// добавленная в перечень выше и забытая здесь, осталась бы неизмеренной, а
	// вердикт — зелёным.
	lanes := make([]string, 0, len(rolesPageStatements))
	for name := range rolesPageStatements {
		lanes = append(lanes, name)
	}
	sort.Strings(lanes)
	require.NotEmpty(t, lanes, "полос ноль — мерить нечего")

	measured := map[string][]point{}
	for _, want := range populations {
		rows := seedRolesVia(ctx, t, pool, want)
		require.GreaterOrEqual(t, rows, want, "население не набрано — замер беспредметен")

		for _, lane := range lanes {
			stmt := rolesPageStatements[lane]
			indexed := explainRolesPage(ctx, t, pool, stmt)
			// Контроль: тот же запрос БЕЗ индексного пути. Он обязан подорожать
			// с населением — иначе проба не умеет видеть роста и её «не растёт»
			// ничего не значит.
			unindexed := explainRolesPage(ctx, t, pool, stmt,
				`SET LOCAL enable_indexscan = off`,
				`SET LOCAL enable_bitmapscan = off`,
				`SET LOCAL enable_indexonlyscan = off`)

			measured[lane] = append(measured[lane], point{rows: rows, indexed: indexed, unindexed: unindexed})
			t.Logf("перепись: полоса «%s» · строк %d · блоков по индексному пути %d · без него %d · узлы %s · индексы %s",
				lane, rows, indexed.blocks, unindexed.blocks,
				strings.Join(indexed.nodeTypes, ","), strings.Join(indexed.indexes, ","))
		}
	}
	require.Len(t, measured, len(lanes), "снято меньше полос, чем объявлено")

	for _, lane := range lanes {
		pts := measured[lane]
		require.Len(t, pts, len(populations), "полоса «%s»: снято меньше точек, чем объявлено", lane)
		first, last := pts[0], pts[len(pts)-1]

		// 1. Путь доступа: страница читается ПО КУРСОРУ, а не сортировкой всего.
		require.Contains(t, strings.Join(first.indexed.indexes, ","), "roles_cursor_idx",
			"полоса «%s»: страница не идёт через курсорный индекс: узлы %v, индексы %v",
			lane, first.indexed.nodeTypes, first.indexed.indexes)
		require.NotContains(t, first.indexed.nodeTypes, "Sort",
			"полоса «%s»: в плане страницы стоит сортировка — цена страницы принадлежит таблице", lane)

		// 2. Положительный контроль пробы: без индексного пути та же страница
		//    ОБЯЗАНА дорожать с населением. Не подорожала — проба слепа, и её
		//    утверждение ниже зелено при любом плане.
		require.Greater(t, last.unindexed.blocks, first.unindexed.blocks,
			"полоса «%s»: контроль без индексного пути не подорожал (%d → %d) — проба не видит роста",
			lane, first.unindexed.blocks, last.unindexed.blocks)

		// 3. Несущее утверждение: по индексному пути цена страницы НЕ растёт с
		//    населением. Допуск — половина от первой точки: шум статистики и
		//    границы страниц.
		require.LessOrEqual(t, last.indexed.blocks, first.indexed.blocks+first.indexed.blocks/2,
			"полоса «%s»: страница подорожала с населением: %d строк — %d блоков, %d строк — %d блоков",
			lane, first.rows, first.indexed.blocks, last.rows, last.indexed.blocks)

		t.Logf("итог полосы «%s»: страница из 100 строк стоит %d блоков при %d строках и %d блоков при %d строках "+
			"(без индексного пути %d → %d)",
			lane, first.indexed.blocks, first.rows, last.indexed.blocks, last.rows,
			first.unindexed.blocks, last.unindexed.blocks)
	}
}

// seedRolesVia доводит население таблицы ролей до want строк.
//
// Строки заводятся кластерного яруса и опираются на УЖЕ существующий кластер:
// свой ярус потребовал бы своего аккаунта со своими ограничениями, а предмет
// пробы — план чтения, а не форма строки. Статистика пересобирается сразу:
// планировщик судит по ней, и без неё замер был бы о её отсутствии.
func seedRolesVia(ctx context.Context, t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, want int) int {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	var have int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.roles`).Scan(&have))
	if have < want {
		_, err = tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO kaname.roles (id, cluster_id, name, permissions, created_at)
			SELECT 'rol' || lpad(g::text, 17, '0'),
			       (SELECT cluster_id FROM kaname.roles WHERE is_system AND cluster_id IS NOT NULL LIMIT 1),
			       'seedrole-' || lpad(g::text, 9, '0'),
			       (SELECT permissions FROM kaname.roles WHERE is_system AND jsonb_array_length(permissions) > 0 LIMIT 1),
			       now() + (g || ' milliseconds')::interval
			  FROM generate_series(%d, %d) g`, have+1, want))
		require.NoError(t, err)
		require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.roles`).Scan(&have))
	}
	require.NoError(t, tx.Commit(ctx))

	txa, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = txa.Exec(ctx, `ANALYZE kaname.roles`)
	require.NoError(t, err)
	require.NoError(t, txa.Commit(ctx))
	return have
}
