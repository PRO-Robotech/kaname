// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// selector_type_membership_integration_test.go — задача #2053: отбор селекторов
// по типу объекта обязан идти формой, которую обслуживает GIN.
//
// # Предмет
//
// Столбец `role_rule_selectors.object_types` — массив, и под ним стоит GIN.
// GIN обслуживает `@>` / `&&` / `=`, но НЕ `скаляр = ANY(массив)`: на этой
// форме планировщик индекс не берёт вовсе и читает столбец последовательно.
// Семантика у форм одна, путь доступа — разный, и различие видно только
// планом.
//
// # Здесь ДВА разных утверждения, и они намеренно разведены
//
//  1. ФОРМА в дереве — свойство исходников, спрашивается без базы;
//  2. ИСХОД в базе — что GIN действительно обслуживает одну форму и не
//     обслуживает другую. Это не предположение из документации движка: обе
//     формы прогоняются на населённой таблице, и старая работает здесь
//     ДВОЙНИКОМ-ДЕФЕКТОМ — то есть способность пробы различить пути доказана
//     тем же прогоном, а не отдельной инъекцией.
//
// Утверждать «результат тот же» было бы бессодержательно: он тот же и на
// последовательном чтении, поэтому такая проба зеленела бы при неснятом
// дефекте.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// selectorMembershipSources — исходники, где живёт отбор селекторов по типу.
// Перечень узкий и назван: предмет — конкретный отбор, а не всякое упоминание
// столбца в дереве.
var selectorMembershipSources = []string{"reconcile_adapter.go"}

// TestSelectorTypeMembership_UsesTheContainmentForm — форма отбора в дереве.
//
// Без базы: это свойство исходников, и держать его прогоном хранилища значило
// бы не проверять его там, где прогона нет.
func TestSelectorTypeMembership_UsesTheContainmentForm(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	require.NoError(t, err)

	scanned, scalarAny, containment := 0, 0, 0
	var offenders []string
	for _, name := range selectorMembershipSources {
		raw, rerr := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, rerr, "исходник отбора не прочитан: %s", name)
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			// Форма СКАЛЯР = ANY(массив) — та, которую GIN не обслуживает.
			if strings.Contains(line, "= ANY(rrs.object_types)") {
				scalarAny++
				offenders = append(offenders, filepathLine(name, i+1, line))
			}
			if strings.Contains(line, "rrs.object_types @>") {
				containment++
			}
		}
	}
	t.Logf("перепись: исходников прочитано %d, отборов формой членства %d, формой скаляр-в-массиве %d",
		scanned, containment, scalarAny)

	require.NotZero(t, scanned, "перепись не прочитала ни одного исходника — вердикт беспредметен")
	require.NotZero(t, containment,
		"перепись не нашла НИ ОДНОГО отбора по типу — она смотрит не туда, и её ноль ничего не значит")
	require.Empty(t, offenders,
		"отбор идёт формой, которую GIN не обслуживает:\n%s", strings.Join(offenders, "\n"))
}

func filepathLine(name string, no int, line string) string {
	return name + ":" + itoa(no) + ": " + strings.TrimSpace(line)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestSelectorTypeMembership_GinServesContainmentNotScalarAny — исход в базе.
func TestSelectorTypeMembership_GinServesContainmentNotScalarAny(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		// Тип, по которому идёт отбор, — РЕДКИЙ в населении: на типе,
		// которым помечена вся таблица, индекс не выигрывает ни при какой
		// форме, и проба была бы зелена по причине, к предмету не
		// относящейся.
		probedType = "iam.role"
		bulkType   = "vpc.network"
		population = 3000
	)

	rows := seedRolesVia(ctx, t, pool, population)
	require.GreaterOrEqual(t, rows, population, "население ролей не набрано — селекторы не на что повесить")

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.role_rule_selectors
		       (role_id, rule_fp, arm, object_types, resource_names, match_labels)
		SELECT r.id, md5(r.id), 'anchor',
		       CASE WHEN (row_number() OVER (ORDER BY r.id)) % 500 = 0
		            THEN ARRAY[$1::text] ELSE ARRAY[$2::text] END,
		       '{}'::text[], '{}'::jsonb
		  FROM kacho_iam.roles r
		 WHERE r.id LIKE 'rol0%'
		ON CONFLICT DO NOTHING`, probedType, bulkType)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	txa, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = txa.Exec(ctx, `ANALYZE kacho_iam.role_rule_selectors`)
	require.NoError(t, err)
	require.NoError(t, txa.Commit(ctx))

	var selectors, matching int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*), count(*) FILTER (WHERE object_types @> ARRAY[$1::text])
		   FROM kacho_iam.role_rule_selectors`, probedType).Scan(&selectors, &matching))
	t.Logf("перепись: строк селекторов %d, из них с искомым типом %d", selectors, matching)
	require.Greater(t, selectors, 1000,
		"населения мало — планировщик выберет последовательное чтение при ЛЮБОЙ форме, и проба ничего не различит")
	require.NotZero(t, matching, "искомого типа нет ни в одной строке — отбор пуст, различать нечего")

	// Обе формы — один и тот же вопрос, разными словами.
	containment := explainSelectorPredicate(ctx, t, pool,
		`SELECT role_id FROM kacho_iam.role_rule_selectors WHERE object_types @> ARRAY[$1::text]`, probedType)
	scalarAny := explainSelectorPredicate(ctx, t, pool,
		`SELECT role_id FROM kacho_iam.role_rule_selectors WHERE $1 = ANY(object_types)`, probedType)

	t.Logf("перепись: форма членства — узлы %s, индексы %s", strings.Join(containment.nodeTypes, ","),
		strings.Join(containment.indexes, ","))
	t.Logf("перепись: форма скаляр-в-массиве — узлы %s, индексы %s", strings.Join(scalarAny.nodeTypes, ","),
		strings.Join(scalarAny.indexes, ","))

	// Несущее утверждение: GIN обслуживает форму членства.
	require.Contains(t, strings.Join(containment.indexes, ","), "role_rule_selectors_object_types_idx",
		"GIN не обслуживает форму членства: узлы %v, индексы %v",
		containment.nodeTypes, containment.indexes)

	// Двойник-дефект: старая форма индекс НЕ берёт. Возьми она его — различия
	// между формами не было бы, и правка была бы косметикой; проба обязана
	// сказать это вслух, а не молчать.
	require.NotContains(t, strings.Join(scalarAny.indexes, ","), "role_rule_selectors_object_types_idx",
		"старая форма внезапно обслуживается GIN — предмет задачи #2053 отпал, правку надо пересмотреть: узлы %v",
		scalarAny.nodeTypes)
	require.Contains(t, scalarAny.nodeTypes, "Seq Scan",
		"старая форма не читает столбец последовательно: узлы %v", scalarAny.nodeTypes)
}

// explainSelectorPredicate снимает план одного отбора.
func explainSelectorPredicate(ctx context.Context, t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, statement, arg string) planShape {
	t.Helper()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	var raw []byte
	require.NoError(t, tx.QueryRow(ctx,
		`EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+statement, arg).Scan(&raw))

	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &plans))
	require.Len(t, plans, 1, "разбор плана пуст — мерить нечего")

	root := plans[0].Plan
	shape := planShape{}
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
