// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_subject_filter_plan_integration_test.go — фильтр субъекта
// у List читает набор субъектов выдачи ИНДЕКСОМ, а не обходом всей таблицы
// (kaname#888).
//
// # Предмет
//
// Фильтр `subject` у публичного List знает идентификатор субъекта, но не его
// вид. Набор `access_binding_subjects` проиндексирован ведущим столбцом
// `subject_type` (`access_binding_subjects_subject_scope_idx`), и подзапрос
// «где этот идентификатор стоит в наборе» без вида индекс не берёт: план читает
// таблицу целиком, то есть субъектов ВСЕХ арендаторов, на каждый запрос.
//
// # Посадка
//
// 20000 выдач в одном аккаунте, у каждой два субъекта-человека: выдача i
// называет парой человека i, набором — i и i+1. Спрашиваемый человек стоит
// в двух выдачах: в своей — первым, в соседней — вторым.
//
// # Пробы
//
//   - отрицательная: план фильтра `subject` не содержит последовательного чтения
//     набора, и ответ — ровно две выдачи (вторая находится);
//   - законный близнец: тот же вопрос С видом (ListBySubject) — план индексный
//     до правки и после неё; отличающий факт один — вид известен. Близнец
//     доказывает, что проба способна быть зелёной на этой посадке, и красное
//     отрицательной — не от посадки;
//   - словарь вида, которым чтение без вида называет ведущий столбец индекса,
//     совпадает с закрытым набором ограничений схемы: вид, добавленный в
//     ограничение и не добавленный в словарь, выпал бы из ответа молча;
//   - положительный контроль обеих: план вообще обращается к набору — иначе
//     «последовательного чтения нет» было бы правдой о плане, набора не
//     читающем.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// subjectPlanBindings — размер посадки: тот, на котором цена была замерена
// автором (kaname#888).
const subjectPlanBindings = 20000

// subjectsTable — таблица набора, чьё последовательное чтение — предмет пробы.
const subjectsTable = "access_binding_subjects"

// planNode — узел плана: вид и таблица, если узел её читает.
type planNode struct {
	nodeType string
	relation string
	index    string
}

func (n planNode) String() string {
	return fmt.Sprintf("%s(%s%s)", n.nodeType, n.relation, n.index)
}

// subjectPlanFixture — посадка и спрашиваемый человек.
type subjectPlanFixture struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	acc     domain.AccountID
	subject string
	// expected — выдачи, называющие субъекта: своя (первым) и соседняя (вторым).
	expected []string
}

func seedSubjectPlanFixture(t *testing.T) subjectPlanFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := kanamepg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, "sbjpln")
	acc := seedAccount(t, ctx, repo, "acc-sbjpln", owner)
	role := seedAccountRole(t, ctx, pool, acc.ID, "sbjpln_role")

	const userPrefix, bindingPrefix = "usr-sbjpln-", "acb-sbjpln-"
	_, err = pool.Exec(ctx, activewayin.WithWayIn(`
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		SELECT $1 || lpad(i::text, 6, '0'), $2, $1 || lpad(i::text, 6, '0'),
		       $1 || lpad(i::text, 6, '0') || '@kacho.local', 'p', 'ACTIVE'
		  FROM generate_series(1, $3::int) AS i`), userPrefix, string(acc.ID), subjectPlanBindings)
	require.NoError(t, err, "посев людей")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		SELECT $1 || lpad(i::text, 6, '0'), 'user', $2 || lpad(i::text, 6, '0'),
		       $3, 'account', $4, 'ACTIVE'
		  FROM generate_series(1, $5::int) AS i`,
		bindingPrefix, userPrefix, string(role), string(acc.ID), subjectPlanBindings)
	require.NoError(t, err, "посев выдач")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		SELECT $1 || lpad(i::text, 6, '0'), 'user',
		       $2 || lpad(((i - 1 + k) % $3::int + 1)::text, 6, '0'), k
		  FROM generate_series(1, $3::int) AS i, generate_series(0, 1) AS k`,
		bindingPrefix, userPrefix, subjectPlanBindings)
	require.NoError(t, err, "посев набора")

	_, err = pool.Exec(ctx, `ANALYZE kaname.access_bindings; ANALYZE kaname.access_binding_subjects`)
	require.NoError(t, err)

	var subjectRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE $1 || '%'`,
		bindingPrefix).Scan(&subjectRows))
	if subjectRows != 2*subjectPlanBindings {
		t.Fatalf("условие замера не создано: строк набора %d при %d выдачах", subjectRows, subjectPlanBindings)
	}

	// Человек 500 стоит первым в выдаче 500 и вторым в выдаче 499.
	return subjectPlanFixture{
		ctx: ctx, pool: pool, acc: acc.ID,
		subject:  userPrefix + "000500",
		expected: []string{bindingPrefix + "000499", bindingPrefix + "000500"},
	}
}

// listShape — оператор чтения той формы, что собирает List: предикат, скрытие
// отозванных, порядок курсора и предел страницы.
func listShape(predicate string, limitPos int) string {
	return fmt.Sprintf(`SELECT id FROM kaname.access_bindings
		 WHERE %s AND status <> 'REVOKED'
		 ORDER BY created_at ASC, id ASC LIMIT $%d`, predicate, limitPos)
}

// explainNodes снимает план оператора и возвращает его узлы.
func explainNodes(t *testing.T, f subjectPlanFixture, statement string, args ...any) []planNode {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(f.ctx) }()
	_, err = tx.Exec(f.ctx, `SET LOCAL search_path = kaname, public`)
	require.NoError(t, err)

	var raw []byte
	require.NoError(t, tx.QueryRow(f.ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+statement, args...).Scan(&raw))
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	require.NoError(t, json.Unmarshal(raw, &plans))
	require.Len(t, plans, 1, "разбор плана пуст — мерить нечего")

	var out []planNode
	var walk func(node map[string]any)
	walk = func(node map[string]any) {
		n := planNode{}
		n.nodeType, _ = node["Node Type"].(string)
		n.relation, _ = node["Relation Name"].(string)
		if ix, ok := node["Index Name"].(string); ok {
			n.index = " " + ix
		}
		out = append(out, n)
		kids, _ := node["Plans"].([]any)
		for _, kid := range kids {
			if m, ok := kid.(map[string]any); ok {
				walk(m)
			}
		}
	}
	walk(plans[0].Plan)
	return out
}

// requireSubjectsReadByIndex — набор прочитан, и прочитан не последовательно.
func requireSubjectsReadByIndex(t *testing.T, what string, nodes []planNode) {
	t.Helper()
	touched, seq := 0, 0
	for _, n := range nodes {
		if n.relation != subjectsTable {
			continue
		}
		touched++
		if n.nodeType == "Seq Scan" {
			seq++
		}
	}
	t.Logf("%s: узлов плана %d, читающих %s %d, последовательно %d: %v",
		what, len(nodes), subjectsTable, touched, seq, nodes)
	require.NotZero(t, touched, "%s: план не читает %s вовсе — «последовательного чтения нет» беспредметно: %v",
		what, subjectsTable, nodes)
	require.Zero(t, seq, "%s: набор %s читается последовательно — субъекты всех арендаторов на каждый запрос: %v",
		what, subjectsTable, nodes)
}

func queryIDs(t *testing.T, f subjectPlanFixture, statement string, args ...any) []string {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(f.ctx) }()
	_, err = tx.Exec(f.ctx, `SET LOCAL search_path = kaname, public`)
	require.NoError(t, err)
	rows, err := tx.Query(f.ctx, statement, args...)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestSubjectFilterPlan(t *testing.T) {
	f := seedSubjectPlanFixture(t)

	// Законный близнец: вид известен — ListBySubject.
	t.Run("typed_subject_reads_the_set_by_index", func(t *testing.T) {
		stmt := listShape(kanamepg.BindingNamesSubjectSQL("access_bindings", 1, 2), 3)
		args := []any{string(domain.SubjectTypeUser), f.subject, 51}
		require.ElementsMatch(t, f.expected, queryIDs(t, f, stmt, args...), "близнец: обе выдачи субъекта")
		requireSubjectsReadByIndex(t, "ListBySubject", explainNodes(t, f, stmt, args...))
	})

	// Предмет: вид не известен — фильтр `subject` у List.
	t.Run("untyped_subject_reads_the_set_by_index", func(t *testing.T) {
		stmt := listShape(kanamepg.BindingNamesSubjectIDSQL(1), 2)
		args := []any{f.subject, 51}
		require.ElementsMatch(t, f.expected, queryIDs(t, f, stmt, args...), "фильтр subject: обе выдачи субъекта")
		requireSubjectsReadByIndex(t, "List subject", explainNodes(t, f, stmt, args...))
	})
}

// kindLiteral — значение вида в тексте ограничения: `'user'::text`.
var kindLiteral = regexp.MustCompile(`'([a-z_]+)'::text`)

func TestSubjectFilterPlan_KindDictionaryMatchesTheSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	for _, c := range []struct{ table, constraint string }{
		{"access_bindings", "access_bindings_subject_ck"},
		{"access_binding_subjects", "access_binding_subjects_type_ck"},
	} {
		var def string
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT pg_get_constraintdef(c.oid)
			  FROM pg_constraint c
			  JOIN pg_class r ON r.oid = c.conrelid
			  JOIN pg_namespace n ON n.oid = r.relnamespace
			 WHERE n.nspname = 'kaname' AND r.relname = $1 AND c.conname = $2`,
			c.table, c.constraint).Scan(&def), "ограничение %s не найдено", c.constraint)
		var schema []string
		for _, m := range kindLiteral.FindAllStringSubmatch(def, -1) {
			schema = append(schema, m[1])
		}
		t.Logf("%s: видов в схеме %d %v, в словаре чтения %d %v",
			c.constraint, len(schema), schema, len(kanamepg.BindingSubjectKinds()), kanamepg.BindingSubjectKinds())
		require.NotEmpty(t, schema, "разбор ограничения %s не нашёл ни одного вида — сверка беспредметна: %s", c.constraint, def)
		require.ElementsMatch(t, schema, kanamepg.BindingSubjectKinds(),
			"словарь вида чтения без вида разошёлся с %s — выдачи нового вида выпадут из фильтра subject", c.constraint)
	}
}
