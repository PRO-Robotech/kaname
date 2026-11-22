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
// 20000 выдач в одном аккаунте, у каждой два субъекта-человека: 2000 людей ×
// 10 ролей, выдача называет парой человека u, набором — u и u+1. Спрашиваемый
// человек стоит в двадцати выдачах: в десяти — первым, в десяти — вторым.
//
// # Пробы
//
//   - отрицательная: план фильтра `subject` не читает набор последовательно И
//     читает не больше страниц, чем вдвое против близнеца; ответ — все выдачи
//     субъекта (где он второй — тоже). Одного «последовательного чтения нет»
//     мало: на этой посадке прежний предикат планировщик исполнял полным
//     обходом индекса набора — Index Scan без ведущего столбца, та же линейная
//     цена в другой форме (контрольный прогон kaname#888: план прежнего
//     предиката с узлом Index Scan, последовательно 0). Поэтому мера — страницы
//     плана (EXPLAIN BUFFERS), а не вид узла;
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
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// subjectPlanPeople × subjectPlanRoles — размер посадки: 20000 выдач, тот, на
// котором цена была замерена (kaname#888).
const (
	subjectPlanPeople   = 2000
	subjectPlanRoles    = 10
	subjectPlanBindings = subjectPlanPeople * subjectPlanRoles
)

// subjectsTable — таблица набора, чьё последовательное чтение — предмет пробы.
const subjectsTable = "access_binding_subjects"

// subjectPlanBlockRatio — во сколько раз чтение без вида вправе стоить дороже
// близнеца с видом: по спуску индекса на каждый вид словаря вместо одного, а
// не обход индекса целиком.
const subjectPlanBlockRatio = 2

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
	// expected — выдачи, называющие субъекта: где он первый и где второй.
	expected []string
}

// Один batch — самостоятельный bounded Given. Binding и оба его субъекта
// commit вместе; все существующие guards, journal и deferred constraints живы.
func subjectPlanSeedTransaction(t *testing.T, pool *pgxpool.Pool, label string, body func(context.Context, pgx.Tx) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if tx != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			rollbackErr := tx.Rollback(cleanup)
			if !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				require.NoError(t, rollbackErr, "cleanup %s", label)
			}
		}()
	}
	require.NoError(t, err, "begin %s", label)
	require.NotNil(t, tx)
	require.NoError(t, body(ctx, tx), label)
	require.NoError(t, tx.Commit(ctx), "commit %s", label)
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
	roles := make([]string, subjectPlanRoles)
	for r := range roles {
		roles[r] = string(seedAccountRole(t, ctx, pool, acc.ID, fmt.Sprintf("sbjpln_role_%02d", r)))
	}

	const userPrefix, bindingPrefix = "usr-sbjpln-", "acb-sbjpln-"
	// Люди, как и выдачи, фиксируются короткими TX: journal keys не живут
	// до конца всего посева, а один INSERT не собирает guards всех 2000 людей.
	const peopleBatch = 128
	for first := 1; first <= subjectPlanPeople; first += peopleBatch {
		last := min(first+peopleBatch-1, subjectPlanPeople)
		subjectPlanSeedTransaction(t, pool, fmt.Sprintf("посев людей %d–%d", first, last), func(batchCtx context.Context, tx pgx.Tx) error {
			_, seedErr := tx.Exec(batchCtx, activewayin.WithWayIn(`
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		SELECT $1 || lpad(i::text, 6, '0'), $2, $1 || lpad(i::text, 6, '0'),
		       $1 || lpad(i::text, 6, '0') || '@kacho.local', 'p', 'ACTIVE'
		  FROM generate_series($3::int, $4::int) AS i`), userPrefix, string(acc.ID), first, last)
			return seedErr
		})
	}

	// Общий объём прежний. Короткая TX ограничивает удерживаемые journal locks;
	// statement_timeout пула не отключается. Глобальный i сохраняет IDs и роли.
	const bindingBatch = 128
	for first := 1; first <= subjectPlanBindings; first += bindingBatch {
		last := min(first+bindingBatch-1, subjectPlanBindings)
		subjectPlanSeedTransaction(t, pool, fmt.Sprintf("посев выдач %d–%d", first, last), func(batchCtx context.Context, tx pgx.Tx) error {
			// Выдача i: человек (i-1) mod 2000 + 1, роль (i-1) div 2000.
			_, seedErr := tx.Exec(batchCtx, `
		INSERT INTO kaname.access_bindings
		    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		SELECT $1 || lpad(i::text, 6, '0'), 'user', $2 || lpad(((i - 1) % $5::int + 1)::text, 6, '0'),
		       ($3::text[])[(i - 1) / $5::int + 1], 'account', $4, 'ACTIVE'
		  FROM generate_series($6::int, $7::int) AS i`,
				bindingPrefix, userPrefix, roles, string(acc.ID), subjectPlanPeople, first, last)
			if seedErr != nil {
				return seedErr
			}
			_, seedErr = tx.Exec(batchCtx, `
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		SELECT $1 || lpad(i::text, 6, '0'), 'user',
		       $2 || lpad(((i - 1 + k) % $3::int + 1)::text, 6, '0'), k
		  FROM generate_series($4::int, $5::int) AS i, generate_series(0, 1) AS k`,
				bindingPrefix, userPrefix, subjectPlanPeople, first, last)
			return seedErr
		})
	}

	// Финальная плотность посадки обязательна независимо от числа batch.
	func() {
		countCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		var peopleRows, bindingRows int
		require.NoError(t, pool.QueryRow(countCtx, `SELECT count(*) FROM kaname.users WHERE account_id=$1 AND id LIKE $2 || '%'`, string(acc.ID), userPrefix).Scan(&peopleRows))
		require.Equal(t, subjectPlanPeople, peopleRows)
		require.NoError(t, pool.QueryRow(countCtx, `SELECT count(*) FROM kaname.access_bindings WHERE resource_type='account' AND resource_id=$1 AND id LIKE $2 || '%'`, string(acc.ID), bindingPrefix).Scan(&bindingRows))
		require.Equal(t, subjectPlanBindings, bindingRows)
	}()

	_, err = pool.Exec(ctx, `ANALYZE kaname.access_bindings`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `ANALYZE kaname.access_binding_subjects`)
	require.NoError(t, err)

	var subjectRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE $1 || '%'`,
		bindingPrefix).Scan(&subjectRows))
	if subjectRows != 2*subjectPlanBindings {
		t.Fatalf("условие замера не создано: строк набора %d при %d выдачах", subjectRows, subjectPlanBindings)
	}

	// Человек 500 стоит первым в выдачах 500 + 2000·r и вторым — в 499 + 2000·r.
	const person = 500
	var expected []string
	for r := 0; r < subjectPlanRoles; r++ {
		expected = append(expected,
			fmt.Sprintf("%s%06d", bindingPrefix, person+subjectPlanPeople*r),
			fmt.Sprintf("%s%06d", bindingPrefix, person-1+subjectPlanPeople*r))
	}
	return subjectPlanFixture{
		ctx: ctx, pool: pool, acc: acc.ID,
		subject:  fmt.Sprintf("%s%06d", userPrefix, person),
		expected: expected,
	}
}

// listShape — оператор чтения той формы, что собирает List: предикат, скрытие
// отозванных, порядок курсора и предел страницы.
func listShape(predicate string, limitPos int) string {
	return fmt.Sprintf(`SELECT id FROM kaname.access_bindings
		 WHERE %s AND status <> 'REVOKED'
		 ORDER BY created_at ASC, id ASC LIMIT $%d`, predicate, limitPos)
}

// explainNodes снимает план оператора и возвращает его узлы и страницы
// (общие буферы корня: прочитанные и найденные в кэше — вместе со всеми узлами
// под ним, включая InitPlan набора).
func explainNodes(t *testing.T, f subjectPlanFixture, statement string, args ...any) ([]planNode, int) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(f.ctx) }()
	_, err = tx.Exec(f.ctx, `SET LOCAL search_path = kaname, public`)
	require.NoError(t, err)

	var raw []byte
	require.NoError(t, tx.QueryRow(f.ctx, `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) `+statement, args...).Scan(&raw))
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
	blocks := 0
	for _, k := range []string{"Shared Hit Blocks", "Shared Read Blocks"} {
		v, ok := plans[0].Plan[k].(float64)
		require.True(t, ok, "в плане нет %q — мерить нечего", k)
		blocks += int(v)
	}
	require.NotZero(t, blocks, "план не прочитал ни одной страницы — мера беспредметна")
	return out, blocks
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
	var typedBlocks int

	// Законный близнец: вид известен — ListBySubject.
	t.Run("typed_subject_reads_the_set_by_index", func(t *testing.T) {
		stmt := listShape(kanamepg.BindingNamesSubjectSQL("access_bindings", 1, 2), 3)
		args := []any{string(domain.SubjectTypeUser), f.subject, 51}
		require.ElementsMatch(t, f.expected, queryIDs(t, f, stmt, args...), "близнец: все выдачи субъекта")
		nodes, blocks := explainNodes(t, f, stmt, args...)
		requireSubjectsReadByIndex(t, "ListBySubject", nodes)
		typedBlocks = blocks
		t.Logf("ListBySubject: страниц плана %d", blocks)
	})

	// Предмет: вид не известен — фильтр `subject` у List.
	t.Run("untyped_subject_reads_the_set_by_index", func(t *testing.T) {
		require.NotZero(t, typedBlocks, "близнец не измерен — сравнивать не с чем")
		stmt := listShape(kanamepg.BindingNamesSubjectIDSQL(1), 2)
		args := []any{f.subject, 51}
		require.ElementsMatch(t, f.expected, queryIDs(t, f, stmt, args...), "фильтр subject: все выдачи субъекта")
		nodes, blocks := explainNodes(t, f, stmt, args...)
		requireSubjectsReadByIndex(t, "List subject", nodes)
		t.Logf("List subject: страниц плана %d, у близнеца %d, предел %d", blocks, typedBlocks, subjectPlanBlockRatio*typedBlocks)
		require.LessOrEqual(t, blocks, subjectPlanBlockRatio*typedBlocks,
			"фильтр subject читает %d страниц против %d у того же вопроса с видом — индекс субъекта обходится целиком: %v",
			blocks, typedBlocks, nodes)
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
