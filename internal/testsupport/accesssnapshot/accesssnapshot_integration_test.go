// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package accesssnapshot

// accesssnapshot_integration_test.go — IAM-ID-1-28: право остаётся в границах
// аккаунта, где выдано.
//
// Здесь инструмент работает целиком, как он будет работать на стадиях, меняющих
// доступ: страницы объектов берутся курсором из НАСТОЯЩЕЙ базы, вопрос о доступе
// задаётся НАСТОЯЩЕЙ решающей стороне — той же двери, которую композиционный
// корень выдаёт стражам службы (`authzcascade.Wrap(relverdict.NewAsker(pool))`,
// см. cmd/kacho-iam/wiring.go).
//
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ И ПОЧЕМУ ЭТО НЕ ОСЛАБЛЕНИЕ. Прежняя редакция спрашивала
// внешний движок прав, поднятый рядом, и выдавала право записью кортежа. Движка
// нет; право теперь и есть закоммиченная строка своей базы — роль, её проекция
// глаголов, селектор и привязка на область, — а решение выносит реляционная
// форма. Дублёра при этом не появилось: спрашивается ровно то значение, которым
// решает продукт, — иначе инструмент утверждал бы про свою копию правил, а не
// про правила.
//
// Утверждение — про границу: выдача в одном аккаунте не даёт доступа в другом.
// Это и есть содержание «не расширяясь» в статике; равенство множеств до и после
// (IAM-ID-1-29/30) проверяет то же самое в динамике, и его способность падать в
// обе стороны доказана рядом, в юнит-пробах компаратора.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// seedAccountWithProjects заводит аккаунт, его владельца и n проектов.
// Ключи цикла отложены, поэтому порядок внутри транзакции значения не имеет.
func seedAccountWithProjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tag string, n int) (string, []string) {
	t.Helper()
	accID := "acc" + fmt.Sprintf("%017s", tag)
	ownerID := "usr" + fmt.Sprintf("%017s", tag)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'Owner', $4, 'ACTIVE')`,
		ownerID, "ext-"+tag, tag+"@example.test", accID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		accID, "acc-"+tag, ownerID)
	require.NoError(t, err)

	projects := make([]string, 0, n)
	for i := range n {
		pid := fmt.Sprintf("prj%014s%03d", tag, i)
		_, err = tx.Exec(ctx, `
			INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ($1, $2, $3)`,
			pid, accID, fmt.Sprintf("prj-%s-%d", tag, i))
		require.NoError(t, err)
		projects = append(projects, pid)
	}
	require.NoError(t, tx.Commit(ctx))
	return accID, projects
}

// projectsOfAccount — страница проектов аккаунта курсором ИЗ СВОЕЙ БАЗЫ.
// Именно так снимок и обязан обходить объекты: перечисление «всего доступного»
// имеет жёсткий предел и не имеет продолжения, а курсор по своей базе перечисляет
// ровно то, что в ней лежит (см. шапку пакета).
func projectsOfAccount(pool *pgxpool.Pool, accID string) PageFunc {
	return func(ctx context.Context, after string, limit int) ([]string, error) {
		rows, err := pool.Query(ctx, `
			SELECT id FROM kacho_iam.projects
			 WHERE account_id = $1 AND id > $2
			 ORDER BY id
			 LIMIT $3`, accID, after, limit)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if serr := rows.Scan(&id); serr != nil {
				return nil, serr
			}
			out = append(out, id)
		}
		return out, rows.Err()
	}
}

// grantProjectRead выдаёт право читать ОДИН проект — так же, как его выдаёт
// продукт: ролью, её проекцией глаголов, селектором и привязкой на область.
//
// Прямым фактом это не сеется, и не по стилю: глагол ВЫВОДИТСЯ из выдачи и
// копией не хранится — проекция журнала строку `v_*` отвергает намеренно
// (миграция 0098). Фикстура, положившая такой факт мимо производителя, посеяла бы
// состояние, которого продукт не производит, и первое же расхождение вывода с
// выдачей осталось бы незамеченным.
//
// Тип объекта берётся из КАТАЛОГА (`authzmap.DottedType`), а не выписывается
// строкой: выписанный разошёлся бы с каталогом молча, и соединение перестало бы
// сходиться — то есть выдача исчезла бы, выглядя честным отказом.
func grantProjectRead(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	roleID, bindingID, userID, projectID string) {
	t.Helper()
	dotted, known := authzmap.DottedType("project")
	require.Truef(t, known, "каталог не знает типа project — посев назвал бы тип, которого нет")

	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "посев: %s", sql)
	}
	exec(`INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
	      ON CONFLICT DO NOTHING`)
	exec(`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
	      VALUES ($1, $2, '[]'::jsonb,
	              jsonb_build_array(jsonb_build_object(
	                  'module',    'test',
	                  'resources', jsonb_build_array('*'),
	                  'verbs',     jsonb_build_array('get'))),
	              'cluster_kacho_root')`, roleID, "test.snapshot.get")
	exec(`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
		roleID, dotted)
	exec(`INSERT INTO kacho_iam.role_rule_selectors
	        (role_id, rule_fp, arm, object_types, match_labels)
	      VALUES ($1, 'fp-1', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, roleID, dotted)
	exec(`INSERT INTO kacho_iam.access_bindings
	        (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
	      VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		bindingID, userID, roleID, projectID)
	exec(`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
	      VALUES ($1, 'user', $2)`, bindingID, userID)
}

func TestIntegration_GrantDoesNotReachAcrossAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Дверь решения — ТА ЖЕ, что у продукта: форма поверх ведущего пула.
	door := authzcascade.Wrap(relverdict.NewAsker(pool))

	accA, projectsA := seedAccountWithProjects(t, ctx, pool, "snapa", 3)
	accBID, projectsB := seedAccountWithProjects(t, ctx, pool, "snapb", 3)

	const subject = "user:usr0000000000snapusr"
	// Субъект выдачи — настоящий пользователь: строка привязки на него ссылается.
	const subjectUser = "usr0000000000snapusr"
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		VALUES ($1, $1, $1 || '@example.test', $2)`, subjectUser, accA)
	require.NoError(t, err)

	// Выдача РОВНО на один проект аккаунта A.
	granted := projectsA[1]
	grantProjectRead(t, ctx, pool, "rol-snapshot", "acb-snapshot", subjectUser, granted)

	inA, err := Take(ctx, door, projectsOfAccount(pool, accA), subject, "v_get", "project")
	require.NoError(t, err)
	inB, err := Take(ctx, door, projectsOfAccount(pool, accBID), subject, "v_get", "project")
	require.NoError(t, err)

	t.Logf("перепись: аккаунт A — осмотрено %d, доступно %v; аккаунт B — осмотрено %d, доступно %v",
		inA.Examined, inA.IDs(), inB.Examined, inB.IDs())

	// Предпосылка: снимки СОБРАЛИСЬ. Без неё всё ниже истинно на пустом месте.
	require.Equal(t, len(projectsA), inA.Examined,
		"ПРЕДПОСЫЛКА: курсор обязан был обойти все проекты A")
	require.Equal(t, len(projectsB), inB.Examined,
		"ПРЕДПОСЫЛКА: курсор обязан был обойти все проекты B")

	// Положительная половина: выданное доступно.
	require.Equal(t, []string{granted}, inA.IDs(),
		"в аккаунте A доступен ровно тот проект, на который выдано, и только он")

	// Отрицательная половина: в чужом аккаунте не доступно ничего.
	require.Empty(t, inB.IDs(),
		"выдача в аккаунте A не даёт доступа в аккаунте B — это и есть «не расширяясь»")

	// Сравнение снимка с самим собой обязано сходиться: контроль, что компаратор
	// на живых данных не шумит.
	d, err := Compare(inA, inA)
	require.NoError(t, err)
	require.True(t, d.Empty(), "снимок обязан совпадать с самим собой: %+v", d)

	// А снимок другого аккаунта — расходиться, и расхождение обязано быть названо
	// ПОТЕРЕЙ выданного, а не пустотой.
	d, err = Compare(inA, inB)
	require.NoError(t, err)
	require.Equal(t, []string{granted}, d.Lost,
		"компаратор обязан называть предмет расхождения, а не только его факт")
	require.Empty(t, d.Gained)
}
