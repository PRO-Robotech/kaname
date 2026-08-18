// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package accesssnapshot

// accesssnapshot_integration_test.go — IAM-ID-1-28: право остаётся в границах
// аккаунта, где выдано.
//
// Здесь инструмент работает целиком, как он будет работать на стадиях, меняющих
// доступ: страницы объектов берутся курсором из НАСТОЯЩЕЙ базы, вопрос о доступе
// задаётся НАСТОЯЩЕМУ движку прав ПРОДОВЫМ клиентом.
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

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
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
// Именно так снимок и обязан обходить объекты: у своей базы нет серверного
// предела перечисления, а у движка прав он есть, общий на тип.
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

func TestIntegration_GrantDoesNotReachAcrossAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	h := fgatest.New(t)

	accA, projectsA := seedAccountWithProjects(t, ctx, pool, "snapa", 3)
	accBID, projectsB := seedAccountWithProjects(t, ctx, pool, "snapb", 3)

	const subject = "user:usr0000000000snapusr"
	// Выдача РОВНО на один проект аккаунта A.
	granted := projectsA[1]
	h.Write(t, subject, "v_get", "project:"+granted)

	inA, err := Take(ctx, h.Client, projectsOfAccount(pool, accA), subject, "v_get", "project")
	require.NoError(t, err)
	inB, err := Take(ctx, h.Client, projectsOfAccount(pool, accBID), subject, "v_get", "project")
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
