// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_list_search_integration_test.go — поиск пользователя ПО ПОДСТРОКЕ на
// стороне SQL.
//
// Предмет (#420). Пользователя знают по почте, и `name` у него нет вовсе.
// Полное совпадение (`email="..."`) отвечает только тому, кто уже знает адрес
// целиком; консоли нужен поиск по мере набора, а сужать список НА КЛИЕНТЕ
// нельзя — клиент видит только загруженную страницу и врёт обо всём, что в неё
// не поместилось.
//
// Утверждается ровно то, чем этот поиск отличается от прежнего фильтра:
//   - часть почты находит своего владельца (подстрока, не префикс);
//   - регистр не имеет значения;
//   - часть идентификатора тоже находит — второе, чем пользователя адресуют;
//   - чужой пользователь НЕ попадает (отрицание в паре с положительным, иначе
//     «нашёл» было бы неотличимо от «вернул всех»);
//   - служебные знаки образца ищутся как СИМВОЛЫ: `%` не превращает запрос в
//     «показать всех». Без экранирования поиск отвечал бы не на заданный вопрос,
//     и именно так выглядит фильтр, который «работает» и ничего не сужает.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
)

// seedUserWithEmail кладёт строку пользователя с ЗАДАННОЙ почтой: предмет
// утверждений ниже — сама почта, поэтому она не может быть производной от
// служебного суффикса.
func seedUserWithEmail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, acc domain.AccountID, email string) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, string(acc), "ext-"+uid, email, email)
	require.NoError(t, err, "seed user with email")
	return uid
}

// listIDs — идентификаторы страницы, отданной репозиторием по фильтру.
func listIDs(t *testing.T, ctx context.Context, repo *kanamepg.Repository, f repouser.ListFilter) []string {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	users, _, err := rd.Users().List(ctx, f)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, string(u.ID))
	}
	return out
}

func TestUserList_Search_SubstringOverEmailAndID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "srch-own")
	acc := seedAccount(t, ctx, repo, "acc-srch", owner)

	admin := seedUserWithEmail(t, ctx, pool, acc.ID, "Admin.Ops@prorobotech.ru")
	other := seedUserWithEmail(t, ctx, pool, acc.ID, "billing@example.com")

	scoped := func(filter string) repouser.ListFilter {
		return repouser.ListFilter{PageSize: 100, AccountID: acc.ID, Filter: filter}
	}

	// Положительный контроль: без фильтра в аккаунте видны обе строки. Без него
	// любое «не нашёл» ниже было бы неотличимо от пустого аккаунта.
	all := listIDs(t, ctx, repo, scoped(""))
	assert.Contains(t, all, admin)
	assert.Contains(t, all, other)

	t.Run("часть почты находит владельца", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="min.ops"`))
		assert.Equal(t, []string{admin}, got,
			"часть почты не нашла своего владельца — искать пользователя нечем именно тем, чем его знают")
	})

	t.Run("регистр не имеет значения", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="ADMIN.OPS@PROROBOTECH"`))
		assert.Equal(t, []string{admin}, got, "поиск чувствителен к регистру — почта набирается как придётся")
	})

	t.Run("часть идентификатора находит строку", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="`+admin[len(admin)-6:]+`"`))
		assert.Equal(t, []string{admin}, got, "по части идентификатора не нашлось — вторая форма адресации не работает")
	})

	t.Run("чужой пользователь не попадает", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="billing"`))
		assert.Equal(t, []string{other}, got)
		assert.NotContains(t, got, admin, "поиск вернул того, кого не спрашивали — значит он не сужает")
	})

	t.Run("знак подстановки ищется как символ, а не как «все»", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="%"`))
		assert.Empty(t, got,
			"образец `%` вернул строки — служебный знак LIKE уехал в запрос неэкранированным, "+
				"и поиск отвечает не на заданный вопрос")
	})

	t.Run("подчёркивание тоже символ", func(t *testing.T) {
		got := listIDs(t, ctx, repo, scoped(`search="_dmin"`))
		assert.Empty(t, got, "образец `_dmin` совпал — подчёркивание сработало как «любой знак»")
	})
}
