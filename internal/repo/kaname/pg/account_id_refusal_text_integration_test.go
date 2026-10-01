// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// account_id_refusal_text_integration_test.go — тексты отказа вставки аккаунта,
// когда идентификатор может прислать вызывающий (задача kaname#549, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, Р4 и Р6;
// разбор экспозиции классов, условие 4).
//
// Отказ «занят» один для живого, удалённого и посеянного и не зависит от того,
// какой из двух ключей одной вставки база проверила первым. Подсказка вставки
// поэтому несёт и идентификатор, и имя, а текст выбирается по имени ограничения.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const genericUniqueText = "resource with these attributes already exists"

func insertAccountTx(ctx context.Context, repo *kanamepg.Repository, a domain.Account) error {
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	if _, err = w.AccountsW().Insert(ctx, a); err != nil {
		_ = w.Rollback(ctx)
		return err
	}
	return w.Commit(ctx)
}

func accountWith(id, name string, owner domain.UserID) domain.Account {
	return domain.Account{
		ID: domain.AccountID(id), Name: domain.AccountName(name), Labels: domain.Labels{}, OwnerUserID: owner,
	}
}

func requireAccountTaken(t *testing.T, err error, id string) {
	t.Helper()
	require.Error(t, err, "вставка с занятым идентификатором %s прошла", id)
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "ожидается ErrAlreadyExists: %v", err)
	require.Contains(t, err.Error(), "Account "+id+" already exists")
	require.NotContains(t, err.Error(), genericUniqueText, "конфликт идентификатора ушёл в общий текст")
}

// TestAccountID12_InsertRefusalNamesTheIDWhicheverKeyFiresFirst — AID-12 и AID-16
// уровнем хранилища.
func TestAccountID12_InsertRefusalNamesTheIDWhicheverKeyFiresFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	// Свой человек на каждую ветвь: темп заведения считается на личность, а
	// предмет пробы — тексты ключей, а не темп.
	seeded := 0
	ownerOf := func(t *testing.T) domain.UserID {
		seeded++
		return mustSeedUser(t, ctx, pool, fmt.Sprintf("aid12-%d", seeded))
	}

	t.Run("live_id_with_a_name", func(t *testing.T) {
		owner := ownerOf(t)
		x := ids.NewID(domain.PrefixAccount)
		require.NoError(t, insertAccountTx(ctx, repo, accountWith(x, "aid12-first", owner)))
		requireAccountTaken(t, insertAccountTx(ctx, repo, accountWith(x, "aid12-second", owner)), x)
	})

	t.Run("live_id_with_the_default_name", func(t *testing.T) {
		owner := ownerOf(t)
		// Оба ключа одной вставки заняты: первичный и имени. Текст обязан быть
		// один, каким бы ни был порядок их проверки.
		x2 := ids.NewID(domain.PrefixAccount)
		require.NoError(t, insertAccountTx(ctx, repo, accountWith(x2, x2, owner)))
		requireAccountTaken(t, insertAccountTx(ctx, repo, accountWith(x2, x2, owner)), x2)
	})

	t.Run("deleted_id", func(t *testing.T) {
		owner := ownerOf(t)
		x := ids.NewID(domain.PrefixAccount)
		require.NoError(t, insertAccountTx(ctx, repo, accountWith(x, "aid16-gone", owner)))
		_, err := pool.Exec(ctx, `DELETE FROM kaname.accounts WHERE id = $1`, x)
		require.NoError(t, err)
		requireAccountTaken(t, insertAccountTx(ctx, repo, accountWith(x, "aid16-again", owner)), x)
	})

	t.Run("seeded_id", func(t *testing.T) {
		owner := ownerOf(t)
		requireAccountTaken(t, insertAccountTx(ctx, repo, accountWith("acc1a18042d81fb438d6", "aid15-seeded", owner)),
			"acc1a18042d81fb438d6")
	})

	t.Run("twin_ordinary_name_keeps_its_text", func(t *testing.T) {
		owner := ownerOf(t)
		require.NoError(t, insertAccountTx(ctx, repo, accountWith(ids.NewID(domain.PrefixAccount), "aid25-name", owner)))
		err := insertAccountTx(ctx, repo, accountWith(ids.NewID(domain.PrefixAccount), "aid25-name", owner))
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "%v", err)
		require.Contains(t, err.Error(), "Account with name aid25-name already exists")
	})
}

// TestAccountID21_SchemaRefusesANameOfAForeignIDForm — CHECK имени (Р6) уровнем
// хранилища: запись в обход проверки типа отвергается базой тем же текстом, что
// у Account.Validate. Близнец — имя, равное собственному идентификатору.
func TestAccountID21_SchemaRefusesANameOfAForeignIDForm(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, "aid21t")

	err = insertAccountTx(ctx, repo, accountWith(ids.NewID(domain.PrefixAccount), ids.NewID(domain.PrefixAccount), owner))
	require.Error(t, err, "имя формы чужого идентификатора записано")
	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "ожидается ErrInvalidArg: %v", err)
	require.Contains(t, err.Error(),
		"Illegal argument name: the account id form is reserved for the account's own id")

	own := ids.NewID(domain.PrefixAccount)
	require.NoError(t, insertAccountTx(ctx, repo, accountWith(own, own, owner)))
}
