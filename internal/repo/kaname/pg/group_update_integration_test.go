// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// group_update_integration_test.go — запись группы против НАСТОЯЩЕГО Postgres
// (задача продукта #2065).
//
// Пробел, который эта проба закрывает, назван числом: у аккаунта и проекта
// запись проверялась на живой базе (`TestAccount_06_Update_Rename`,
// `TestProject_UpdateRename`), у группы — НИКОГДА. То есть единственный оператор
// из трёх остался бы неисполненным ни разу, а класс дефекта здесь ровно такой:
// ошибка набора колонок не видна ни сборке, ни обзору диффа, а видна только
// прогону, дошедшему до этой ветви маски.
//
// Утверждается ДВОЙНОЕ: названное маской поле переписано, а НЕ названное —
// сохранено. Без второй половины проба зеленела бы на операторе, который пишет
// все колонки всегда, — то есть на том самом поведении, отличить которое она и
// заведена.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestGroup_Update_MaskWritesOnlyWhatItNames(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gupd")
	acc := seedAccount(t, ctx, repo, "acc-gupd", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-upd")

	// Исходное состояние: метки непусты, чтобы «сохранено» отличалось от
	// «затёрто умолчанием».
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	seeded, err := w.GroupsW().Update(ctx, domain.Group{
		ID:          g.ID,
		AccountID:   acc.ID,
		Name:        g.Name,
		Description: "исходное описание",
		Labels:      domain.Labels{"env": "prod"},
	}, nil)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, domain.Description("исходное описание"), seeded.Description)
	require.Equal(t, domain.Labels{"env": "prod"}, seeded.Labels)

	t.Run("маска называет одно поле — остальные сохранены", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		out, err := w.GroupsW().Update(ctx, domain.Group{
			ID:          g.ID,
			AccountID:   acc.ID,
			Name:        "g-upd-renamed",
			Description: "это значение маской НЕ названо",
			Labels:      domain.Labels{"env": "dev"},
		}, []string{"name"})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))

		assert.Equal(t, domain.GroupName("g-upd-renamed"), out.Name,
			"названное поле обязано быть переписано")
		assert.Equal(t, domain.Description("исходное описание"), out.Description,
			"НЕ названное поле обязано остаться прежним — иначе оператор пишет всё всегда")
		assert.Equal(t, domain.Labels{"env": "prod"}, out.Labels,
			"метки маской не названы и переписаны быть не могут")
	})

	t.Run("пустая маска — полная правка", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		out, err := w.GroupsW().Update(ctx, domain.Group{
			ID:          g.ID,
			AccountID:   acc.ID,
			Name:        "g-upd-full",
			Description: "переписано целиком",
			Labels:      domain.Labels{"env": "dev"},
		}, nil)
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))

		assert.Equal(t, domain.GroupName("g-upd-full"), out.Name)
		assert.Equal(t, domain.Description("переписано целиком"), out.Description)
		assert.Equal(t, domain.Labels{"env": "dev"}, out.Labels)
	})

	t.Run("неизвестное поле маски — INVALID_ARGUMENT, записи нет", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, err = w.GroupsW().Update(ctx, domain.Group{
			ID: g.ID, AccountID: acc.ID, Name: "g-upd-nope", Labels: domain.Labels{},
		}, []string{"account_id"})
		require.Error(t, err)
		assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg))
		assert.Contains(t, err.Error(), `Illegal argument update_mask field "account_id"`,
			"текст отказа — часть контракта")
	})

	t.Run("несуществующая группа — NOT_FOUND", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, err = w.GroupsW().Update(ctx, domain.Group{
			ID: "grp00000000000000000", AccountID: acc.ID, Name: "ghost", Labels: domain.Labels{},
		}, nil)
		require.Error(t, err)
		assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
			"сторож WHERE id = $1 обязан не найти строку, а не переписать чужую")
	})
}
