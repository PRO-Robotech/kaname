// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_updated_at_integration_test.go — время правки роли ПРОИЗВОДИТСЯ
// (задача #1873).
//
// Предмет. Контракт `iam.v1.Role` объявляет `updated_at`, а заполнить его не
// могло ничто: столбца у таблицы не было, писатель его не присваивал, проекция
// чтения не выбирала, а перевод в контракт стоял под `if !r.UpdatedAt.IsZero()`
// — то есть НИКОГДА. Класс «возможность объявлена и неисполнима»
// (`api-conventions.md` §«Неисполнимая возможность»): арендатор видит поле в
// контракте и в сгенерированных клиентах и не может получить его ни одним
// вызовом. У соседнего ресурса того же домена (`Membership`) поле живое, значит
// разнобой сам по себе есть находка (ban #18).
//
// Утверждается ИСХОД, а не объявление: роль читается через репозиторий после
// создания и после правки, и сравниваются полученные величины.
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestRoleUpdatedAt_IsProducedAndMovesOnMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rua")
	acc := seedAccount(t, ctx, repo, "acc-rua", owner)

	rules := domain.Rules{
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}},
	}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)

	r := domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("updated_at_probe"),
		Description: domain.Description("before"),
		Rules:       rules,
		Permissions: compiled,
	}

	// ── создание: время правки ПРОИЗВЕДЕНО и равно времени создания ──────────
	//
	// Роль, которую никто не правил, «правлена» в момент своего появления — та
	// же форма, что у соседних ресурсов схемы. Пустое значение здесь означало бы
	// «поля нет», а поле есть.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.RolesW().Insert(ctx, r)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	require.False(t, inserted.UpdatedAt.IsZero(),
		"создание не произвело времени правки: поле объявлено контрактом и остаётся неисполнимым")
	assert.Equal(t, inserted.CreatedAt.UTC(), inserted.UpdatedAt.UTC(),
		"у только что созданной роли время правки обязано совпадать со временем создания")

	// Чтение производит его так же, как запись: столбец, который пишут и не
	// читают, невидим отовсюду.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got1, err := rd.Roles().Get(ctx, inserted.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.False(t, got1.UpdatedAt.IsZero(), "путь чтения времени правки не производит")

	// ── правка: время правки ДВИЖЕТСЯ, время создания НЕТ ───────────────────
	//
	// Вторая половина — положительный контроль наоборот: без неё проба зеленела
	// бы на writer'е, который двигает ОБЕ метки, и «время создания» перестало бы
	// означать создание.
	target := got1
	target.Description = domain.Description("after")
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w2.RolesW().Update(ctx, target, []string{"description"})
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	assert.Equal(t, "after", string(updated.Description), "правка не применилась — предмет пробы не создан")
	assert.True(t, updated.UpdatedAt.After(got1.UpdatedAt),
		"время правки не сдвинулось: было %s, стало %s", got1.UpdatedAt, updated.UpdatedAt)
	assert.Equal(t, got1.CreatedAt.UTC(), updated.CreatedAt.UTC(),
		"правка сдвинула время СОЗДАНИЯ — метка перестала означать создание")

	// Прочитанное совпадает с возвращённым: RETURNING и проекция чтения обязаны
	// говорить об одном.
	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	got2, err := rd2.Roles().Get(ctx, inserted.ID)
	_ = rd2.Rollback(ctx)
	require.NoError(t, err)
	assert.Equal(t, updated.UpdatedAt.UTC(), got2.UpdatedAt.UTC(),
		"RETURNING и путь чтения разошлись во времени правки")

	t.Logf("перепись: создано %s; правка %s; время создания неподвижно %v",
		inserted.UpdatedAt.UTC(), got2.UpdatedAt.UTC(),
		got1.CreatedAt.UTC().Equal(got2.CreatedAt.UTC()))
}
