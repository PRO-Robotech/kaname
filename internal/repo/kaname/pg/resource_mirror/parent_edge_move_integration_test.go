// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror_test

// parent_edge_move_integration_test.go — ПЕРЕНОС ОБЪЕКТА ПОД ДРУГОЙ КОНТЕЙНЕР
// ТОГО ЖЕ ПРОЕКТА (kaname#874, ND-09 приёмки
// `nested-rule-reaches-descendants-of-a-named-container.md`).
//
// Регистрация со строго новой версией, у которой проект, аккаунт и метки прежние,
// а цепь предков другая (репозиторий переехал в соседний реестр), — это НЕ
// «сдвиг одной версии»: цепь читает вложенное правило роли, и право обязано
// перейти за ней. Прежде полоса сдвига версии сверяла только проект, аккаунт и
// метки — цепь оставалась старой, а путь регистрации считал проекцию
// неизменной и шёл аддитивно, не снимая устаревшего.
//
// Близнец — та же цепь со строго новой версией: это и есть сдвиг одной версии,
// в каком бы словаре — модели или каталога — цепь ни прислали.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestParentEdges_ND09_MoveWithinTheProjectReplacesTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	const repo = "reg00000000000000001/moved"
	inX := []string{"registry_registry:reg00000000000000001", "project:prj-P", "account:acc-A"}
	inY := []string{"registry_registry:reg00000000000000002", "project:prj-P", "account:acc-A"}
	row := func(chain []string, v time.Time) resource_mirror.Row {
		return resource_mirror.Row{
			ObjectType: "registry.repositories", ObjectID: repo, ParentProjectID: "prj-P",
			ParentAccountID: "acc-A", Labels: map[string]string{"env": "dev"},
			SourceVersion: v, ParentChain: chain,
		}
	}
	upsert := func(r resource_mirror.Row) resource_mirror.Outcome {
		t.Helper()
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		out, err := resource_mirror.UpsertTx(ctx, tx, r)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return out
	}

	v1 := time.Now().Truncate(time.Microsecond)
	upsert(row(inX, v1))
	require.Equal(t, inX, readParentChain(t, ctx, pool, "registry_repository", repo), "Дано: цепь через X")

	// Близнец: та же цепь, версия новее — сдвиг одной версии.
	same := upsert(row(inX, v1.Add(time.Second)))
	require.True(t, same.Applied && same.ProjectionUnchanged, "близнец: та же цепь — только версия (%+v)", same)

	// Перенос в Y: версия новее, проект и метки прежние, цепь другая.
	moved := upsert(row(inY, v1.Add(2*time.Second)))
	require.True(t, moved.Applied, "перенос со строго новой версией не применён (%+v)", moved)
	require.False(t, moved.ProjectionUnchanged,
		"перенос под другой контейнер назван «только версией»: путь регистрации пойдёт аддитивно и не снимет право, оставшееся у X")
	require.Equal(t, inY, readParentChain(t, ctx, pool, "registry_repository", repo),
		"цепь не заменена: объект остался под X, и право выдачи на X его переживает")

	// Не новее — не применяется, цепь прежняя (ND-09, близнец).
	stale := upsert(row(inX, v1.Add(2*time.Second)))
	require.False(t, stale.Applied, "регистрация не новее применена (%+v)", stale)
	require.Equal(t, inY, readParentChain(t, ctx, pool, "registry_repository", repo), "не новее — цепь прежняя")

	// Та же цепь, присланная словарём КАТАЛОГА: сверка переводит её тем же
	// правилом, каким цепь пишут рёбра, — это сдвиг одной версии, а не перенос.
	inYDotted := []string{"registry.registries:reg00000000000000002", "project:prj-P", "account:acc-A"}
	again := upsert(row(inYDotted, v1.Add(3*time.Second)))
	require.True(t, again.Applied && again.ProjectionUnchanged,
		"та же цепь словарём каталога названа переносом (%+v): сверка цепи не переводит словарь", again)
	require.Equal(t, inY, readParentChain(t, ctx, pool, "registry_repository", repo), "цепь прежняя")
}
