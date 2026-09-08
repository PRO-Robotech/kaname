// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// parent_edge_unregister_integration_test.go — что происходит с набором рёбер
// объекта, когда РЕГИСТРАЦИЯ СНИМАЕТСЯ.
//
// # Предмет
//
// Регистрация пишет две вещи — строку зеркала и цепь рёбер, — и пишет их одной
// транзакцией. Снятие убирало ТОЛЬКО первую. Ребро не несёт внешнего ключа на
// зеркало и нести его не может (стороны названы разными словарями: зеркало —
// словарём каталога, ребро — словарём модели прав), поэтому база за снятие не
// доделывает ничего: рёбра остаются навсегда.
//
// Наблюдаемое следствие ровно обратно тому, ради чего цепь заведена: снятый
// объект продолжает лежать под областью выдачи. Обход ВНИЗ («что лежит под этой
// областью») перечисляет объекты, которых нет, — то есть право переживает свой
// предмет. Замер стенда 2026-08-20: рёбер 14 707, из них 14 527 без строки
// зеркала — 98.8 % таблицы.
//
// # Почему проб ДВЕ, и почему вторая не «на всякий случай»
//
// Снятие условно: устаревшее надгробие (перестановка «правка → снятие») ноль
// строк зеркала и трогать не должно. Проба, требующая лишь «после снятия рёбер
// нет», зеленела бы и на безусловном `DELETE`, который сносит цепь СВЕЖЕЙ
// регистрации по опоздавшему надгробию — то есть на реализации, теряющей
// объект, который никто не снимал.
//
// Пропускается под `go test -short`.
package resource_mirror_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestParentEdges_UnregisterClearsTheChain — снятие регистрации снимает и цепь.
func TestParentEdges_UnregisterClearsTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	v1 := time.Now().Truncate(time.Microsecond)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-unreg-chain", ParentProjectID: "prj-P",
		ParentAccountID: "acc-A", SourceVersion: v1,
		ParentChain: []string{"project:prj-P", "account:acc-A"},
	})
	require.NotEmpty(t, readParentChain(t, ctx, pool, "compute_instance", "inst-unreg-chain"),
		"регистрация не записала цепь — предмета у пробы нет")

	deleteCommitted(t, ctx, pool, "compute.instance", "inst-unreg-chain", v1.Add(time.Second))

	require.Empty(t, readParentChain(t, ctx, pool, "compute_instance", "inst-unreg-chain"),
		"цепь пережила снятие регистрации: обход вниз по-прежнему числит объект под "+
			"областью выдачи, хотя объекта нет — право пережило свой предмет")
}

// TestParentEdges_StaleUnregisterKeepsTheChain — законный близнец: устаревшее
// надгробие не снимает НИЧЕГО, ни строки зеркала, ни цепи.
func TestParentEdges_StaleUnregisterKeepsTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	chain := []string{"project:prj-P", "account:acc-A"}
	fresh := time.Now().Truncate(time.Microsecond)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-unreg-stale", ParentProjectID: "prj-P",
		ParentAccountID: "acc-A", SourceVersion: fresh, ParentChain: chain,
	})

	// Надгробие СТАРШЕ хранимой регистрации — перестановка доставки.
	deleteCommitted(t, ctx, pool, "compute.instance", "inst-unreg-stale", fresh.Add(-time.Hour))

	require.Equal(t, chain, readParentChain(t, ctx, pool, "compute_instance", "inst-unreg-stale"),
		"устаревшее надгробие снесло цепь свежей регистрации: снятие безусловно, и "+
			"объект, которого никто не снимал, выпал из области выдачи")
	require.Equal(t, fresh, readMirrorVersion(t, ctx, pool, "compute.instance", "inst-unreg-stale"),
		"устаревшее надгробие тронуло строку зеркала")
}
