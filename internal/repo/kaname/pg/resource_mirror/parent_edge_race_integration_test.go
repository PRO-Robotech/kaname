// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_mirror_test

// parent_edge_race_integration_test.go — ДВЕ ДОСТАВКИ ОДНОГО ОБЪЕКТА С
// ПЕРЕСТАВЛЕННЫМИ ВЕРСИЯМИ (kaname#874, находка ревью круга 1).
//
// # Предмет
//
// Полоса сдвига версии сверяет цепь предков подзапросом по
// `resource_parent_edge`. В READ COMMITTED после ожидания замка строки
// Postgres перепроверяет условие только по колонкам САМОЙ обновляемой строки, а
// подзапрос по чужой таблице остаётся на снимке, взятом до ожидания. Значит:
//
//  1. старшая доставка (цепь B) применяется и держит замок строки зеркала;
//  2. новейшая доставка (цепь A) встаёт за этим замком в полосе сдвига версии;
//  3. старшая фиксируется — рёбра теперь B;
//  4. новейшая сверяет присланную цепь A с рёбрами СТАРОГО снимка (A), видит
//     совпадение и сдвигает одну версию.
//
// Итог без защиты — версия новейшая, рёбра старшей доставки: объект числится
// под чужим контейнером, и вложенное правило роли даёт по нему лишний доступ.
//
// Утверждается исход, а не механизм: итоговая цепь — от новейшей версии, и
// новейшая доставка НЕ названа «только версией» (иначе путь регистрации пошёл
// бы аддитивно и не снял права, выданного по цепи B).
//
// # Порядок задан, а не выпал
//
// Новейшая доставка запускается ПОСЛЕ того, как старшая применилась и держит
// замок, а старшая фиксируется только тогда, когда в каталоге замков появился
// неудовлетворённый запрос новейшей. Сон здесь утверждал бы о расписании, а не
// о продукте.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestParentEdges_ND09_ReorderedDeliveriesLeaveTheNewestChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	const repo = "reg00000000000000001/raced"
	inA := []string{"registry_registry:reg00000000000000001", "project:prj-P", "account:acc-A"}
	inB := []string{"registry_registry:reg00000000000000002", "project:prj-P", "account:acc-A"}
	row := func(chain []string, v time.Time) resource_mirror.Row {
		return resource_mirror.Row{
			ObjectType: "registry.repositories", ObjectID: repo, ParentProjectID: "prj-P",
			ParentAccountID: "acc-A", Labels: map[string]string{"env": "dev"},
			SourceVersion: v, ParentChain: chain,
		}
	}

	v1 := time.Now().Truncate(time.Microsecond)
	v2, v3 := v1.Add(time.Second), v1.Add(2*time.Second)

	// Дано: объект под A, версия v1.
	tx0, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = resource_mirror.UpsertTx(ctx, tx0, row(inA, v1))
	require.NoError(t, err)
	require.NoError(t, tx0.Commit(ctx))
	require.Equal(t, inA, readParentChain(t, ctx, pool, "registry_repository", repo), "Дано: цепь через A")

	// Старшая доставка (v2, цепь B) применяется и держит замок строки.
	tx1, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx1.Rollback(ctx) }()
	older, err := resource_mirror.UpsertTx(ctx, tx1, row(inB, v2))
	require.NoError(t, err)
	require.Truef(t, older.Applied && !older.ProjectionUnchanged,
		"старшая доставка обязана примениться переносом — иначе гонке не из чего строиться (%+v)", older)

	// Новейшая доставка (v3, цепь A) — в своей транзакции, за замком старшей.
	tx2, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx2.Rollback(ctx) }()
	var newestPID int
	require.NoError(t, tx2.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&newestPID))
	type result struct {
		out resource_mirror.Outcome
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, uerr := resource_mirror.UpsertTx(ctx, tx2, row(inA, v3))
		done <- result{out, uerr}
	}()

	// Ждём УСЛОВИЯ: новейшая стоит в очереди за замком старшей.
	waited := false
	for deadline := time.Now().Add(60 * time.Second); !waited && time.Now().Before(deadline); {
		select {
		case r := <-done:
			t.Fatalf("новейшая доставка завершилась (%+v, %v), не встав за замком старшей — гонка не создана", r.out, r.err)
		default:
		}
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_locks WHERE NOT granted AND pid = $1`, newestPID).Scan(&n))
		waited = n > 0
	}
	require.True(t, waited, "новейшая доставка не встала за замком старшей за 60 с — гонка не создана")

	require.NoError(t, tx1.Commit(ctx))
	var newest result
	select {
	case newest = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("новейшая доставка не завершилась за 60 с после фиксации старшей")
	}
	require.NoError(t, newest.err)
	require.NoError(t, tx2.Commit(ctx))

	var version time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT source_version FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		"registry.repositories", repo).Scan(&version))
	chain := readParentChain(t, ctx, pool, "registry_repository", repo)
	t.Logf("исход: новейшая %+v · версия %s · цепь %v", newest.out, version.UTC().Format(time.RFC3339Nano), chain)

	require.True(t, version.Equal(v3), "итоговая версия не новейшая: %s", version)
	require.Equal(t, inA, chain,
		"версия новейшая, а рёбра — старшей доставки: объект числится под чужим контейнером, "+
			"и вложенное правило даёт по нему лишний доступ")
	require.Truef(t, newest.out.Applied && !newest.out.ProjectionUnchanged,
		"новейшая доставка названа «только версией» (%+v), хотя между ней и прежней цепью "+
			"успела лечь другая: путь регистрации пойдёт аддитивно и не снимет право, выданное по B", newest.out)
}
