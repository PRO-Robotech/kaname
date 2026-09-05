// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// parent_edge_integration_test.go — что происходит с набором рёбер объекта на
// ПОВТОРНОЙ регистрации.
//
// # Предмет
//
// Цепь предков — состояние, а не приращение: применённая регистрация заменяет
// набор рёбер объекта целиком. Отсюда два утверждения, и порознь ни одно из них
// ничего не доказывает:
//
//   - повторная регистрация, НАЗЫВАЮЩАЯ цепь, набор не опустошает (её и делает
//     каждая правка меток — самый частый повтор в продукте);
//   - регистрация, цепь НЕ назвавшая, набор опустошает — и это не дефект
//     приёмной стороны, а цена того, что владелец промолчал. Ровно так рёбра и
//     терялись у четырёх потребителей из пяти.
//
// Второе утверждение здесь стоит не «на всякий случай»: без него первое зеленело
// бы и на реализации, которая рёбра просто никогда не трогает, — то есть на
// реализации, теряющей перенос объекта в другую область.
//
// Пропускается под `go test -short`.
package resource_mirror_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// readParentChain — цепь предков объекта в порядке возрастания глубины.
//
// `objType` называется в словаре МОДЕЛИ ПРАВ: цепь читается вопросом о доступе,
// а он приходит им (см. migration 0091 и комментарий у upsertParentEdges).
// Регистрация при этом называет объект словарём КАТАЛОГА — на этом стыке и
// стоит перевод, который здесь проверяется по исходу.
func readParentChain(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID string) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT parent_type || ':' || parent_id
		   FROM kacho_iam.resource_parent_edge
		  WHERE object_type = $1 AND object_id = $2
		  ORDER BY depth`, objType, objID)
	require.NoError(t, err)
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ref string
		require.NoError(t, rows.Scan(&ref))
		out = append(out, ref)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestParentEdges_ReRegistrationWithChainDoesNotEmptyTheSet — повтор с цепью
// набор рёбер сохраняет.
func TestParentEdges_ReRegistrationWithChainDoesNotEmptyTheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	chain := []string{"project:prj-P", "account:acc-A"}
	v1 := time.Now().Truncate(time.Microsecond)

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-chain-keep", ParentProjectID: "prj-P",
		ParentAccountID: "acc-A", Labels: map[string]string{"env": "dev"},
		SourceVersion: v1, ParentChain: chain,
	})
	require.Equal(t, chain, readParentChain(t, ctx, pool, "compute_instance", "inst-chain-keep"),
		"первая регистрация не записала цепь — дальше проверять нечего")

	// Правка меток: тот же объект, та же цепь, версия строго новее.
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-chain-keep", ParentProjectID: "prj-P",
		ParentAccountID: "acc-A", Labels: map[string]string{"env": "prod"},
		SourceVersion: v1.Add(time.Second), ParentChain: chain,
	})

	require.Equal(t, chain, readParentChain(t, ctx, pool, "compute_instance", "inst-chain-keep"),
		"повторная регистрация опустошила набор рёбер объекта: дальше вопрос о доступе "+
			"поднимается по цепи, цепи нет, и отказ неотличим от честного")
}

// TestParentEdges_ReRegistrationWithoutChainEmptiesTheSet — отрицательный
// контроль к пробе выше и одновременно ЦЕНА молчания владельца.
//
// Утверждение здесь двойное: замена работает (перенос объекта снимает старое
// ребро) И неназванная цепь означает «предков нет». Именно это делало доставку
// без цепи разрушительной, а не безобидной.
func TestParentEdges_ReRegistrationWithoutChainEmptiesTheSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v1 := time.Now().Truncate(time.Microsecond)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-chain-lost", ParentProjectID: "prj-P",
		SourceVersion: v1, ParentChain: []string{"project:prj-P"},
	})
	require.NotEmpty(t, readParentChain(t, ctx, pool, "compute_instance", "inst-chain-lost"))

	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-chain-lost", ParentProjectID: "prj-P",
		Labels: map[string]string{"env": "prod"}, SourceVersion: v1.Add(time.Second),
	})

	require.Empty(t, readParentChain(t, ctx, pool, "compute_instance", "inst-chain-lost"),
		"набор рёбер пережил регистрацию, которая цепи не назвала — значит замена "+
			"не работает, и перенос объекта в другую область не снимет старого предка")
}

// TestParentEdges_MovedObjectLosesTheOldAncestor — замена, ради которой она и
// полная: объект, перенесённый в другую область, теряет прежнего предка.
func TestParentEdges_MovedObjectLosesTheOldAncestor(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	v1 := time.Now().Truncate(time.Microsecond)
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-moved", ParentProjectID: "prj-OLD",
		SourceVersion: v1, ParentChain: []string{"project:prj-OLD"},
	})
	upsertCommitted(t, ctx, pool, resource_mirror.Row{
		ObjectType: "compute.instance", ObjectID: "inst-moved", ParentProjectID: "prj-NEW",
		SourceVersion: v1.Add(time.Second), ParentChain: []string{"project:prj-NEW"},
	})

	require.Equal(t, []string{"project:prj-NEW"},
		readParentChain(t, ctx, pool, "compute_instance", "inst-moved"),
		"прежний предок пережил перенос — право пережило бы вместе с ним")
}
