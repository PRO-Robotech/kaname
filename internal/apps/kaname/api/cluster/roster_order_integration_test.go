// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// roster_order_integration_test.go — находка Н3 приёмки ADM-CA: порядок
// перечня администраторов был `granted_at` без второго ключа, и равные значения
// давали неопределённый порядок. Контракт объявляет порядок, значит третьего
// состояния у него быть не должно.
//
// Равенство `granted_at` создаётся построением, а не надеждой: две выдачи
// заводятся глаголом записи `Grant` в ОДНОЙ транзакции, и `now()` транзакции
// даёт им одно значение. Чтобы дефект был наблюдаем, порядок вставки обязан
// быть ПРОТИВОПОЛОЖЕН порядку идентификаторов: иначе куча отдаёт строки в
// порядке вставки, он совпадает с ожидаемым, и проба зелена без правки.
// Идентификатор выдачи порождает писатель, поэтому пара, у которой порядки
// совпали, откатывается и заводится заново.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// tiedGrants — три активные выдачи: first и second с равным granted_at
// (одна транзакция), вставленные в порядке, ОБРАТНОМ порядку id; later —
// отдельной транзакцией позже. Возвращает id субъектов в ожидаемом порядке.
func tiedGrants(t *testing.T, ctx context.Context, dsn string) []string {
	t.Helper()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	w := kanamepg.NewClusterAdminGrantWriter(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	a := mustSeedUser(t, ctx, pool, "orda")
	b := mustSeedUser(t, ctx, pool, "ordb")
	c := mustSeedUser(t, ctx, pool, "ordc")

	var expected []string
	for attempt := 0; attempt < 64 && expected == nil; attempt++ {
		tx, err := txb.Begin(ctx)
		require.NoError(t, err)
		ga, _, err := w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(a), "bootstrap")
		require.NoError(t, err)
		gb, _, err := w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(b), "bootstrap")
		require.NoError(t, err)
		require.Equal(t, ga.GrantedAt, gb.GrantedAt, "one transaction gives both grants one granted_at")
		if ga.ID < gb.ID {
			// Порядок вставки совпал бы с ожидаемым — дефект не наблюдаем.
			require.NoError(t, tx.Rollback(ctx))
			continue
		}
		require.NoError(t, tx.Commit(ctx))
		expected = []string{string(b), string(a)}
	}
	require.NotNil(t, expected, "a pair inserted against id order must be producible")

	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	_, _, err = w.Grant(ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(c), "bootstrap")
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return append(expected, string(c))
}

// rosterOrder — id субъектов из ответа в порядке ответа, только из want.
func rosterOrder(resp *iamv1.ListClusterAdminsResponse, want []string) []string {
	keep := map[string]bool{}
	for _, id := range want {
		keep[id] = true
	}
	var out []string
	for _, e := range resp.GetAdmins() {
		if keep[e.GetSubjectId()] {
			out = append(out, e.GetSubjectId())
		}
	}
	return out
}

// TestClusterAdmins_H3_OrderTieBrokenByGrantID — Н3: при равном granted_at
// порядок — по id выдачи по возрастанию, одинаковый на каждом чтении.
func TestClusterAdmins_H3_OrderTieBrokenByGrantID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	want := tiedGrants(t, ctx, dsn)

	var h *clusterapp.Handler = buildHandler(t, dsn)
	for i := 0; i < 10; i++ {
		resp, err := h.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
		require.NoError(t, err)
		require.Equal(t, want, rosterOrder(resp, want),
			"read %d: equal granted_at must be ordered by grant id ascending", i)
	}
}
