// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package fga_outbox_test

// delete_version_integration_test.go — версия строки СНЯТИЯ, которую свёртка
// журнала сравнивает с версией прямого факта (kaname#919, kaname#923; механизм —
// deleteStamp в emitter.go).
//
// ПРЕДМЕТ. Свёртка снимает факт, только если его версия не новее версии строки
// снятия. Снятие, открывшее транзакцию РАНЬШЕ выдачи и написавшее строку после
// её коммита, обязано снять то, что увидело: версия его строки — момент вставки,
// а не начало транзакции.
//
// ЗАКОННЫЙ БЛИЗНЕЦ той же формы — две переплетённые транзакции, меняется один
// факт: выдача, открывшая транзакцию раньше снятия, но записанная ПОСЛЕ его
// коммита, остаётся. Без него ноль в первой пробе был бы неотличим от снятия,
// сносящего факт безусловно.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func versionPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	pool, err := coredb.NewPool(context.Background(), iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func factCount(t *testing.T, pool *pgxpool.Pool, objID, subject string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.relation_fact
		  WHERE object_type = 'project' AND object_id = $1 AND relation = 'admin' AND subject = $2`,
		objID, subject).Scan(&n))
	return n
}

// TestEmitDeleteTx_RemovesAFactWrittenAfterTheRevokerBegan — снятие начало
// транзакцию раньше выдачи, выдача зафиксирована, снятие пишет строку после
// её коммита: факта нет.
func TestEmitDeleteTx_RemovesAFactWrittenAfterTheRevokerBegan(t *testing.T) {
	pool := versionPool(t)
	ctx := context.Background()
	tuple := []clients.RelationTuple{{User: "user:usr_ver919a", Relation: "admin", Object: "project:prj_ver919a"}}

	revoker, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = revoker.Rollback(context.Background()) })
	_, err = revoker.Exec(ctx, `SELECT now()`)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: транзакция снятия начата")

	granter, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = granter.Rollback(context.Background()) })
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, granter, tuple))
	require.NoError(t, granter.Commit(ctx))
	require.Equal(t, 1, factCount(t, pool, "prj_ver919a", "user:usr_ver919a"),
		"ПРЕДПОСЫЛКА: выдача, начатая позже снятия, легла фактом")

	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, revoker, tuple))
	require.NoError(t, revoker.Commit(ctx))
	require.Zero(t, factCount(t, pool, "prj_ver919a", "user:usr_ver919a"),
		"снятие, начавшее транзакцию раньше выдачи и записанное после её коммита, оставило факт — строка снятия старше факта, который обязана снять")
}

// TestEmitDeleteTx_GrantFoldedAfterTheRevokeSurvives — близнец: выдача начала
// транзакцию раньше снятия, но записана ПОСЛЕ его коммита — факт остаётся.
func TestEmitDeleteTx_GrantFoldedAfterTheRevokeSurvives(t *testing.T) {
	pool := versionPool(t)
	ctx := context.Background()
	tuple := []clients.RelationTuple{{User: "user:usr_ver919b", Relation: "admin", Object: "project:prj_ver919b"}}

	granter, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = granter.Rollback(context.Background()) })
	_, err = granter.Exec(ctx, `SELECT now()`)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: транзакция выдачи начата")

	revoker, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = revoker.Rollback(context.Background()) })
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, revoker, tuple))
	require.NoError(t, revoker.Commit(ctx))

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, granter, tuple))
	require.NoError(t, granter.Commit(ctx))
	require.Equal(t, 1, factCount(t, pool, "prj_ver919b", "user:usr_ver919b"),
		"близнец: выдача, записанная после коммита снятия, обязана остаться — иначе ноль в первой пробе ни о чём")
}

// TestEmitDeleteTx_GrantBegunBeforeTheRemovalOfAStandingFactSurvives — близнец
// надгробия снятия по другую сторону его границы (kaname#636, миграция
// 20261028210500, п. 3 шапки): факт стоит, вторая выдача того же кортежа начала
// транзакцию раньше снятия и свёрнута ПОСЛЕ его коммита — факт остаётся. Строка
// выдачи без версии владельца упорядочена меткой журнала (начало транзакции), и
// её метка старше метки снятия; след снятия её не судит — иначе действующая
// выдача осталась бы без факта.
func TestEmitDeleteTx_GrantBegunBeforeTheRemovalOfAStandingFactSurvives(t *testing.T) {
	pool := versionPool(t)
	ctx := context.Background()
	tuple := []clients.RelationTuple{{User: "user:usr_ver636", Relation: "admin", Object: "project:prj_ver636"}}

	first, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Rollback(context.Background()) })
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, first, tuple))
	require.NoError(t, first.Commit(ctx))
	require.Equal(t, 1, factCount(t, pool, "prj_ver636", "user:usr_ver636"),
		"ПРЕДПОСЫЛКА: первая выдача легла фактом")

	granter, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = granter.Rollback(context.Background()) })
	_, err = granter.Exec(ctx, `SELECT now()`)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: транзакция второй выдачи начата")

	revoker, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = revoker.Rollback(context.Background()) })
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, revoker, tuple))
	require.NoError(t, revoker.Commit(ctx))
	require.Zero(t, factCount(t, pool, "prj_ver636", "user:usr_ver636"),
		"ПРЕДПОСЫЛКА: снятие сняло стоящий факт")

	require.NoError(t, fga_outbox.EmitWriteTx(ctx, granter, tuple))
	require.NoError(t, granter.Commit(ctx))
	require.Equal(t, 1, factCount(t, pool, "prj_ver636", "user:usr_ver636"),
		"выдача, начавшая транзакцию раньше снятия стоящего факта и свёрнутая после его коммита, факта не дала — надгробие судит строку без версии владельца")
}
