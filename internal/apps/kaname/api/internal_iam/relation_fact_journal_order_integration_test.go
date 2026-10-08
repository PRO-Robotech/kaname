// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_journal_order_integration_test.go — снятие кортежа, вошедшее в
// журнал ПОСЛЕ его записи, снимает факт, когда бы ни началась его транзакция
// (приёмка NTF-3, kacho#2918, сценарий NTF3-174 (н) — снятие объекта
// конкурентно с регистрациями не оставляет кортежа `parent`; Р30 «Поколение и
// проекция», Д134 B2; задача https://github.com/PRO-Robotech/kaname/issues/667).
//
// # Предмет
//
// Порядок прямого факта у строки журнала без версии владельца — метка строки
// `fga_outbox.created_at`. Регистрация и снятие объекта упорядочены головой
// объекта: снятие кладёт свою строку журнала, только дождавшись блокировки
// головы, то есть после коммита регистрации, которую оно снимает. Если метка
// строки — момент НАЧАЛА транзакции (`now()`), снятие, чья транзакция началась
// раньше регистрации, несёт метку старше записанного факта, и сравнение
// `source_version <= метка снятия` факт не снимает: кортеж `parent` остаётся на
// снятом объекте. Пробу конкурентного снятия
// (`TestRegisterResource_NTF3_174_ConcurrentWithdrawalLeavesTheTombstone`) это
// роняет по жребию; здесь та же перестановка поставлена детерминированно.
//
// # Как построено
//
// Обе строки кладёт производитель журнала службы (`FGAOutboxEmitter`) — тот,
// что пишет их на пути регистрации и снятия. Транзакция снятия открывается и
// фиксирует свою метку начала ДО транзакции записи, а строку кладёт ПОСЛЕ её
// коммита. Близнец по одному факту — транзакция снятия открыта после коммита
// записи.
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestRelationFact_NTF3_174_RemovalEnteringTheJournalLaterRemovesTheFact —
// снятие, начавшее транзакцию раньше записи и положившее строку после её
// коммита, факт снимает. Близнец — снятие, начавшее транзакцию после записи.
func TestRelationFact_NTF3_174_RemovalEnteringTheJournalLaterRemovesTheFact(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	emitter := kanamepg.NewFGAOutboxEmitter()
	txs := kanamepg.NewPoolTxBeginner(pool)

	tuple := func(id string) []service.RelationTuple {
		return []service.RelationTuple{{User: "project:prj-1", Relation: "parent", Object: "storage_volume:" + id}}
	}
	fact := func(t *testing.T, id string) (time.Time, bool) {
		t.Helper()
		var v time.Time
		err := pool.QueryRow(ctx, `
			SELECT source_version FROM kaname.relation_fact
			 WHERE object_type = 'storage_volume' AND object_id = $1
			   AND relation = 'parent' AND subject = 'project:prj-1'`, id).Scan(&v)
		if err == pgx.ErrNoRows {
			return time.Time{}, false
		}
		require.NoError(t, err)
		return v, true
	}
	write := func(t *testing.T, id string) time.Time {
		t.Helper()
		tx, err := txs.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.NoError(t, emitter.EmitWriteTx(ctx, tx, tuple(id)))
		require.NoError(t, tx.Commit(ctx))
		v, ok := fact(t, id)
		require.True(t, ok, "положительный контроль: запись даёт строку факта")
		return v
	}
	// beginRemoval открывает транзакцию снятия и возвращает её метку начала.
	beginRemoval := func(t *testing.T) (service.Tx, time.Time) {
		t.Helper()
		tx, err := txs.Begin(ctx)
		require.NoError(t, err)
		t.Cleanup(func() { _ = tx.Rollback(ctx) })
		var started time.Time
		require.NoError(t, tx.(pgx.Tx).QueryRow(ctx, `SELECT now()`).Scan(&started))
		return tx, started
	}
	remove := func(t *testing.T, tx service.Tx, id string) {
		t.Helper()
		require.NoError(t, emitter.EmitDeleteTx(ctx, tx, tuple(id)))
		require.NoError(t, tx.Commit(ctx))
	}

	t.Run("снятие начато раньше записи, в журнал вошло после её коммита", func(t *testing.T) {
		const id = "vol-41order"
		tx, started := beginRemoval(t)
		written := write(t, id)
		require.True(t, written.After(started),
			"предусловие: запись (%s) упорядочена после начала транзакции снятия (%s)", written, started)
		remove(t, tx, id)
		v, ok := fact(t, id)
		require.False(t, ok, "снятие, вошедшее в журнал после записи, факт не сняло (версия факта %s, начало снятия %s)", v, started)
	})
	t.Run("близнец: снятие начато после коммита записи", func(t *testing.T) {
		const id = "vol-41order-twin"
		write(t, id)
		tx, _ := beginRemoval(t)
		remove(t, tx, id)
		_, ok := fact(t, id)
		require.False(t, ok, "снятие после записи факт не сняло")
	})
}
