// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lock_order_integration_test.go — две транзакции журнала с пересекающимися
// наборами не встают в тупик.
//
// ПРЕДМЕТ. Строку журнала прямой факт складывает ТРИГГЕР
// (`kaname.relation_fact_from_journal`), и он берёт блокировку строки факта на каждый
// кортеж в том порядке, в каком строки журнала лежат в наборе. Две транзакции, одна из
// которых выдаёт, а другая снимает пересекающиеся кортежи одного субъекта, перечисленные
// в разном порядке, берут одни и те же блокировки встречно — и база снимает одну из них
// отказом 40P01. На стенде это видно так: снятие выдачи, совпавшее по времени с
// материализацией соседней выдачи того же субъекта, кончается терминальным ABORTED, и
// выдача, которую вызывающий снимал, остаётся жить.
//
// Порядок, в котором кортежи пришли от вызывающего, у отличающихся ключей ничего не
// значит: строки одного набора всегда разных ключей (эмиттер группирует по паре
// субъект–объект), а строки разных ключей коммутируют. Поэтому эмиттер обязан класть
// набор в ОДНОМ порядке, общем для всех писателей, — и тогда встречных блокировок нет.
//
// КАК ПРОБА ДЕЛАЕТ ГОНКУ ДЕТЕРМИНИРОВАННОЙ. Третья транзакция держит строку факта
// второго кортежа. Снятие стартует первым и становится в очередь на неё; выдача
// стартует вторым. Блокировка отпускается — и дальше исход определён порядком внутри
// наборов, а не случаем:
//   - наборы во встречном порядке: снятие взяло «b» и ждёт «a», которую держит выдача,
//     а выдача ждёт «b» — тупик, одна из транзакций получает 40P01;
//   - наборы в общем порядке: снятие успело взять «a» раньше, чем стало ждать «b»,
//     выдача ждёт «a» за ним — очередь, а не цикл, обе транзакции коммитятся.
//
// Skipped under `go test -short` (needs Docker).
package fga_outbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestEmitSetsOfOneSubjectDoNotDeadlockOnOppositeEnumeration — выдача и снятие
// пересекающихся наборов, перечисленных встречно, обе коммитятся.
//
// Положительный близнец того же входа — те же два набора, перечисленные в ОДНОМ
// порядке, — стоит рядом: он зелен и до правки, поэтому красное здесь меняется ровно
// на одном факте — порядке перечисления.
func TestEmitSetsOfOneSubjectDoNotDeadlockOnOppositeEnumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	a := clients.RelationTuple{User: "user:usr_lockorder", Relation: "admin", Object: "project:prj_lockorder_a"}
	b := clients.RelationTuple{User: "user:usr_lockorder", Relation: "admin", Object: "project:prj_lockorder_b"}

	revokeErr, grantErr := raceRevokeAgainstGrant(t,
		[]clients.RelationTuple{b, a}, // снятие перечисляет встречно
		[]clients.RelationTuple{a, b},
		"prj_lockorder_b")
	require.NoError(t, revokeErr, "снятие набора не должно падать тупиком на встречной выдаче того же субъекта")
	require.NoError(t, grantErr, "выдача набора не должна падать тупиком на встречном снятии того же субъекта")
}

// TestEmitSetsOfOneSubjectCommitWhenEnumeratedAlike — законный близнец: тот же вход в
// одном порядке. Зелен на любой реализации эмиттера; без него красное выше не отличить
// от поломки самой гонки.
func TestEmitSetsOfOneSubjectCommitWhenEnumeratedAlike(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	a := clients.RelationTuple{User: "user:usr_lockalike", Relation: "admin", Object: "project:prj_lockalike_a"}
	b := clients.RelationTuple{User: "user:usr_lockalike", Relation: "admin", Object: "project:prj_lockalike_b"}

	revokeErr, grantErr := raceRevokeAgainstGrant(t,
		[]clients.RelationTuple{a, b},
		[]clients.RelationTuple{a, b},
		"prj_lockalike_b")
	require.NoError(t, revokeErr)
	require.NoError(t, grantErr)
}

// raceRevokeAgainstGrant засевает оба кортежа фактами, держит строку факта heldObjectID
// третьей транзакцией, ставит в очередь снятие, затем выдачу, отпускает блокировку и
// возвращает исход коммита каждой.
func raceRevokeAgainstGrant(t *testing.T, revoke, grant []clients.RelationTuple, heldObjectID string) (revokeErr, grantErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	seed, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, seed, grant))
	require.NoError(t, seed.Commit(ctx))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	var held int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.relation_fact WHERE object_id = $1 FOR UPDATE) s`,
		heldObjectID).Scan(&held))
	require.Equal(t, 1, held, "предусловие: строка факта засеяна и взята держателем")

	run := func(emit func(context.Context, pgx.Tx) error) <-chan error {
		done := make(chan error, 1)
		go func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := emit(ctx, tx); err != nil {
				_ = tx.Rollback(context.Background())
				done <- err
				return
			}
			done <- tx.Commit(ctx)
		}()
		return done
	}

	revokeDone := run(func(ctx context.Context, tx pgx.Tx) error { return fga_outbox.EmitDeleteTx(ctx, tx, revoke) })
	waitForLockWaiters(t, ctx, pool, 1)
	grantDone := run(func(ctx context.Context, tx pgx.Tx) error { return fga_outbox.EmitWriteTx(ctx, tx, grant) })
	waitForLockWaiters(t, ctx, pool, 2)

	require.NoError(t, holder.Commit(ctx))
	revokeErr, grantErr = <-revokeDone, <-grantDone
	for _, e := range []error{revokeErr, grantErr} {
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) {
			t.Logf("отказ базы: SQLSTATE %s — %s", pgErr.Code, pgErr.Message)
		}
	}
	return revokeErr, grantErr
}

// waitForLockWaiters ждёт, пока в базе не наберётся n сеансов, ждущих блокировку.
// Ожидание наблюдаемым состоянием, а не сном: гонка поставлена, когда база её видит.
func waitForLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("предусловие гонки не создано: ждущих блокировку %d из %d", waiting, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
