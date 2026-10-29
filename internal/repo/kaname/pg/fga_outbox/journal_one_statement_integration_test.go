// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// journal_one_statement_integration_test.go — выдачи и снятия одной транзакции,
// положенные одним вызовом EmitJournalTx, берут замки строк факта в общем порядке и
// ВНУТРИ ключа (субъект, объект) (kaname#617).
//
// ПРЕДМЕТ. Свёртка берёт строки одного ключа в порядке id, а отношения набора —
// побайтно. Будь у ключа, где есть и выдача, и снятие, две строки (набор выдачи и
// набор снятия), порядок замков внутри ключа был бы порядком СТРОК:
//   - T2 выдаёт {editor, owner} и снимает {viewer} — строки «editor…», «viewer»:
//     editor, owner, viewer;
//   - T1 выдаёт {admin, viewer} и снимает {owner} — строки «admin…», «owner»:
//     admin, viewer, owner.
//
// owner и viewer взяты встречно — 40P01. Строка на отношение, по отношению, даёт
// обеим один порядок: admin, editor, owner, viewer.
//
// КАК ГОНКА ДЕТЕРМИНИРОВАНА. Держатель берёт строку факта owner. T2 стартует первым и
// встаёт за ним, T1 — вторым. При строках-наборах T1 до ожидания успевает взять
// viewer; отпущенный owner достаётся T2, и та ждёт viewer у T1, которая ждёт owner у
// T2. При строках-отношениях T1 ждёт owner, ещё не взяв viewer, — очередь, не цикл.
//
// Под `go test -short` пропускается: нужен Docker.
package fga_outbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestEmitJournalTx_OppositeSwapsOnOneKeyBothCommit — две транзакции, у которых на
// одном ключе есть и выдача, и снятие, перечисленные встречно: обе коммитятся.
func TestEmitJournalTx_OppositeSwapsOnOneKeyBothCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	k := swapTuples("usr_swap617", "prj_swap617")
	err2, err1 := raceJournalCalls(t, k.all(), k.owner,
		k.emit([]string{"editor", "owner"}, []string{"viewer"}),
		k.emit([]string{"admin", "viewer"}, []string{"owner"}))
	require.NoError(t, err2, "выдача {editor, owner} со снятием viewer не должна падать тупиком на встречной паре")
	require.NoError(t, err1, "выдача {admin, viewer} со снятием owner не должна падать тупиком на встречной паре")
}

// TestEmitJournalTx_SameSwapOnOneKeyBothCommit — законный близнец: вторая транзакция
// перечисляет то же, что первая. Зелен на любой раскладке строк ключа.
func TestEmitJournalTx_SameSwapOnOneKeyBothCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	k := swapTuples("usr_same617", "prj_same617")
	err2, err1 := raceJournalCalls(t, k.all(), k.owner,
		k.emit([]string{"editor", "owner"}, []string{"viewer"}),
		k.emit([]string{"editor", "owner"}, []string{"viewer"}))
	require.NoError(t, err2)
	require.NoError(t, err1)
}

// TestEmitJournalTx_RefusesATupleBothWrittenAndDeleted — пара «выдать и снять» одного
// кортежа в одном вызове отвергается, а не решается порядком строк.
func TestEmitJournalTx_RefusesATupleBothWrittenAndDeleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	tu := clients.RelationTuple{User: "user:usr_both617", Relation: "admin", Object: "project:prj_both617"}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	err = fga_outbox.EmitJournalTx(ctx, tx, []clients.RelationTuple{tu}, []clients.RelationTuple{tu})
	require.EqualError(t, err, "fga_outbox: tuple project:prj_both617#admin@user:usr_both617 is both written and deleted in one call")
}

// swapKey — отношения одного субъекта на одном объекте.
type swapKey struct {
	user, object string
	owner        clients.RelationTuple
}

func swapTuples(user, project string) swapKey {
	k := swapKey{user: "user:" + user, object: "project:" + project}
	k.owner = clients.RelationTuple{User: k.user, Relation: "owner", Object: k.object}
	return k
}

func (k swapKey) tuples(rels []string) []clients.RelationTuple {
	out := make([]clients.RelationTuple, 0, len(rels))
	for _, r := range rels {
		out = append(out, clients.RelationTuple{User: k.user, Relation: r, Object: k.object})
	}
	return out
}

func (k swapKey) all() []clients.RelationTuple {
	return k.tuples([]string{"admin", "editor", "owner", "viewer"})
}

func (k swapKey) emit(writes, deletes []string) func(context.Context, pgx.Tx) error {
	return func(ctx context.Context, tx pgx.Tx) error {
		return fga_outbox.EmitJournalTx(ctx, tx, k.tuples(writes), k.tuples(deletes))
	}
}

// raceJournalCalls засевает факты `seed`, держит строку факта `held` третьей
// транзакцией, ставит в очередь first, затем second, отпускает строку и возвращает
// исход коммита каждой.
func raceJournalCalls(t *testing.T, seed []clients.RelationTuple, held clients.RelationTuple,
	first, second func(context.Context, pgx.Tx) error) (errFirst, errSecond error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	seedTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, seedTx, seed))
	require.NoError(t, seedTx.Commit(ctx))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	var locked int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.relation_fact
		  WHERE object_type || ':' || object_id = $1 AND relation = $2 AND subject = $3 FOR UPDATE) s`,
		held.Object, held.Relation, held.User).Scan(&locked))
	require.Equal(t, 1, locked, "предусловие: строка факта засеяна и взята держателем")

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
	doneFirst := run(first)
	waitForLockWaiters(t, ctx, pool, 1)
	doneSecond := run(second)
	waitForLockWaiters(t, ctx, pool, 2)

	require.NoError(t, holder.Commit(ctx))
	errFirst, errSecond = <-doneFirst, <-doneSecond
	for _, e := range []error{errFirst, errSecond} {
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) {
			t.Logf("отказ базы: SQLSTATE %s — %s", pgErr.Code, pgErr.Message)
		}
	}
	return errFirst, errSecond
}
