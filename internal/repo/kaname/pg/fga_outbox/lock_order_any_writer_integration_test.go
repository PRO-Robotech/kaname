// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lock_order_any_writer_integration_test.go — общий порядок захвата строк факта
// держит БАЗА, а не один из писателей журнала (kaname#568).
//
// ПРЕДМЕТ. Правка #357 (0fecf7e55) положила наборы ЭМИТТЕРА в общий порядок, и
// встречная блокировка двух его вызовов исчезла. Но журнал прав пишет не только
// эмиттер: обратное заполнение старта кладёт строки одним `INSERT … SELECT` в
// порядке просмотра таблицы, посев модулей — своим циклом, а строка с набором
// отношений, положенная мимо эмиттера, перечисляет их как пришлось. Свёртка в
// прямой факт брала блокировки строк факта в порядке строк оператора и в порядке
// отношений внутри строки — то есть в порядке ПИСАТЕЛЯ. Два оператора с
// пересекающимися ключами в разном порядке брали их встречно, и база снимала
// один отказом 40P01.
//
// Пробы пишут журнал СЫРЫМ оператором — так, как пишет всякий писатель, кроме
// эмиттера, — и потому краснеют на родителе правки, где порядок держал только
// эмиттер. Гонка ставится детерминированно тем же приёмом, что у соседней пробы
// эмиттера (lock_order_integration_test.go): третья транзакция держит строку
// факта, снятие встаёт за ней первым, выдача — вторым, блокировка отпускается.
//
// Skipped under `go test -short` (needs Docker).
package fga_outbox_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// rawRow — строка журнала, как её кладёт писатель мимо эмиттера.
type rawRow struct {
	user      string
	object    string
	relations []string
}

func (r rawRow) payload(t *testing.T) string {
	t.Helper()
	fields := map[string]any{"user": r.user, "object": r.object}
	if len(r.relations) == 1 {
		fields["relation"] = r.relations[0]
	} else {
		fields["relations"] = r.relations
	}
	b, err := json.Marshal(fields)
	require.NoError(t, err)
	return string(b)
}

// TestRawJournalStatementsDoNotDeadlockOnOppositeRowOrder — два оператора,
// перечисляющие одни и те же строки встречно, оба коммитятся.
func TestRawJournalStatementsDoNotDeadlockOnOppositeRowOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	a := rawRow{user: "user:usr_rawrows", object: "project:prj_rawrows_a", relations: []string{"admin"}}
	b := rawRow{user: "user:usr_rawrows", object: "project:prj_rawrows_b", relations: []string{"admin"}}

	revokeErr, grantErr := raceRawRevokeAgainstGrant(t,
		[]rawRow{b, a}, // снятие перечисляет встречно
		[]rawRow{a, b},
		"prj_rawrows_b", "admin")
	require.NoError(t, revokeErr, "снятие сырым оператором не должно падать тупиком на встречной выдаче")
	require.NoError(t, grantErr, "выдача сырым оператором не должна падать тупиком на встречном снятии")
}

// TestRawJournalSetDoesNotDeadlockOnOppositeRelationOrder — одна строка с
// набором отношений против другой с тем же набором в обратном порядке.
func TestRawJournalSetDoesNotDeadlockOnOppositeRelationOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	revokeErr, grantErr := raceRawRevokeAgainstGrant(t,
		[]rawRow{{user: "user:usr_rawrels", object: "project:prj_rawrels", relations: []string{"viewer", "admin"}}},
		[]rawRow{{user: "user:usr_rawrels", object: "project:prj_rawrels", relations: []string{"admin", "viewer"}}},
		"prj_rawrels", "viewer")
	require.NoError(t, revokeErr, "снятие набора не должно падать тупиком на встречном порядке отношений")
	require.NoError(t, grantErr, "выдача набора не должна падать тупиком на встречном порядке отношений")
}

// TestRawJournalStatementsCommitWhenEnumeratedAlike — законный близнец: тот же
// вход в одном порядке. Зелен на любой ревизии; без него красное выше не
// отличить от поломки самой гонки.
func TestRawJournalStatementsCommitWhenEnumeratedAlike(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	a := rawRow{user: "user:usr_rawalike", object: "project:prj_rawalike_a", relations: []string{"admin"}}
	b := rawRow{user: "user:usr_rawalike", object: "project:prj_rawalike_b", relations: []string{"admin"}}

	revokeErr, grantErr := raceRawRevokeAgainstGrant(t,
		[]rawRow{a, b},
		[]rawRow{a, b},
		"prj_rawalike_b", "admin")
	require.NoError(t, revokeErr)
	require.NoError(t, grantErr)
}

// rawInsert кладёт строки ОДНИМ оператором в заданном порядке — как обратное
// заполнение старта (`INSERT … SELECT`).
func rawInsert(ctx context.Context, t *testing.T, tx pgx.Tx, eventType string, rows []rawRow) error {
	payloads := make([]string, 0, len(rows))
	for _, r := range rows {
		payloads = append(payloads, r.payload(t))
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 SELECT $1, p::jsonb, now() FROM unnest($2::text[]) WITH ORDINALITY AS u(p, n) ORDER BY n`,
		eventType, payloads)
	return err
}

// raceRawRevokeAgainstGrant засевает строки фактами, держит строку факта
// (heldObjectID, heldRelation) третьей транзакцией, ставит в очередь снятие,
// затем выдачу, отпускает блокировку и возвращает исход коммита каждой.
func raceRawRevokeAgainstGrant(t *testing.T, revoke, grant []rawRow, heldObjectID, heldRelation string) (revokeErr, grantErr error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	seed, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, rawInsert(ctx, t, seed, "fga.tuple.write", grant))
	require.NoError(t, seed.Commit(ctx))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	var held int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.relation_fact
		  WHERE object_id = $1 AND relation = $2 FOR UPDATE) s`,
		heldObjectID, heldRelation).Scan(&held))
	require.Equal(t, 1, held, "предусловие: строка факта засеяна и взята держателем")

	run := func(eventType string, rows []rawRow) <-chan error {
		done := make(chan error, 1)
		go func() {
			tx, err := pool.Begin(ctx)
			if err != nil {
				done <- err
				return
			}
			if err := rawInsert(ctx, t, tx, eventType, rows); err != nil {
				_ = tx.Rollback(context.Background())
				done <- err
				return
			}
			done <- tx.Commit(ctx)
		}()
		return done
	}

	revokeDone := run("fga.tuple.delete", revoke)
	waitForLockWaiters(t, ctx, pool, 1)
	grantDone := run("fga.tuple.write", grant)
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
