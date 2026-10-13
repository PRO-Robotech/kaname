// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_key_login_issue_race_integration_test.go — выдача испытания входа
// ключом под КОНКУРИРУЮЩИМИ транзакциями (задача PRO-Robotech/kaname#769,
// приёмка Ф13-03 «одно живое испытание на контекст: второе замещает первое»),
// против настоящего Postgres.
//
//   - МЕХАНИЗМ: чужая транзакция держит незафиксированную живую строку того же
//     контекста; выдача ждёт её на ключе уникальности и после фиксации обязана
//     ЗАМЕСТИТЬ её, а не отказать — проверено ожиданием настоящего замка, а не
//     чтением кода;
//   - пачка одновременных выдач на одном контексте: все успешны, живое
//     испытание после них ровно одно и оно — одно из выданных;
//   - соперник ПОТРЕБЛЯЕТ живую строку, пока выдача ждёт её замок: после
//     фиксации строка уходит из-под ключа, выдача вставляет новую, а
//     потреблённая остаётся нетронутой (её не переписывают и не снимают);
//   - близнец: выдачи на РАЗНЫХ контекстах друг друга не замещают.

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func lcChallenge(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, domain.AccessKeyChallengeBytes)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func lcLive(t *testing.T, pool *pgxpool.Pool, formContext string) [][]byte {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT challenge FROM access_key_login_challenges
		 WHERE form_context = $1 AND consumed_at IS NULL`, formContext)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
	require.NoError(t, err)
	return got
}

// Чужая транзакция вставила живую строку контекста и не зафиксировала её.
// Выдача того же контекста ждёт её на частичном ключе уникальности; после
// фиксации выдача обязана заместить строку (Ф13-03), а не отказать.
func TestF13_03_IssueReplacesALiveChallengeCommittedByAConcurrentTransaction(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyLoginRepo(pool, pg.NewAccessKeyRepo(pool))
	ctx := context.Background()
	const formContext = "race-held-by-a-peer"

	first := lcChallenge(t)
	peer, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = peer.Rollback(ctx) }()
	_, err = peer.Exec(ctx, `
		INSERT INTO access_key_login_challenges (challenge, form_context, issued_at, expires_at)
		VALUES ($1, $2, now(), now() + interval '5 minutes')`, first, formContext)
	require.NoError(t, err)

	second := lcChallenge(t)
	done := make(chan error, 1)
	go func() {
		done <- repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: second, FormContext: formContext}, 5*time.Minute)
	}()

	// Выдача обязана ЖДАТЬ замок чужой транзакции: иначе проба не создала
	// условия гонки и её зелёное ничего не говорит.
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'
			   AND query LIKE '%access_key_login_challenges%'`).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 20*time.Millisecond, "выдача не встала в ожидание замка чужой строки — условие гонки не создано")

	require.NoError(t, peer.Commit(ctx))
	select {
	case err := <-done:
		require.NoError(t, err, "выдача под гонкой отказала вместо замещения (Ф13-03)")
	case <-time.After(10 * time.Second):
		t.Fatal("выдача не завершилась после фиксации чужой транзакции")
	}

	live := lcLive(t, pool, formContext)
	require.Len(t, live, 1, "живое испытание на контекст — ровно одно")
	require.Equal(t, second, live[0], "живым осталось ПОЗДНЕЕ испытание: первое замещено")
}

// Живое испытание контекста зафиксировано; чужая транзакция предъявляет его
// (отметка потребления) и держит строку незафиксированной. Выдача того же
// контекста ждёт её замок; после фиксации потреблённая строка из-под ключа
// уходит, и выдача обязана ВСТАВИТЬ новое испытание, не тронув потреблённое:
// переписать его значило бы оживить предъявленное, снять — стереть след
// предъявления до уборки.
func TestF13_03_IssueInsertsAfterAConcurrentTransactionConsumedTheLiveChallenge(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyLoginRepo(pool, pg.NewAccessKeyRepo(pool))
	ctx := context.Background()
	const formContext = "race-consumed-by-a-peer"

	first := lcChallenge(t)
	require.NoError(t, repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: first, FormContext: formContext}, 5*time.Minute))

	peer, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = peer.Rollback(ctx) }()
	tag, err := peer.Exec(ctx, `
		UPDATE access_key_login_challenges SET consumed_at = now()
		 WHERE challenge = $1 AND form_context = $2 AND consumed_at IS NULL`, first, formContext)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "фикстура: соперник не потребил живую строку")

	second := lcChallenge(t)
	done := make(chan error, 1)
	go func() {
		done <- repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: second, FormContext: formContext}, 5*time.Minute)
	}()

	// Выдача обязана ЖДАТЬ замок потребляемой строки: иначе соперник не успел
	// бы вмешаться, и зелёное ничего не говорило бы о гонке.
	require.Eventually(t, func() bool {
		var waiting int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'
			   AND query LIKE '%access_key_login_challenges%'`).Scan(&waiting)
		return err == nil && waiting == 1
	}, 10*time.Second, 20*time.Millisecond, "выдача не встала в ожидание замка потребляемой строки — условие гонки не создано")

	require.NoError(t, peer.Commit(ctx))
	select {
	case err := <-done:
		require.NoError(t, err, "выдача после потребления соперником отказала (Ф13-03)")
	case <-time.After(10 * time.Second):
		t.Fatal("выдача не завершилась после фиксации соперника")
	}

	require.Equal(t, [][]byte{second}, lcLive(t, pool, formContext), "живым стало НОВОЕ испытание")
	var consumed int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM access_key_login_challenges
		 WHERE form_context = $1 AND challenge = $2 AND consumed_at IS NOT NULL`, formContext, first).Scan(&consumed))
	require.Equal(t, 1, consumed, "потреблённое испытание сохраняется нетронутым до уборки")
}

// Пачка одновременных выдач на одном контексте: ни одного отказа, живое
// испытание после них ровно одно и оно — одно из выданных.
func TestF13_03_ConcurrentIssuesOnOneContextAllSucceedAndLeaveOneLive(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyLoginRepo(pool, pg.NewAccessKeyRepo(pool))
	ctx := context.Background()
	const formContext = "race-burst"
	const issuers = 16

	issued := make([][]byte, issuers)
	for i := range issued {
		issued[i] = lcChallenge(t)
	}
	start := make(chan struct{})
	errs := make([]error, issuers)
	var wg sync.WaitGroup
	for i := 0; i < issuers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: issued[i], FormContext: formContext}, 5*time.Minute)
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "выдача %d из %d отказала под гонкой (Ф13-03)", i+1, issuers)
	}

	live := lcLive(t, pool, formContext)
	require.Len(t, live, 1, "живое испытание на контекст — ровно одно")
	require.Contains(t, issued, live[0], "живое испытание — одно из выданных")
}

// Близнец: выдачи на РАЗНЫХ контекстах друг друга не замещают.
func TestF13_03_IssuesOnDifferentContextsDoNotReplaceEachOther(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyLoginRepo(pool, pg.NewAccessKeyRepo(pool))
	ctx := context.Background()

	a, b := lcChallenge(t), lcChallenge(t)
	require.NoError(t, repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: a, FormContext: "twin-a"}, 5*time.Minute))
	require.NoError(t, repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: b, FormContext: "twin-b"}, 5*time.Minute))
	require.Equal(t, [][]byte{a}, lcLive(t, pool, "twin-a"))
	require.Equal(t, [][]byte{b}, lcLive(t, pool, "twin-b"))

	// Потреблённое испытание под ключ уникальности не подпадает: новая выдача
	// того же контекста его не трогает.
	consumed, err := repo.ConsumeChallenge(ctx, a, "twin-a")
	require.NoError(t, err)
	require.True(t, consumed)
	c := lcChallenge(t)
	require.NoError(t, repo.IssueChallenge(ctx, domain.AccessKeyLoginChallenge{Challenge: c, FormContext: "twin-a"}, 5*time.Minute))
	require.Equal(t, [][]byte{c}, lcLive(t, pool, "twin-a"))
	var total int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM access_key_login_challenges WHERE form_context = 'twin-a'`).Scan(&total))
	require.Equal(t, 2, total, "потреблённая строка сохраняется до уборки")
}
