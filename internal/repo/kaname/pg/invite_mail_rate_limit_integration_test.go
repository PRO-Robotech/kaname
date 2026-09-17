// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invite_mail_rate_limit_integration_test.go — ограничение частоты писем НА
// АДРЕС стоит на единственном пути письма и держится ОПЕРАТОРОМ базы (приёмка
// ID-MAIL-1, Р14/Р22, MAIL-25, MAIL-42; задача продукта #1775).
//
// # Что утверждается
//
//   - в пределах нормы намерение ставится в очередь (положительный контроль);
//   - сверхнормативное намерение в очередь НЕ попадает — и вызов при этом не
//     отказ: писатель отвечает «не поставлено», а не ошибкой, потому что ответ
//     глагола обязан быть неотличим от ответа в норме (Р9);
//   - под КОНКУРЕНЦИЕЙ окно списывается ровно до нормы: N транзакций на один
//     адрес — в очередь попадает ровно MaxPerWindow, остальные видят «не
//     поставлено». Это ban #10 в чистом виде: решение принимает один
//     атомарный оператор с блокировкой строки окна, а не «прочитал → решил →
//     записал»;
//   - истёкшее окно открывается заново;
//   - адрес нормализуется: `A@X` и `a@x` — один адресат, иначе регистр
//     буквы обходил бы ограничение;
//   - непозитивное ограничение — ОТКАЗ писателя, а не «сколько угодно»:
//     значения «без ограничения» не существует и на этом уровне.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func mailIntent(to string, limit outboxtypes.InviteMailRateLimit) outboxtypes.InviteMailIntent {
	return outboxtypes.InviteMailIntent{
		UserID:    ids.NewID(domain.PrefixUser),
		AccountID: ids.NewID(domain.PrefixAccount),
		To:        to,
		Limit:     limit,
	}
}

func countQueuedMail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, to string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.invite_mail_outbox WHERE lower(payload->>'to') = lower($1)`, to).Scan(&n))
	return n
}

func TestInviteMailRateLimit_WithinTheCapTheLetterIsQueued(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 2, Window: time.Hour}
	const to = "mail25-cap@example.com"

	for i := 1; i <= 2; i++ {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		queued, err := w.EmitInviteMail(ctx, mailIntent(to, limit))
		require.NoError(t, err)
		require.True(t, queued, "письмо %d из %d — в пределах нормы, обязано быть поставлено", i, limit.MaxPerWindow)
		require.NoError(t, w.Commit(ctx))
	}
	require.Equal(t, 2, countQueuedMail(t, ctx, pool, to))

	// Сверхнормативное: НЕ ошибка и НЕ в очереди.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	queued, err := w.EmitInviteMail(ctx, mailIntent(to, limit))
	require.NoError(t, err, "сверхнормативное намерение обязано отвечать «не поставлено», а не ошибкой: "+
		"отказ по частоте не вправе быть отличим от ответа в норме (Р9)")
	require.False(t, queued, "третье письмо за окно при норме 2 поставлено — ограничение не действует")
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 2, countQueuedMail(t, ctx, pool, to), "сверхнормативное письмо попало в очередь")

	// Регистр адреса ограничение не обходит.
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	queued, err = w.EmitInviteMail(ctx, mailIntent("MAIL25-CAP@Example.COM", limit))
	require.NoError(t, err)
	require.False(t, queued, "тот же адрес другим регистром прошёл мимо ограничения")
	require.NoError(t, w.Commit(ctx))
}

func TestInviteMailRateLimit_ConcurrentSendersChargeExactlyTheCap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour}
	const to = "mail25-race@example.com"
	const senders = 8

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		queuedN  int
		errs     []error
		startGun = make(chan struct{})
	)
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGun
			w, err := repo.Writer(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				return
			}
			queued, err := w.EmitInviteMail(ctx, mailIntent(to, limit))
			if err == nil {
				err = w.Commit(ctx)
			} else {
				_ = w.Rollback(ctx)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if queued {
				queuedN++
			}
		}()
	}
	close(startGun)
	wg.Wait()
	require.Empty(t, errs, "конкурирующие отправители получили ошибки вместо исхода")
	require.Equal(t, limit.MaxPerWindow, queuedN,
		"под конкуренцией в очередь попало %d писем при норме %d — окно списано не оператором, а гонкой",
		queuedN, limit.MaxPerWindow)
	require.Equal(t, limit.MaxPerWindow, countQueuedMail(t, ctx, pool, to))
}

func TestInviteMailRateLimit_ExpiredWindowOpensAgain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	limit := outboxtypes.InviteMailRateLimit{MaxPerWindow: 1, Window: time.Hour}
	const to = "mail25-window@example.com"

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	queued, err := w.EmitInviteMail(ctx, mailIntent(to, limit))
	require.NoError(t, err)
	require.True(t, queued)
	require.NoError(t, w.Commit(ctx))

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	queued, err = w.EmitInviteMail(ctx, mailIntent(to, limit))
	require.NoError(t, err)
	require.False(t, queued, "второе письмо в том же окне при норме 1")
	require.NoError(t, w.Commit(ctx))

	// Окно отодвигается в прошлое ровно так, как его отодвинуло бы время.
	_, err = pool.Exec(ctx,
		`UPDATE kaname.invite_mail_windows SET window_started_at = window_started_at - interval '2 hours' WHERE recipient = $1`, to)
	require.NoError(t, err)

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	queued, err = w.EmitInviteMail(ctx, mailIntent(to, limit))
	require.NoError(t, err)
	require.True(t, queued, "истёкшее окно не открылось заново")
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 2, countQueuedMail(t, ctx, pool, to))
}

func TestInviteMailRateLimit_NonPositiveLimitIsRefusedNotUnlimited(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	for _, limit := range []outboxtypes.InviteMailRateLimit{
		{MaxPerWindow: 0, Window: time.Hour},
		{MaxPerWindow: 3, Window: 0},
	} {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		_, err = w.EmitInviteMail(ctx, mailIntent("mail43@example.com", limit))
		require.Error(t, err, "непозитивное ограничение %+v принято писателем — это «без ограничения», которого не существует", limit)
		_ = w.Rollback(ctx)
	}
	require.Equal(t, 0, countQueuedMail(t, ctx, pool, "mail43@example.com"))
}
