// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail_test

// enqueue_feed_integration_test.go — постановка письма на НАСТОЯЩЕЙ схеме kaname
// через НАСТОЯЩИЙ порт журнала ленты (`subscriptionjournal.FeedSignal`) и
// источник ленты corelib (замысел issue-2917 З1, З2, З17; приёмка NTF-2).
//
//   - NTF2-52 (модуль, интеграционно): флаг выключен — строк ленты 0 и строк
//     сигнала 0; близнец — флаг включён, тот же глагол даёт ровно одну строку
//     ленты и ровно одну строку сигнала `notification_feed:kaname`;
//   - CX2-27 (проба отката): откат транзакции события уносит строку ленты,
//     строку журнала и строку окна вместе; близнец — фиксация той же
//     транзакции оставляет каждую ровно одной.
//
// Транзакцию открывает открывающий службы `journalwrite.Begin` от имени
// пользователя — тот же, что у глагола: строку сигнала пишет писатель
// фундамента, требующий транзакцию помощника с инициатором.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/notify/feed"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail"
	"github.com/PRO-Robotech/kaname/internal/journalwrite"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
)

// feedService — префикс ленты службы «схема.служба» (заголовок миграции ленты
// `notifygen feed schema: service=kaname.kaname`).
const feedService = "kaname.kaname"

// refusingSealer — запечатывание фикстуры, неспособное дать зелёное молча:
// у шаблона пробы секретных атрибутов нет, и вызов здесь — дефект пробы.
type refusingSealer struct{}

var errSealerCalled = errors.New("проба: запечатывание позвано у шаблона без секретных атрибутов")

func (refusingSealer) Seal(string, string, string, []byte) ([]byte, error) {
	return nil, errSealerCalled
}

// feedFixture — пул на свежей схеме, источник ленты и Enqueuer с ОДНИМ
// значением флага, и контекст пользователя с привязанным источником.
type feedFixture struct {
	pool *pgxpool.Pool
	q    mail.Enqueuer
	ctx  context.Context
	user string
}

func newFeedFixture(t *testing.T, on bool) feedFixture {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	sig, err := subscriptionjournal.FeedSignal()
	require.NoError(t, err, "порт журнала ленты обязан собраться над объявлением владельца")

	word := "false"
	if on {
		word = "true"
	}
	en, err := feed.ParseEnabled("notifications.enabled", func(string) (string, bool) { return word, true })
	require.NoError(t, err)
	src, err := feed.NewSource(feed.Config{
		Module: manifest.AccessServiceFeed, Service: feedService, Enabled: en,
		Signal: sig, Sealer: refusingSealer{}, Metrics: prometheus.NewRegistry(),
	})
	require.NoError(t, err)

	menabled, err := mail.EnabledFrom(&on)
	require.NoError(t, err)
	q, err := mail.NewEnqueuer(menabled)
	require.NoError(t, err)

	user := ids.NewID(ids.PrefixUser)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: user})
	return feedFixture{pool: pool, q: q, ctx: src.Bind(ctx), user: user}
}

// letter — письмо password-changed пользователю фикстуры: шаблон класса S с
// лимитом на адресата, поэтому постановка пишет и окно, и вклад.
func (f feedFixture) letter(t *testing.T) mail.Letter {
	t.Helper()
	l, err := mail.PasswordChanged(f.user, mail.PasswordChangedAttrs{
		OccurredAt: time.Now().UTC().Truncate(time.Second),
		UserID:     f.user,
	})
	require.NoError(t, err)
	return l
}

// rows — сколько лежит строк ленты, строк сигнала ленты kaname в журнале, строк
// окна и строк вклада.
type rows struct{ feed, signal, window, contrib int }

func (f feedFixture) count(t *testing.T) rows {
	t.Helper()
	var r rows
	require.NoError(t, f.pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM kaname.kaname_notification_outbox),
		       (SELECT count(*) FROM kaname.resource_journal
		         WHERE resource_kind = $1 AND resource_id = $2),
		       (SELECT count(*) FROM kaname.kaname_notification_window),
		       (SELECT count(*) FROM kaname.kaname_notification_contrib)`,
		feed.JournalKey, manifest.AccessServiceFeed).
		Scan(&r.feed, &r.signal, &r.window, &r.contrib))
	return r
}

// TestIntegration_EnqueueFlagDecidesTheFeedAndTheSignal — NTF2-52: флаг
// выключен — строк ленты и сигнала 0, исход Disabled; близнец — флаг включён:
// одна строка ленты с id исхода и одна строка сигнала. Пара меняет ровно флаг.
func TestIntegration_EnqueueFlagDecidesTheFeedAndTheSignal(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}

	t.Run("flag off: no feed row, no signal row", func(t *testing.T) {
		f := newFeedFixture(t, false)
		tx, err := journalwrite.Begin(f.ctx, f.pool)
		require.NoError(t, err)
		r, err := f.q.Enqueue(f.ctx, tx, f.letter(t))
		require.NoError(t, err)
		require.Equal(t, mail.OutcomeDisabled, r.Outcome())
		require.NoError(t, tx.Commit(f.ctx))

		require.Equal(t, rows{}, f.count(t), "флаг выключен — не записано ничего (NTF2-52)")
	})

	t.Run("flag on twin: one feed row, one signal row", func(t *testing.T) {
		f := newFeedFixture(t, true)
		tx, err := journalwrite.Begin(f.ctx, f.pool)
		require.NoError(t, err)
		r, err := f.q.Enqueue(f.ctx, tx, f.letter(t))
		require.NoError(t, err)
		require.Equal(t, mail.OutcomeQueued, r.Outcome())
		id, queued := r.FeedID()
		require.True(t, queued)
		require.NoError(t, tx.Commit(f.ctx))

		got := f.count(t)
		require.Equal(t, 1, got.feed, "одна постановка — одна строка ленты")
		require.Equal(t, 1, got.signal, "одна постановка — одна строка сигнала notification_feed:kaname")

		var stored string
		require.NoError(t, f.pool.QueryRow(f.ctx,
			`SELECT id FROM kaname.kaname_notification_outbox`).Scan(&stored))
		require.Equal(t, id, stored, "id исхода — id записанной строки ленты")

		var project, scope, event, initiator string
		require.NoError(t, f.pool.QueryRow(f.ctx, `
			SELECT project_id, scope::text, event_type, initiator FROM kaname.resource_journal
			 WHERE resource_kind = $1`, feed.JournalKey).Scan(&project, &scope, &event, &initiator))
		require.Equal(t, "", project, "лента уровня кластера: якоря нет")
		require.Equal(t, "[]", scope, "захваченных областей у сигнала нет")
		require.Equal(t, "UPDATED", event, "сигнал говорит «в ленте появилось»")
		require.Equal(t, "user:"+f.user, initiator, "инициатор — субъект глагола")
	})
}

// TestIntegration_EnqueueRollbackTakesTheFeedSignalAndWindowTogether — CX2-27:
// откат транзакции события уносит строку ленты, строку журнала и строку окна
// (и вклад) вместе; близнец — фиксация той же транзакции оставляет каждую
// ровно одной.
func TestIntegration_EnqueueRollbackTakesTheFeedSignalAndWindowTogether(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}

	t.Run("rollback: nothing remains", func(t *testing.T) {
		f := newFeedFixture(t, true)
		tx, err := journalwrite.Begin(f.ctx, f.pool)
		require.NoError(t, err)
		r, err := f.q.Enqueue(f.ctx, tx, f.letter(t))
		require.NoError(t, err)
		require.Equal(t, mail.OutcomeQueued, r.Outcome(),
			"предусловие отката: постановка обязана записать строку в транзакции")
		require.NoError(t, tx.Rollback(f.ctx))

		require.Equal(t, rows{}, f.count(t),
			"откат транзакции события уносит строку ленты, сигнал и окно вместе (CX2-27)")
	})

	t.Run("commit twin: each remains once", func(t *testing.T) {
		f := newFeedFixture(t, true)
		tx, err := journalwrite.Begin(f.ctx, f.pool)
		require.NoError(t, err)
		r, err := f.q.Enqueue(f.ctx, tx, f.letter(t))
		require.NoError(t, err)
		require.Equal(t, mail.OutcomeQueued, r.Outcome())
		require.NoError(t, tx.Commit(f.ctx))

		require.Equal(t, rows{feed: 1, signal: 1, window: 1, contrib: 1}, f.count(t),
			"фиксация оставляет строку ленты, сигнал, окно и вклад по одной")
	})
}
