// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail_integration_test.go — свойства ОЧЕРЕДИ писем приглашения на живой
// базе.
//
// Несущее утверждение здесь одно, и оно про ТРАНЗАКЦИЮ: строка приглашения и
// намерение отправить письмо появляются вместе либо не появляются вовсе. Проба
// «событие эмитировано» утверждала бы о ВЫЗОВЕ, а не о свойстве, и осталась бы
// зелёной на отправке письма о приглашении, которого не случилось.
//
// # MAIL-53 ДЕРЖИТСЯ ДВУМЯ ПОЛОВИНАМИ, И НИ ОДНА НЕ НАЗЫВАЛА ЕГО ПО ИМЕНИ
//
// Сценарий MAIL-53 приёмки ID-MAIL-1 требует ДВУХ разных свойств, и держат их
// разные пробы — поэтому имя сценария не стояло ни у одной, а поиск по нему
// давал ноль при живых производителях:
//
//	повтор ограничен НАЗВАННЫМ числом    Test_InviteMailQueue_MisconfiguredLaneIsPoisonedNotRetriedForever
//	                                     (здесь) — строка отравляется, а не крутится вечно;
//	                                     сама величина приезжает из объявления и проверена
//	                                     Test_InviteMailDrainerConfig_CarriesBothValuesSeparately
//	                                     (services/iam/cmd/kacho-iam/invite_mail_wiring_test.go)
//	второго письма не порождается        Test_InviteMailQueue_SurvivesTheDeathOfTheProcessThatEmitted
//	                                     (здесь) — отправка ровно одна, клетка «сдано» ровно одна,
//	                                     и очередь ПУСТЕЕТ: непустевшая очередь и есть второе письмо
//
// Разводить эти половины по одной пробе нельзя: первая требует ОТКАЗЫВАЮЩЕГО
// транспорта, вторая — исправного. Проба, совмещающая оба, утверждала бы о
// поведении, которого в одном прогоне не бывает.
package clients_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/invite_mail_outbox"
)

// Test_InviteMailIntent_IsAtomicWithTheInviteRow — MAIL-50, несущая половина.
//
// Строки нет — события нет, и наоборот. Атомарность здесь не оптимизация: без
// неё продукт отправляет письмо о приглашении, которого не случилось, либо
// создаёт приглашение, о котором человек не узнает никогда.
func Test_InviteMailIntent_IsAtomicWithTheInviteRow(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := setupInviteMailDB(t)

	t.Run("откат транзакции не оставляет намерения", func(t *testing.T) {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		require.NoError(t, err)
		require.NoError(t, invite_mail_outbox.EmitTx(ctx, tx,
			"usr-rolled-back", "acc-1", "rolled-back@example.invalid", ""))
		// Строка приглашения не состоялась — транзакция откатывается целиком.
		require.NoError(t, tx.Rollback(ctx))

		assert.Equal(t, 0, countInviteMail(ctx, t, pool, "usr-rolled-back"),
			"откат приглашения обязан снять и намерение: письма о приглашении, "+
				"которого не случилось, не бывает")
	})

	t.Run("положительный контроль: коммит оставляет ровно одно намерение", func(t *testing.T) {
		// Без этой половины отрицание выше зеленело бы на writer'е, который не
		// пишет НИКОГДА.
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		require.NoError(t, err)
		require.NoError(t, invite_mail_outbox.EmitTx(ctx, tx,
			"usr-committed", "acc-1", "committed@example.invalid", ""))
		require.NoError(t, tx.Commit(ctx))

		assert.Equal(t, 1, countInviteMail(ctx, t, pool, "usr-committed"),
			"состоявшееся приглашение обязано оставить намерение — оно переживает "+
				"смерть процесса")
	})
}

// Test_InviteMailQueue_RefusesARowWithoutASubject — ограничение хранилища, а не
// проверка в коде: строку без адресата и без ключа партиции записать НЕЛЬЗЯ.
//
// Это первый рубеж; декодер остаётся вторым. Отвергает именно база, поэтому
// обойти его нельзя ни одним вызывающим — в том числе тем, которого ещё нет.
func Test_InviteMailQueue_RefusesARowWithoutASubject(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := setupInviteMailDB(t)

	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.invite_mail_outbox (event_type, payload, resource_id)
		 VALUES ($1, $2, $3)`,
		clients.EventInviteMailSend, `{"account_id":"acc-1"}`, "usr-1")
	require.Error(t, err, "строка без адресата — отправка «никому», её записать нельзя")

	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.invite_mail_outbox (event_type, payload, resource_id)
		 VALUES ($1, $2, $3)`,
		clients.EventInviteMailSend, `{"to":"a@example.invalid"}`, "")
	require.Error(t, err, "пустой ключ партиции слил бы письма всех адресатов в одну партицию")

	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.invite_mail_outbox (event_type, payload, resource_id)
		 VALUES ($1, $2, $3)`,
		"mail.invite.something_else", `{"to":"a@example.invalid"}`, "usr-1")
	require.Error(t, err, "словарь видов события ЗАКРЫТ: опечатка отвергается на записи")

	// Положительный контроль: законная строка проходит. Без него отрицания выше
	// зеленели бы на таблице, которая не принимает ничего.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.invite_mail_outbox (event_type, payload, resource_id)
		 VALUES ($1, $2, $3)`,
		clients.EventInviteMailSend, `{"to":"a@example.invalid","account_id":"acc-1"}`, "usr-1")
	require.NoError(t, err, "положительный контроль: законная строка обязана записаться")
}

// Test_InviteMailQueue_OldestPendingAgeGrowsAndReturnsToZero — MAIL-50, вторая
// величина наблюдаемости.
//
// Возраст старейшего неотправленного растёт, пока письмо не ушло, и возвращается
// к нулю, когда ушло. Проба, знающая только рост, зелена на счётчике, который
// считает всё подряд, — поэтому обе стороны утверждаются порознь.
func Test_InviteMailQueue_OldestPendingAgeGrowsAndReturnsToZero(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := setupInviteMailDB(t)

	// Недоставленное письмо, поставленное «давно».
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.invite_mail_outbox (event_type, payload, resource_id, created_at)
		 VALUES ($1, $2, $3, now() - interval '600 seconds')`,
		clients.EventInviteMailSend, `{"to":"stuck@example.invalid"}`, "usr-stuck")
	require.NoError(t, err)

	rec := outboxmetrics.NewMemRecorder()
	col := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       clients.InviteMailTable,
		MaxAttempts: 10,
	})
	require.NoError(t, col.Scan(ctx))
	assert.Greater(t, rec.OldestPendingAgeSeconds(clients.InviteMailTable), float64(500),
		"застрявшее письмо обязано быть ВИДНО возрастом: без него «ноль доставленных "+
			"за всю жизнь очереди» незаметно")

	// Письмо сдано — величина обязана вернуться к нулю.
	_, err = pool.Exec(ctx,
		`UPDATE kacho_iam.invite_mail_outbox SET sent_at = now() WHERE resource_id = $1`, "usr-stuck")
	require.NoError(t, err)
	require.NoError(t, col.Scan(ctx))
	assert.Equal(t, float64(0), rec.OldestPendingAgeSeconds(clients.InviteMailTable),
		"на исправной доставке величина обязана возвращаться к нулю — иначе она "+
			"тревога, которая звонит всегда")
}

// Test_InviteMailQueue_SurvivesTheDeathOfTheProcessThatEmitted — намерение
// исполняется ДРУГИМ процессом, чем тот, что его записал.
//
// Это и есть то, ради чего отправка идёт через очередь: прямой вызов из
// обработчика такой пробы не прошёл бы.
func Test_InviteMailQueue_SurvivesTheDeathOfTheProcessThatEmitted(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := setupInviteMailDB(t)

	// «Первый процесс»: записал намерение и больше ничего не сделал.
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, invite_mail_outbox.EmitTx(ctx, tx,
		"usr-durable", "acc-1", "durable@example.invalid", "https://console.example.invalid/login"))
	require.NoError(t, tx.Commit(ctx))

	// «Второй процесс»: дренаж, поднятый отдельно.
	sent := newSentRecorder()
	obs := newRecordingObserver()
	startInviteMailDrainer(t, pool, sent, obs)

	require.Eventually(t, func() bool { return sent.count() == 1 }, 20*time.Second, 50*time.Millisecond,
		"намерение обязано быть исполнено дренажом, а не тем, кто его записал")

	got := sent.first()
	assert.Equal(t, "durable@example.invalid", got.To)
	assert.Equal(t, "https://console.example.invalid/login", got.LoginURL,
		"адрес страницы входа обязан доехать до отправителя нагрузкой строки")
	assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeSent),
		"сданное письмо обязано считаться — иначе «ноль отказов» неотличим от «никто не приходил»")

	// Очередь обязана опустеть: строка помечена сданной.
	require.Eventually(t, func() bool {
		return countPendingInviteMail(ctx, t, pool) == 0
	}, 20*time.Second, 50*time.Millisecond,
		"положительный контроль: обычная отправка отмечается сданной, и очередь пустеет")
}

// Test_InviteMailQueue_MisconfiguredLaneIsPoisonedNotRetriedForever — MAIL-33
// на живой очереди.
//
// Отказ по настройке ограничен числом повторов: строка отравляется, остаётся
// ВИДИМОЙ и повторно исполнимой, а не крутится вечно, изображая работу.
func Test_InviteMailQueue_MisconfiguredLaneIsPoisonedNotRetriedForever(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := setupInviteMailDB(t)

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, invite_mail_outbox.EmitTx(ctx, tx,
		"usr-misconfigured", "acc-1", "nowhere@example.invalid", ""))
	require.NoError(t, tx.Commit(ctx))

	obs := newRecordingObserver()
	startInviteMailDrainer(t, pool, sendFunc(func(context.Context, clients.InviteMailEvent) error {
		return clients.ErrMailMisconfigured
	}), obs)

	// Строка обязана перестать ретраиться, а не крутиться вечно.
	require.Eventually(t, func() bool {
		return attemptCount(ctx, t, pool, "usr-misconfigured") >= inviteMailTestMaxAttempts
	}, 20*time.Second, 50*time.Millisecond,
		"MAIL-33: отказ по настройке ограничен числом повторов")

	assert.Equal(t, 1, countInviteMail(ctx, t, pool, "usr-misconfigured"),
		"отравленная строка НЕ снимается: намерение не доехало, и терять его нельзя")
	assert.Positive(t, obs.count(clients.InviteMailOutcomeMisconfigured),
		"настройка обязана попадать в СВОЮ клетку счётчика — иначе она спрятана под сбоем")
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeSent),
		"положительный контроль отрицания: сданных при неверной настройке быть не может")
}

// inviteMailTestMaxAttempts — предел повторов дренажа В ЭТОЙ ПРОБЕ. Он мал
// намеренно: проба измеряет ОГРАНИЧЕННОСТЬ повтора, а не производственную
// величину — она объявлена настройкой и читается оттуда.
const inviteMailTestMaxAttempts = 3

// startInviteMailDrainer поднимает дренаж очереди писем — отдельно от того, кто
// записал намерение.
func startInviteMailDrainer(
	t *testing.T, pool *pgxpool.Pool, transport clients.InviteMailTransport, obs clients.InviteMailObserver,
) {
	t.Helper()
	logger := observability.NewSlogger(testLoggerWriter{t})
	d, err := drainer.New[clients.InviteMailEvent](
		pool,
		drainer.Config{
			Table:           clients.InviteMailTable,
			Channel:         clients.InviteMailChannel,
			BatchSize:       32,
			PollFallback:    200 * time.Millisecond,
			MaxAttempts:     inviteMailTestMaxAttempts,
			BackoffMin:      20 * time.Millisecond,
			BackoffMax:      100 * time.Millisecond,
			ApplyTimeout:    2 * time.Second,
			PartitionColumn: "resource_id",
			PermanentPolicy: drainer.PoisonPermanent,
		},
		clients.DecodeInviteMail,
		clients.NewInviteMailApplier(transport, obs, logger),
		logger,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("invite mail drainer did not stop within 5s")
		}
	})
}

// sentRecorder — транспорт, запоминающий сданные письма.
type sentRecorder struct {
	mu   sync.Mutex
	sent []clients.InviteMailEvent
}

func newSentRecorder() *sentRecorder { return &sentRecorder{} }

func (r *sentRecorder) Send(_ context.Context, ev clients.InviteMailEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, ev)
	return nil
}

func (r *sentRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

func (r *sentRecorder) first() clients.InviteMailEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sent[0]
}

func setupInviteMailDB(t *testing.T) *pgxpool.Pool { return setupCompensationDB(t) }

func countInviteMail(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.invite_mail_outbox WHERE resource_id = $1`, userID).Scan(&n))
	return n
}

func countPendingInviteMail(ctx context.Context, t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.invite_mail_outbox WHERE sent_at IS NULL`).Scan(&n))
	return n
}

func attemptCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(max(attempt_count), 0) FROM kacho_iam.invite_mail_outbox WHERE resource_id = $1`,
		userID).Scan(&n))
	return n
}
