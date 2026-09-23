// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_concurrent_teardown_integration_test.go — КОНКУРИРУЮЩИЕ
// СНЯТИЯ СЕССИЙ ОДНОГО ЧЕЛОВЕКА СНИМАЮТ КАЖДУЮ ЗАПИСЬ РОВНО ОДИН РАЗ (задача
// kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — КАРДИНАЛЬНОСТЬ СНЯТИЯ ПОД КОНКУРЕНЦИЕЙ
//
// Оператор снятия (`endSessionsOfSQL`) — `UPDATE … WHERE ended_at IS NULL
// RETURNING id`. Его число снятых теперь уходит в долговременную запись
// принудительного выхода (`sessions_ended`). Под READ COMMITTED вторая
// транзакция, ждавшая строк первой, после её фиксации перепроверяет условие и
// уже снятую строку не берёт; только это держит два утверждения:
//
//   - каждая запись сессии снята ровно одной зафиксированной транзакцией;
//   - сумма чисел снятых по всем зафиксированным снятиям равна числу живых
//     записей до начала сцены (знаменатель печатается).
//
// Сцен две: M принудительных выходов одного человека сразу и принудительный
// выход против смены пароля в обоих порядках. Сверх суммы утверждается, что ни
// одна из транзакций не проиграла взаимной блокировкой.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ПОСТРОЕНА КОНКУРЕНЦИЯ — ЗАМКОМ, А НЕ ВРЕМЕНЕМ
//
// Первая транзакция сцены после своего оператора снятия задерживается
// триггером уровня оператора, держа замки снятых строк, и держит их, ПОКА САМА
// НЕ УВИДИТ ждущих, сколько велено сценой, — либо до общего срока сцены.
// Задержка ОДНОРАЗОВАЯ на прогон (последовательность, сбрасываемая перед
// прогоном): задерживается ровно первый оператор, остальные идут без неё, и
// ожидания не складываются в цепочку, упирающуюся в предел ожидания замка
// выхода. Вторые участники запускаются, когда первая видна спящей
// (`pg_stat_activity`), и сцена считается построенной, только когда держатель
// видел ждущими ЗАМКА их всех. Иначе проба судила бы участников, прошедших друг
// за другом, а не конкуренцию. Устройство задержки и почему она не мерится
// временем — у `installOneShotHold`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ СЧИТАЕТСЯ ВЗАИМНАЯ БЛОКИРОВКА — ДВУМЯ РАЗНЫМИ ПРИБОРАМИ
//
// Ответ принудительного выхода взаимную блокировку при снятии скрывает: отказ
// снятия уходит частичным исходом с ответом «недоступно». Поэтому отказы
// хранилища каждого оператора транзакции выхода записывает наблюдатель порта
// (`observedOwnSessions`), который передаёт каждый вызов настоящему писателю и
// ничего не решает сам. ABORTED под READ COMMITTED у этих операторов — ровно
// 40P01. Второй прибор независим от первого: счётчик базы
// `pg_stat_database.deadlocks`, прочитанный после закрытия пула, когда каждый
// обслуживающий процесс уже сбросил свою статистику.

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// ─────────────────────────────────────────────────────────────────────────────
// Наблюдатель порта снятия: передаёт каждый вызов настоящему писателю и
// записывает отказы хранилища. Решений не принимает, ввода не меняет.

type storeRefusalLog struct {
	mu       sync.Mutex
	refusals []error
}

func (l *storeRefusalLog) note(err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refusals = append(l.refusals, err)
}

// aborted — число отказов ABORTED (40P01 либо 40001; под READ COMMITTED у
// операторов снятия, отсечки и события — 40P01).
func (l *storeRefusalLog) aborted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, err := range l.refusals {
		if stderrors.Is(err, iamerr.ErrAborted) {
			n++
		}
	}
	return n
}

func (l *storeRefusalLog) all() []error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]error(nil), l.refusals...)
}

type observedOwnSessions struct {
	inner internaliam.OwnSessions
	log   *storeRefusalLog
}

func (o observedOwnSessions) ForceLogoutWriter(ctx context.Context, subject domain.UserID,
	lockWait time.Duration,
) (internaliam.OwnSessionsWriter, error) {
	w, err := o.inner.ForceLogoutWriter(ctx, subject, lockWait)
	if err != nil {
		o.log.note(err)
		return nil, err
	}
	return observedOwnSessionsWriter{inner: w, log: o.log}, nil
}

type observedOwnSessionsWriter struct {
	inner internaliam.OwnSessionsWriter
	log   *storeRefusalLog
}

func (w observedOwnSessionsWriter) EndOtherSessions(ctx context.Context, userID domain.UserID,
	keep domain.HumanSessionID, at time.Time, reason string,
) (int, error) {
	n, err := w.inner.EndOtherSessions(ctx, userID, keep, at, reason)
	w.log.note(err)
	return n, err
}

func (w observedOwnSessionsWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	err := w.inner.UpsertCutoff(ctx, u, revokedBy)
	w.log.note(err)
	return err
}

func (w observedOwnSessionsWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	err := w.inner.EmitAudit(ctx, ev)
	w.log.note(err)
	return err
}

func (w observedOwnSessionsWriter) Commit(ctx context.Context) error {
	err := w.inner.Commit(ctx)
	w.log.note(err)
	return err
}

func (w observedOwnSessionsWriter) Rollback(ctx context.Context) error {
	return w.inner.Rollback(ctx)
}

// concurrencyScene — своя база, пул и обработчик, собранный как его собирает
// корень на посадке `own`, но с наблюдателем порта снятия.
type concurrencyScene struct {
	dsn      string
	pool     *pgxpool.Pool
	handler  *internaliam.Handler
	sessions *kanamepg.HumanSessionRepo
	refusals *storeRefusalLog
}

func newConcurrencyScene(t *testing.T) *concurrencyScene {
	t.Helper()
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	log := &storeRefusalLog{}
	h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(pool)).
		WithAdminChecker(allowAdmin{}).
		WithOperations(operations.NewRepo(pool, "kaname")).
		WithOwnSessions(observedOwnSessions{inner: kanamepg.NewHumanSessionRepo(pool), log: log})
	return &concurrencyScene{
		dsn: dsn, pool: pool, handler: h,
		sessions: kanamepg.NewHumanSessionRepo(pool), refusals: log,
	}
}

func (s *concurrencyScene) forceLogout(uid domain.UserID) error {
	_, err := s.handler.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// Одноразовая задержка: первый оператор, поднявший триггер после взвода,
// держит свои замки, пока САМ не увидит ждущих замка, сколько велено сценой,
// либо до общего срока сцены; прочие идут без задержки.
//
// ПОЧЕМУ ДЕРЖАТЕЛЬ НЕ СПИТ ЗАДАННОЕ ВРЕМЯ (kaname#397). Здесь стояла выдержка
// на секунду, а сцену судил наблюдатель, ждавший ждущих до 10 с через ПУЛ
// СЦЕНЫ. Пул — умолчание драйвера, max(4, число ядер): на исполнителе с 4
// ядрами — 4 соединения. Держатель и трое ждущих выходов занимали его целиком,
// наблюдатель получал соединение лишь после ухода держателя и видел «ждущих 0
// из 3» до конца срока. Замер в контейнере проб: `--cpuset-cpus=0-3` и `0` —
// отказ 3 из 3 и 1 из 1 тем же текстом, что на исполнителе; `0-4` (пул 5) и
// `--cpus=0.5` без сужения набора ядер (пул 32) — зелено 1 из 1 и 3 из 3.
// Выдержка временем — та же ставка на скорость: ждущий, пришедший позже неё,
// сцены не строит.
//
// Теперь ждущих считает сам держатель — своим обслуживающим процессом, без
// соединения пула, — и отпускает замки по наблюдению. Исход он кладёт в
// последовательности: они вне транзакции и переживают её откат. Судится сцена
// по ним, когда участники уже вернулись (`requireHoldSceneBuilt`), — судящему
// соединение во время сцены не нужно вовсе.
//
// ОБЩИЙ СРОК И ЕГО ВЕРХНЯЯ ГРАНИЦА. Срок один на сцену: он ставится при
// взводе и лежит в базе; держатель его соблюдает, а судящий отказ по нему
// называет. Задержка не длится дольше срока, значит ни один ждущий не ждёт
// дольше срока и операторов держателя после отпуска. Срок — доля предела
// одного ожидания замка выхода (`lock_timeout`): ждущий выход, простоявший
// дольше предела, отказал бы исходом продукта, который вызвала сама сцена, и
// проба судила бы его как предмет. Остаток предела — на операторы держателя
// после отпуска.

// holdSceneBudget — общий срок сцены от взвода задержки: три четверти предела
// одного ожидания замка выхода.
const holdSceneBudget = internaliam.ForceLogoutLockWait * 3 / 4

// installOneShotHold — триггер уровня ОПЕРАТОРА на `table` для `event`
// ("UPDATE OF ended_at" либо "DELETE"). Имя задаёт вызывающий: в одной базе
// могут стоять две задержки.
//
// Состояние задержки — четыре объекта с префиксом имени: взвод (`_seq`), что
// велено (`_scene`: сколько ждущих и к какому сроку) и исход держателя
// (`_seen` — сколько ждущих он видел, отпуская; `_held_ms` — сколько держал).
// Ждущие — обслуживающие процессы базы пробы, ждущие ЗАМКА. Снимок
// `pg_stat_activity` живёт до конца транзакции, поэтому держатель сбрасывает
// его на каждом шаге.
func installOneShotHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, table, event string) {
	t.Helper()
	for _, q := range []string{
		`CREATE SEQUENCE kaname.` + name + `_seq`,
		`CREATE SEQUENCE kaname.` + name + `_seen MINVALUE 0`,
		`CREATE SEQUENCE kaname.` + name + `_held_ms MINVALUE 0`,
		`CREATE TABLE kaname.` + name + `_scene (want int NOT NULL, deadline timestamptz NOT NULL)`,
		`INSERT INTO kaname.` + name + `_scene VALUES (0, clock_timestamp())`,
	} {
		_, err := pool.Exec(ctx, q)
		require.NoError(t, err, "состояние задержки %s: %s", name, q)
	}
	_, err := pool.Exec(ctx, `
		CREATE FUNCTION kaname.`+name+`() RETURNS trigger
		LANGUAGE plpgsql AS $$
		DECLARE
			v_want     int;
			v_deadline timestamptz;
			v_seen     int;
			v_started  timestamptz := clock_timestamp();
		BEGIN
			IF nextval('kaname.`+name+`_seq') <> 1 THEN
				RETURN NULL;
			END IF;
			SELECT s.want, s.deadline INTO v_want, v_deadline FROM kaname.`+name+`_scene s;
			LOOP
				PERFORM pg_stat_clear_snapshot();
				SELECT count(*) INTO v_seen FROM pg_stat_activity
				 WHERE datname = current_database() AND wait_event_type = 'Lock';
				EXIT WHEN v_seen >= v_want OR clock_timestamp() >= v_deadline;
				PERFORM pg_sleep(0.005);
			END LOOP;
			PERFORM setval('kaname.`+name+`_seen', v_seen, true);
			PERFORM setval('kaname.`+name+`_held_ms',
				(extract(epoch FROM clock_timestamp() - v_started) * 1000)::bigint, true);
			RETURN NULL;
		END $$`)
	require.NoError(t, err, "функция задержки %s", name)
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER `+name+` AFTER `+event+` ON kaname.`+table+`
		FOR EACH STATEMENT EXECUTE FUNCTION kaname.`+name+`()`)
	require.NoError(t, err, "триггер задержки %s", name)
	disarmOneShotHold(t, ctx, pool, name)
}

// armOneShotHold — следующий оператор, поднявший триггер, задержится и будет
// держать замки, пока не увидит want ждущих, но не дольше общего срока
// (`holdSceneBudget` от этого момента). Исход прошлого взвода стирается.
func armOneShotHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string, want int) {
	t.Helper()
	require.Positive(t, want, "фикстура: сцене задержки нужен хотя бы один ждущий")
	for _, q := range []string{
		`SELECT setval('kaname.` + name + `_seen', 0, false)`,
		`SELECT setval('kaname.` + name + `_held_ms', 0, false)`,
	} {
		_, err := pool.Exec(ctx, q)
		require.NoError(t, err, "сбросить исход задержки %s", name)
	}
	_, err := pool.Exec(ctx,
		`UPDATE kaname.`+name+`_scene SET want = $1, deadline = clock_timestamp() + make_interval(secs => $2)`,
		want, holdSceneBudget.Seconds())
	require.NoError(t, err, "велеть сцену задержки %s", name)
	_, err = pool.Exec(ctx, `SELECT setval('kaname.`+name+`_seq', 1, false)`)
	require.NoError(t, err, "взвести задержку %s", name)
}

// disarmOneShotHold — задержка израсходована: посев и чтения её не поднимают.
func disarmOneShotHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	_, err := pool.Exec(ctx, `SELECT setval('kaname.`+name+`_seq', 1, true)`)
	require.NoError(t, err, "снять задержку %s", name)
}

// requireHoldSceneBuilt — исход держателя взведённой задержки; зовётся, когда
// участники сцены вернулись. Отвечает, сколько ждущих держатель видел, отпуская
// замки. Держатель до задержки не дошёл либо отпустил по общему сроку, не
// увидев всех, — сцена конкуренции не построена: это ОТКАЗ ФИКСТУРЫ, и проба
// кончается на нём, не вынося вердикта о предмете по исходам участников.
func requireHoldSceneBuilt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) int {
	t.Helper()
	var decided bool
	var seen, heldMs int64
	var want int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT is_called, last_value FROM kaname.`+name+`_seen`).Scan(&decided, &seen))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT last_value FROM kaname.`+name+`_held_ms`).Scan(&heldMs))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT want FROM kaname.`+name+`_scene`).Scan(&want))
	if !decided {
		t.Fatalf("отказ фикстуры: держатель задержки %s до неё не дошёл — сцена конкуренции не построена, "+
			"вердикта о предмете нет", name)
	}
	if seen < int64(want) {
		t.Fatalf("отказ фикстуры: держатель задержки %s отпустил замки по общему сроку %s, видя ждущих замка "+
			"%d из %d, — сцена конкуренции не построена, вердикта о предмете нет", name, holdSceneBudget, seen, want)
	}
	t.Logf("сцена %s построена: держатель видел ждущих замка %d из %d, держал %d мс при общем сроке %s",
		name, seen, want, heldMs, holdSceneBudget)
	return int(seen)
}

// deadlocksAfterPoolClose — счётчик взаимных блокировок базы, прочитанный
// ПОСЛЕ закрытия пула: обслуживающий процесс сбрасывает статистику на выходе,
// а живой — лишь спустя интервал простоя. Читается своим соединением.
func deadlocksAfterPoolClose(t *testing.T, ctx context.Context, dsn string, pool *pgxpool.Pool) int64 {
	t.Helper()
	pool.Close()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err, "соединение для чтения статистики")
	defer func() { _ = conn.Close(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var others int
		require.NoError(t, conn.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&others))
		if others == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("процессов пула в базе %d через 10 с после закрытия — статистика не сброшена", others)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var deadlocks int64
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&deadlocks))
	return deadlocks
}

func databaseDeadlocks(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var deadlocks int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&deadlocks))
	return deadlocks
}

// ─────────────────────────────────────────────────────────────────────────────
// Состояние записей сессии человека.

func liveSessionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1 AND ended_at IS NULL`,
		string(uid)).Scan(&n))
	return n
}

// endedSessionsOfRecords — сумма `sessions_ended` по записям «снято» и число
// записей «не снято».
func endedSessionsOfRecords(t *testing.T, records []map[string]any) (ended, failed int) {
	t.Helper()
	for _, r := range records {
		switch r["session_teardown"] {
		case "ended":
			num, ok := r["sessions_ended"].(json.Number)
			require.True(t, ok, "число снятых в записи не число: %v", r)
			n, err := num.Int64()
			require.NoError(t, err, "число снятых в записи: %v", r)
			ended += int(n)
		default:
			failed++
		}
	}
	return ended, failed
}

func seedLiveSessions(t *testing.T, ctx context.Context, s *concurrencyScene, uid domain.UserID, n int) []domain.HumanSessionID {
	t.Helper()
	out := make([]domain.HumanSessionID, 0, n)
	for i := 0; i < n; i++ {
		digest := freshBearerDigest(t)
		out = append(out, seedOwnLoginSession(t, ctx, s.pool, uid, digest))
		requireLiveBefore(t, ctx, s.sessions, digest)
	}
	return out
}

const concurrentTeardownHold = "probe_concurrent_teardown_hold"

// TestIntegration_ConcurrentForceLogoutsEndEachSessionOnce — M принудительных
// выходов одного человека сразу: каждая запись снята ровно один раз, сумма
// `sessions_ended` по M записям равна N, взаимных блокировок ноль.
func TestIntegration_ConcurrentForceLogoutsEndEachSessionOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	s := newConcurrencyScene(t)
	installOneShotHold(t, ctx, s.pool, concurrentTeardownHold, "human_sessions", "UPDATE OF ended_at")
	deadlocksBefore := databaseDeadlocks(t, ctx, s.pool)

	const (
		rounds            = 3
		sessionsPerPerson = 5
		logoutsAtOnce     = 4
	)
	var denominator, sumEnded, lockWaiters, failedRecords, callFailures int
	for round := 0; round < rounds; round++ {
		uid := seedForceLogoutUser(t, ctx, s.pool)
		seedLiveSessions(t, ctx, s, uid, sessionsPerPerson)
		live := liveSessionCount(t, ctx, s.pool, uid)
		require.Equal(t, sessionsPerPerson, live, "прогон %d: знаменатель сцены", round)
		denominator += live

		armOneShotHold(t, ctx, s.pool, concurrentTeardownHold, logoutsAtOnce-1)
		results := make(chan error, logoutsAtOnce)
		go func() { results <- s.forceLogout(uid) }()
		awaitSleepingBackend(t, ctx, s.pool)
		for i := 1; i < logoutsAtOnce; i++ {
			go func() { results <- s.forceLogout(uid) }()
		}

		for i := 0; i < logoutsAtOnce; i++ {
			if err := <-results; err != nil {
				callFailures++
				t.Logf("прогон %d: выход отказал: %s %q", round, status.Code(err), status.Convert(err).Message())
			}
		}
		disarmOneShotHold(t, ctx, s.pool, concurrentTeardownHold)
		lockWaiters += requireHoldSceneBuilt(t, ctx, s.pool, concurrentTeardownHold)

		records := forceLogoutRecords(t, ctx, s.pool, uid)
		ended, failed := endedSessionsOfRecords(t, records)
		sumEnded += ended
		failedRecords += failed
		t.Logf("прогон %d: живых до %d · выходов %d · записей %d · Σ sessions_ended %d · «не снято» %d · живых после %d",
			round, live, logoutsAtOnce, len(records), ended, failed, liveSessionCount(t, ctx, s.pool, uid))

		assert.Len(t, records, logoutsAtOnce,
			"прогон %d: каждый принудительный выход обязан оставить свою запись", round)
		assert.Equal(t, live, ended,
			"прогон %d: Σ sessions_ended по записям обязана равняться числу живых записей до сцены — "+
				"большее значит, что запись сессии снята НЕСКОЛЬКИМИ транзакциями", round)
		assert.Zero(t, liveSessionCount(t, ctx, s.pool, uid), "прогон %d: живые записи после выходов", round)
	}

	aborted := s.refusals.aborted()
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, s.dsn, s.pool)
	t.Logf("прогонов %d · знаменатель (живых записей до сцен) %d · Σ sessions_ended %d · ждавших замка %d · "+
		"записей «не снято» %d · отказов вызова %d · отказов хранилища %d · ABORTED %d · pg_stat_database.deadlocks +%d",
		rounds, denominator, sumEnded, lockWaiters, failedRecords, callFailures,
		len(s.refusals.all()), aborted, deadlocksAfter-deadlocksBefore)

	require.Positive(t, denominator, "знаменатель пуст — сумма ниже равнялась бы нулю на пустом месте")
	assert.Equal(t, denominator, sumEnded, "Σ sessions_ended по всем прогонам")
	assert.Zero(t, failedRecords, "записи «снятие не состоялось»")
	assert.Zero(t, callFailures, "отказы принудительного выхода")
	assert.Zero(t, aborted, "ABORTED (40P01) в транзакциях выхода")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
}

// passwordChangeSessionWrites — операторы смены пароля над записями сессии, в
// ТОМ порядке, в каком их исполняет `ChangePasswordUseCase.Execute`
// (`humansession/change_password.go`): снятие прочих записей → отсечка →
// перевыпуск носителя своей записи → фиксация, одной транзакцией писателя
// сессии. Замена материала пароля и запись события опущены: они не берут ни
// одной строки, которую берёт принудительный выход (`login_methods`,
// вставка в `audit_outbox`). Отвечает числом снятых — значимым, только если
// транзакция зафиксирована.
func passwordChangeSessionWrites(ctx context.Context, repo *kanamepg.HumanSessionRepo, uid domain.UserID,
	keep domain.HumanSessionID, rotated domain.BearerDigest,
) (int, error) {
	w, err := repo.Writer(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	now := time.Now().UTC()
	n, err := w.EndOtherSessions(ctx, uid, keep, now, domain.RevokeReasonPasswordChange)
	if err != nil {
		return 0, err
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: uid, RevokeBefore: now, Reason: domain.RevokeReasonPasswordChange,
	}, uid); err != nil {
		return 0, err
	}
	if err := w.RotateBearer(ctx, keep, rotated, now); err != nil {
		return 0, err
	}
	if err := w.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// TestIntegration_ForceLogoutThenPasswordChangeEndsEachSessionOnce — выход
// начал первым, смена пароля (keep — своя запись смены) пришла, пока выход
// держит снятые записи.
//
// Исход смены пароля здесь — отказ перевыпуска носителя (`NotFound`): её
// собственную запись снял выход, и транзакция смены откатывается целиком. Это
// исход продукта, а не поломка сцены; число снятых ею в сумму не входит,
// потому что не зафиксировано.
func TestIntegration_ForceLogoutThenPasswordChangeEndsEachSessionOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	forceLogoutAgainstPasswordChange(t, false)
}

// TestIntegration_PasswordChangeThenForceLogoutEndsEachSessionOnce — смена
// пароля начала первой и держит прочие записи, ещё не перевыпустив носитель
// своей; выход пришёл в это окно.
func TestIntegration_PasswordChangeThenForceLogoutEndsEachSessionOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	forceLogoutAgainstPasswordChange(t, true)
}

// forceLogoutAgainstPasswordChange — сцена «выход против смены пароля» в
// заданном порядке: каждая запись снята ровно один раз, сумма снятых
// зафиксированными транзакциями равна N, выход не отказал, взаимных
// блокировок ноль.
func forceLogoutAgainstPasswordChange(t *testing.T, passwordChangeFirst bool) {
	t.Helper()
	ctx := context.Background()
	s := newConcurrencyScene(t)
	installOneShotHold(t, ctx, s.pool, concurrentTeardownHold, "human_sessions", "UPDATE OF ended_at")
	deadlocksBefore := databaseDeadlocks(t, ctx, s.pool)

	const (
		rounds            = 3
		sessionsPerPerson = 5
	)
	var denominator, sumEnded, lockWaiters, passwordAborted, logoutFailures int
	for round := 0; round < rounds; round++ {
		uid := seedForceLogoutUser(t, ctx, s.pool)
		ids := seedLiveSessions(t, ctx, s, uid, sessionsPerPerson)
		keep := ids[0]
		rotated := domain.BearerDigest(freshBearerDigest(t))
		live := liveSessionCount(t, ctx, s.pool, uid)
		require.Equal(t, sessionsPerPerson, live, "прогон %d: знаменатель сцены", round)
		denominator += live

		type pcOutcome struct {
			ended int
			err   error
		}
		pcDone := make(chan pcOutcome, 1)
		flDone := make(chan error, 1)
		runPC := func() {
			n, err := passwordChangeSessionWrites(ctx, s.sessions, uid, keep, rotated)
			pcDone <- pcOutcome{n, err}
		}
		runFL := func() { flDone <- s.forceLogout(uid) }

		armOneShotHold(t, ctx, s.pool, concurrentTeardownHold, 1)
		if passwordChangeFirst {
			go runPC()
			awaitSleepingBackend(t, ctx, s.pool)
			go runFL()
		} else {
			go runFL()
			awaitSleepingBackend(t, ctx, s.pool)
			go runPC()
		}
		pc := <-pcDone
		flErr := <-flDone
		disarmOneShotHold(t, ctx, s.pool, concurrentTeardownHold)
		lockWaiters += requireHoldSceneBuilt(t, ctx, s.pool, concurrentTeardownHold)

		records := forceLogoutRecords(t, ctx, s.pool, uid)
		flEnded, flFailed := endedSessionsOfRecords(t, records)
		committed := flEnded
		if pc.err == nil {
			committed += pc.ended
		}
		sumEnded += committed
		if pc.err != nil && stderrors.Is(pc.err, iamerr.ErrAborted) {
			passwordAborted++
		}
		if flErr != nil {
			logoutFailures++
		}
		after := liveSessionCount(t, ctx, s.pool, uid)
		t.Logf("прогон %d: живых до %d · выход: ошибка=%v снято=%d «не снято»=%d · "+
			"смена пароля: ошибка=%v снято=%d · Σ зафиксированных %d · живых после %d",
			round, live, flErr, flEnded, flFailed, pc.err, pc.ended, committed, after)

		assert.NoError(t, flErr, "прогон %d: принудительный выход", round)
		assert.Equal(t, live, committed,
			"прогон %d: Σ снятых зафиксированными транзакциями обязана равняться числу "+
				"живых записей до сцены — большее значит двойное снятие, меньшее — неснятую запись", round)
		assert.Zero(t, after, "прогон %d: живые записи после сцены", round)
		if passwordChangeFirst {
			assert.NoError(t, pc.err, "прогон %d: смена пароля, начавшая первой", round)
		} else if pc.err != nil {
			assert.True(t, stderrors.Is(pc.err, iamerr.ErrNotFound),
				"прогон %d: смена пароля после выхода обязана откатываться отказом "+
					"перевыпуска своей снятой записи (NotFound), а не иным: %v", round, pc.err)
		}
	}

	aborted := s.refusals.aborted()
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, s.dsn, s.pool)
	t.Logf("прогонов %d · знаменатель (живых записей до сцен) %d · Σ снятых зафиксированными %d · ждавших замка %d · "+
		"отказов выхода %d · ABORTED выхода %d · ABORTED смены пароля %d · pg_stat_database.deadlocks +%d",
		rounds, denominator, sumEnded, lockWaiters,
		logoutFailures, aborted, passwordAborted, deadlocksAfter-deadlocksBefore)

	require.Positive(t, denominator, "знаменатель пуст — сумма ниже равнялась бы нулю на пустом месте")
	assert.Equal(t, denominator, sumEnded, "Σ снятых зафиксированными транзакциями по всем прогонам")
	assert.Zero(t, aborted+passwordAborted, "ABORTED (40P01): выход против смены пароля")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
	assert.Zero(t, logoutFailures, "отказы принудительного выхода")
}
