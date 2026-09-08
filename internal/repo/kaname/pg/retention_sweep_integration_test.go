// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retention_sweep_integration_test.go — уборка таблиц iam, чей рост задаёт
// внешний (приёмка `retention-sweep-has-a-caller.md`, сценарии RET-SWP-01…03,
// 05…08, 15…17, 19, 20; окна темпа заведения — задача #1364, вне объёма той
// приёмки: она вынесла их из своего дословно).
//
// # Почему строки ставятся ОТНОСИТЕЛЬНО `now()` БАЗЫ
//
// Часы уборки — базы (§2.2): момент ушёл из сигнатур уборщиков, предикат целиком
// в SQL. Проба, подающая свой момент, мерила бы не тот предикат, что исполняется
// в проде. Спать при этом не приходится: уборщик зовётся методом, а не тикером —
// довод дерева, а не изобретение (`gateway/internal/idempotencypg/store.go`,
// шапка `Store.Reap`).
//
// # На какой НЕВЕРНОЙ реализации каждая проба зелена — и чем это закрыто
//
//   - «уборщик вызвался» зелено и на уборщике, не снявшем ничего, и на
//     уборщике, опустошившем таблицу ⇒ каждая проба утверждает ЧИСЛО строк и
//     исход читателя, обе стороны;
//   - грубое «в прошлом / в будущем» не различает порога `<= now()` от порога
//     с допуском ⇒ RET-SWP-17 ставит строку ВНУТРЬ окна допуска;
//   - совпадение величин не доказывает совпадения ИСТОЧНИКОВ часов ⇒
//     RET-SWP-19 разводит источники врозь.
package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// sweepBatch — партия проб. Мала намеренно: предмет проб — предикат и порог, а
// не пропускная способность; величину партии в проде объявляет конфигурация.
const sweepBatch = 100

// retentionPool — база пробы. Отдельный помощник, чтобы каждая проба не
// повторяла три строки подъёма.
func retentionPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool
}

// putAssertionAt кладёт строку погашения со сроком, СДВИНУТЫМ ОТ `now()` базы.
//
// Строка ставится оператором базы, а не через `Redeem`: `Redeem` принимает
// момент процесса, а предмет проб — часы базы.
func putAssertionAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, clientID, assertionID string, offset time.Duration) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.client_assertion_replay (client_id, assertion_id, expires_at)
		 VALUES ($1,$2, now() + make_interval(secs => $3))`,
		clientID, assertionID, offset.Seconds())
	require.NoError(t, err, "посев строки погашения")
}

// countAssertions — сколько строк погашения в таблице.
//
// Зовёт `repo.Len` — тот самый метод, который его шапка объявляет читаемым
// пробой сборщика: перепись, живущая рядом с уборщиком, обязана иметь читателя,
// иначе она сама становится объявлением без предмета. База у каждой пробы своя
// (клон шаблона на вызов `setupTestDB`), поэтому счёт по всей таблице и есть
// счёт посеянного этой пробой.
func countAssertions(t *testing.T, ctx context.Context, repo *kanamepg.ClientAssertionReplayRepo) int64 {
	t.Helper()
	n, err := repo.Len(ctx)
	require.NoError(t, err)
	return n
}

// putRevocationAt кладёт строку отзыва со сроком, сдвинутым от `now()` базы.
//
// Момент отзыва ставится ЗАВЕДОМО раньше срока: таблица несёт
// `CHECK (ttl_expires_at > revoked_at)` (`0001_initial.sql:786`), то есть
// инвариант домена «срок строго позже отзыва» держится и на уровне базы. Строку
// с уже истёкшим сроком иначе не посеять — и это не помеха пробе, а
// подтверждение, что ослабить его тихо нельзя.
func putRevocationAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid domain.UserID, jti string, offset time.Duration) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.session_revocations (token_jti, revoked_at, reason, user_id, ttl_expires_at)
		 VALUES ($1, now() + make_interval(secs => $3) - interval '1 hour', 'retention-probe', $2,
		         now() + make_interval(secs => $3))`,
		jti, string(uid), offset.Seconds())
	require.NoError(t, err, "посев строки отзыва")
}

// putCutoffAt кладёт отсечку с границей, сдвинутой от `now()` базы.
func putCutoffAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject string, offset time.Duration) {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.minted_token_revocations (subject, revoke_before, reason, revoked_by)
		 VALUES ($1, now() + make_interval(secs => $2), 'retention-probe', 'probe')`,
		subject, offset.Seconds())
	require.NoError(t, err, "посев отсечки")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-01 — уборка утверждений снимает истёкшее и только его
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_Assertions_RemovesExpiredKeepsLive(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-01-" + ids.NewID(domain.PrefixUser)

	// Заведомо за порогом и заведомо действующая.
	putAssertionAt(t, ctx, pool, clientID, "jti-expired", -(grace + time.Hour))
	putAssertionAt(t, ctx, pool, clientID, "jti-live", time.Hour)
	require.EqualValues(t, 2, countAssertions(t, ctx, repo))

	removed, full, err := repo.Reap(ctx, grace, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть РОВНО одна строка")
	require.False(t, full, "партия не полна: истёкшая строка была одна")

	require.EqualValues(t, 1, countAssertions(t, ctx, repo),
		"действующая строка обязана пережить проход")

	// Обе стороны исхода ЧИТАТЕЛЯ: повтор по пережившей строке по-прежнему
	// отвергается как повтор, а слот снятой — свободен.
	require.True(t, isReplayed(repo.Redeem(ctx, clientID, "jti-live", time.Now().UTC().Add(time.Hour))),
		"строка действующего утверждения снята — открылось окно законного повтора")
	require.NoError(t, repo.Redeem(ctx, clientID, "jti-expired", time.Now().UTC().Add(time.Hour)),
		"истёкшая строка из таблицы не ушла")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-02 — уборка отзывов снимает истёкшее и только его
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_Revocations_RemovesExpiredKeepsLive(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewSessionRevocationRepo(pool)
	uid := mustSeedUser(t, ctx, pool, "ret-02")

	expired := "ret02-expired-" + ids.NewID(domain.PrefixUser)
	live := "ret02-live-" + ids.NewID(domain.PrefixUser)
	putRevocationAt(t, ctx, pool, uid, expired, -time.Hour)
	putRevocationAt(t, ctx, pool, uid, live, time.Hour)

	removed, full, err := repo.DeleteExpired(ctx, 0, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
	require.False(t, full)

	// Исход ЧИТАТЕЛЯ, обе стороны.
	revoked, err := repo.IsRevoked(ctx, live)
	require.NoError(t, err)
	require.True(t, revoked, "действующий отзыв снят — отзыв перестал исполняться")

	var left int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.session_revocations WHERE token_jti = $1`, expired).Scan(&left))
	require.EqualValues(t, 0, left, "истёкшая строка отзыва из таблицы не ушла")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-03 — уборка отсечек: три строки, снимается ровно одна
// ───────────────────────────────────────────────────────────────────────────
//
// Строка (б) лежит МЕЖДУ верным порогом T и наименьшим из неверных,
// T + min(ClockSkew, RemovalSlack): всякое забытое слагаемое сдвигает порог
// вверх, поэтому такая строка снимается ЛЮБЫМ неверным порогом и остаётся при
// верном. Полоса `min` не зависит от того, какое слагаемое крупнее.

func TestRetentionSweep_Cutoffs_RemovesOnlyTheMeaninglessRow(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewMintedTokenRevocationRepo(pool)
	grace := tokenpolicy.MaxTokenTTL + tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack

	minSummand := tokenpolicy.ClockSkew
	if tokenpolicy.RemovalSlack < minSummand {
		minSummand = tokenpolicy.RemovalSlack
	}

	subjA := "ret03-a-" + ids.NewID(domain.PrefixUser) // заведомо старше порога
	subjB := "ret03-b-" + ids.NewID(domain.PrefixUser) // в полосе, различающей забытое слагаемое
	subjC := "ret03-c-" + ids.NewID(domain.PrefixUser) // свежая

	putCutoffAt(t, ctx, pool, subjA, -(grace + time.Hour))
	putCutoffAt(t, ctx, pool, subjB, -(grace - minSummand/2))
	putCutoffAt(t, ctx, pool, subjC, -time.Minute)

	removed, _, err := repo.SweepStaleCutoffs(ctx, grace, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть РОВНО строка (а)")

	// Исход ЧИТАТЕЛЯ по каждой строке — обе стороны.
	_, okA, err := repo.RevokedBefore(ctx, subjA)
	require.NoError(t, err)
	require.False(t, okA, "бессмысленная отсечка (а) осталась")
	_, okB, err := repo.RevokedBefore(ctx, subjB)
	require.NoError(t, err)
	require.True(t, okB, "отсечка (б) снята: порог забыл слагаемое")
	_, okC, err := repo.RevokedBefore(ctx, subjC)
	require.NoError(t, err)
	require.True(t, okC, "свежая отсечка (в) снята — уборка снимает действующую защиту")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-17 — порог утверждений по ВЕЛИЧИНЕ: окно допуска не открывается
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_Assertions_AdmissionWindowStaysClosed(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-17-" + ids.NewID(domain.PrefixUser)

	// (а) внутри окна допуска: утверждение ЕЩЁ принимается читателем, чьи часы
	// не отстают (приём открыт до exp + ClockSkew). Уборщик с порогом
	// `expires_at <= now()` эту строку снимает и открывает окно законного
	// повтора шириной ClockSkew.
	putAssertionAt(t, ctx, pool, clientID, "jti-inside-skew", -tokenpolicy.ClockSkew/2)
	// (б) за полным порогом.
	putAssertionAt(t, ctx, pool, clientID, "jti-past-grace", -(grace + time.Minute))

	removed, _, err := repo.Reap(ctx, grace, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)

	require.True(t, isReplayed(repo.Redeem(ctx, clientID, "jti-inside-skew", time.Now().UTC().Add(time.Hour))),
		"строка внутри окна допуска снята — повтор ещё принимаемого утверждения стал законным")
	require.NoError(t, repo.Redeem(ctx, clientID, "jti-past-grace", time.Now().UTC().Add(time.Hour)),
		"строка за полным порогом не снята")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-19 — порог отзывов по ИСТОЧНИКУ ЧАСОВ
// ───────────────────────────────────────────────────────────────────────────
//
// Единственная проба набора, подающая два источника ВРОЗЬ: у остальных обе
// стороны берутся с одной машины и совпадают by construction. Часы процесса
// уведены вперёд не подменой системного времени, а тем, что уборщику часов
// БОЛЬШЕ НЕ ПЕРЕДАЮТ: проба доказывает, что предикат живёт в SQL и от момента
// вызывающего не зависит. Строка (б) истекла по ОБОИМ часам — она и доказывает,
// что проход был и что-то снял.

func TestRetentionSweep_Revocations_ThresholdUsesTheDatabaseClock(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewSessionRevocationRepo(pool)
	uid := mustSeedUser(t, ctx, pool, "ret-19")

	// δ — насколько «уведены вперёд» часы процесса.
	const delta = 24 * time.Hour

	// (а) действующая по часам базы, но истёкшая по уведённым вперёд часам
	// процесса: все четыре читателя считают её действующей.
	live := "ret19-live-" + ids.NewID(domain.PrefixUser)
	putRevocationAt(t, ctx, pool, uid, live, delta/2)
	// (б) истекла по обоим часам.
	dead := "ret19-dead-" + ids.NewID(domain.PrefixUser)
	putRevocationAt(t, ctx, pool, uid, dead, -time.Hour)

	removed, _, err := repo.DeleteExpired(ctx, 0, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "проход не снял истёкшей строки — уборка не идёт")

	revoked, err := repo.IsRevoked(ctx, live)
	require.NoError(t, err)
	require.True(t, revoked,
		"снята строка, которую все четыре читателя считают действующей: уборка судит часами процесса, "+
			"а читатели — часами базы, и на δ отзыв перестаёт исполняться")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-05 — уборка идёт партиями и догоняет накопленное
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_PassRepeatsTheBatchAndIsBoundedByTheCap(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-05-" + ids.NewID(domain.PrefixUser)

	const (
		batch = 10
		cap_  = 3
		total = batch*cap_ + 7 // заведомо больше произведения
	)
	for i := range total {
		putAssertionAt(t, ctx, pool, clientID, fmt.Sprintf("jti-%03d", i), -(grace + time.Hour))
	}

	sw, err := retention.New(retention.Config{Interval: time.Minute, Batch: batch, MaxBatchesPerPass: cap_},
		[]retention.Subject{{Name: retention.SubjectClientAssertionReplay, Grace: grace, Sweep: repo.Reap}},
		nil)
	require.NoError(t, err)

	start := time.Now()
	res := sw.Pass(ctx)
	elapsed := time.Since(start)
	require.NoError(t, res.Err(), "проход отказал")

	got := res.Removed[retention.SubjectClientAssertionReplay]
	require.Greater(t, got, int64(batch), "проход снял не больше партии — партия за тик не догоняет никогда")
	require.LessOrEqual(t, got, int64(batch*cap_), "проход снял больше произведения партии на потолок — длительность не ограничена")
	require.Equal(t, cap_, res.Batches[retention.SubjectClientAssertionReplay])
	t.Logf("перепись: истёкших посеяно %d, снято за проход %d, партий %d, длительность %v",
		total, got, res.Batches[retention.SubjectClientAssertionReplay], elapsed)

	// Установившийся режим достигается за конечное число проходов (RET-SWP-07).
	for range 10 {
		if countAssertions(t, ctx, repo) == 0 {
			break
		}
		require.NoError(t, sw.Pass(ctx).Err())
	}
	require.EqualValues(t, 0, countAssertions(t, ctx, repo),
		"накопленное не разобрано за конечное число проходов")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-08 — два прохода одновременно на одной базе
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_ConcurrentPassesRemoveEachRowOnce(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-08-" + ids.NewID(domain.PrefixUser)

	const total = 60
	for i := range total {
		putAssertionAt(t, ctx, pool, clientID, fmt.Sprintf("jti-%03d", i), -(grace + time.Hour))
	}
	// Одна действующая: суммарный счёт обязан её не тронуть.
	putAssertionAt(t, ctx, pool, clientID, "jti-live", time.Hour)

	type outcome struct {
		n   int64
		err error
	}
	out := make(chan outcome, 2)
	startGate := make(chan struct{})
	for range 2 {
		go func() {
			<-startGate
			var total int64
			for range 10 {
				n, _, err := repo.Reap(ctx, grace, 10)
				if err != nil {
					out <- outcome{total, err}
					return
				}
				total += n
			}
			out <- outcome{total, nil}
		}()
	}
	close(startGate)

	var sum int64
	for range 2 {
		o := <-out
		require.NoError(t, o.err, "конкурентный проход отказал")
		sum += o.n
	}
	require.EqualValues(t, total, sum,
		"суммарное число снятых не равно числу истёкших: строка снята дважды либо потеряна")
	require.EqualValues(t, 1, countAssertions(t, ctx, repo),
		"действующая строка не пережила конкурентные проходы")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-06 — уборка не блокирует горячий путь
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_DoesNotBlockAdmission(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-06-" + ids.NewID(domain.PrefixUser)

	const total = 400
	for i := range total {
		putAssertionAt(t, ctx, pool, clientID, fmt.Sprintf("old-%03d", i), -(grace + time.Hour))
	}

	done := make(chan error, 1)
	go func() {
		for range 8 {
			if _, _, err := repo.Reap(ctx, grace, 50); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	// Допуск нового утверждения идёт ПАРАЛЛЕЛЬНО проходу. Проверяется ИСХОД
	// конкурента, а не длительность прохода: длительность — свойство машины.
	for i := range 20 {
		require.NoError(t, repo.Redeem(ctx, clientID, fmt.Sprintf("hot-%03d", i), time.Now().UTC().Add(time.Hour)),
			"допуск отказал, пока шёл проход уборки")
	}
	require.NoError(t, <-done)
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-15 — наблюдаемость различает «нечего убирать» и «уборка не доходит»
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_ReportsEachSubjectSeparately(t *testing.T) {
	ctx, pool := retentionPool(t)
	assertions := kanamepg.NewClientAssertionReplayRepo(pool)
	revocations := kanamepg.NewSessionRevocationRepo(pool)
	cutoffs := kanamepg.NewMintedTokenRevocationRepo(pool)
	windows := kanamepg.NewIdentityAdmissionWindowRepo(pool)
	journal := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)
	reconcileQ := kanamepg.NewReconcileOutboxSweeper(pool)
	compensationQ := kanamepg.NewProviderCompensationSweeper(pool)
	uid := mustSeedUser(t, ctx, pool, "ret-15")

	// По отзывам — есть что снять; по утверждениям и отсечкам — нечего.
	putRevocationAt(t, ctx, pool, uid, "ret15-"+ids.NewID(domain.PrefixUser), -time.Hour)

	sw, err := retention.New(retention.Config{Interval: time.Minute, Batch: sweepBatch, MaxBatchesPerPass: 2},
		retention.Subjects(assertions, revocations, cutoffs, windows, journal, reconcileQ, compensationQ), nil)
	require.NoError(t, err)
	res := sw.Pass(ctx)
	require.NoError(t, res.Err())

	require.Contains(t, res.Removed, retention.SubjectClientAssertionReplay,
		"предмет без находок в отчёте отсутствует — «нечего убирать» неотличимо от «уборка не доходит»")
	require.Contains(t, res.Removed, retention.SubjectSessionRevocations)
	require.Contains(t, res.Removed, retention.SubjectMintedTokenCutoffs)
	require.Contains(t, res.Removed, retention.SubjectIdentityAdmissionWindows)
	require.Contains(t, res.Removed, retention.SubjectSubjectChangeJournal)
	require.Contains(t, res.Removed, retention.SubjectReconcileOutbox)
	require.EqualValues(t, 1, res.Removed[retention.SubjectSessionRevocations])

	// Величина имеет читателя: накопитель прохода виден снаружи.
	st := sw.Stats()
	require.EqualValues(t, 1, st.Removed[retention.SubjectSessionRevocations])
	require.EqualValues(t, 1, st.Passes)
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-16 — останов не рвёт проход
// ───────────────────────────────────────────────────────────────────────────

func TestRetentionSweep_StopLeavesNoPartialState(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewClientAssertionReplayRepo(pool)
	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	clientID := "uoc-ret-16-" + ids.NewID(domain.PrefixUser)

	const total = 40
	for i := range total {
		putAssertionAt(t, ctx, pool, clientID, fmt.Sprintf("jti-%03d", i), -(grace + time.Hour))
	}

	loopCtx, cancel := context.WithCancel(ctx)
	sw, err := retention.New(retention.Config{Interval: 20 * time.Millisecond, Batch: 10, MaxBatchesPerPass: 1},
		[]retention.Subject{{Name: retention.SubjectClientAssertionReplay, Grace: grace, Sweep: repo.Reap}},
		nil)
	require.NoError(t, err)
	sw.Start(loopCtx)

	// Ждём, пока петля снимет хотя бы партию, и рвём её контекст.
	require.Eventually(t, func() bool {
		return countAssertions(t, ctx, repo) < total
	}, 5*time.Second, 20*time.Millisecond, "петля не сделала ни одного прохода")
	cancel()
	require.True(t, sw.Wait(5*time.Second), "петля не завершилась по отмене контекста")

	// Частично применённого состояния не бывает: партия — один оператор.
	// Остаток кратен партии, и следующий старт продолжает с того же места.
	left := countAssertions(t, ctx, repo)
	require.EqualValues(t, 0, left%10, "остаток не кратен партии — партия применилась частично")

	resumed, err := retention.New(retention.Config{Interval: time.Minute, Batch: 10, MaxBatchesPerPass: 10},
		[]retention.Subject{{Name: retention.SubjectClientAssertionReplay, Grace: grace, Sweep: repo.Reap}},
		nil)
	require.NoError(t, err)
	require.NoError(t, resumed.Pass(ctx).Err())
	require.EqualValues(t, 0, countAssertions(t, ctx, repo),
		"следующий старт не продолжил с того же места")
}

// ───────────────────────────────────────────────────────────────────────────
// RET-SWP-20 — смена наблюдаемого исхода UserService.Delete не приезжает молча
// ───────────────────────────────────────────────────────────────────────────
//
// Пятый читатель таблицы отзывов — ограничение целостности
// `session_revocations_user_fk` (`ON DELETE RESTRICT`). Он судит по НАЛИЧИЮ
// строки и сравнения со временем не содержит, поэтому согласовать с ним порог
// нельзя НИ ПРИ КАКОМ значении: любая уборка меняет его исход по построению.
// Проба не объявляет уборку способом чинить удаление — она не даёт смене
// исхода приехать незамеченной. Сам внешний ключ — предмет задачи-преемника П1.

func TestRetentionSweep_UserDeleteOutcomeChangesOnlyForExpiredRows(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewSessionRevocationRepo(pool)
	repository := kanamepg.New(pool, nil)

	withExpired := seedNonOwningUser(t, ctx, pool, "ret-20-expired")
	withLive := seedNonOwningUser(t, ctx, pool, "ret-20-live")
	putRevocationAt(t, ctx, pool, withExpired, "ret20-exp-"+ids.NewID(domain.PrefixUser), -time.Hour)
	putRevocationAt(t, ctx, pool, withLive, "ret20-live-"+ids.NewID(domain.PrefixUser), time.Hour)

	// До прохода неудаляемы ОБА: строка есть у каждого.
	require.Error(t, deleteUser(t, ctx, repository, withExpired),
		"пользователь со строкой отзыва удалился ДО прохода — предпосылка пробы не выполняется")

	_, _, err := repo.DeleteExpired(ctx, 0, sweepBatch)
	require.NoError(t, err)

	// Обе стороны: истёкшая строка ушла — удаление проходит; действующая на
	// месте — удаление по-прежнему отвергается.
	require.NoError(t, deleteUser(t, ctx, repository, withExpired),
		"строка истекла и снята, а удаление всё равно отвергнуто")
	require.Error(t, deleteUser(t, ctx, repository, withLive),
		"снята действующая строка отзыва — уборка сняла защиту")
}

// seedNonOwningUser заводит пользователя, который НИЧЕГО не держит, кроме
// строки отзыва.
//
// `mustSeedUser` заводит пользователя вместе с аккаунтом, которым тот ВЛАДЕЕТ, а
// `accounts_owner_fk` — тоже `ON DELETE RESTRICT`. Такой пользователь неудаляем
// всегда, независимо от уборки: проба RET-SWP-20 на нём зеленела бы обеими
// половинами и не различала бы НИЧЕГО — отказ приходил бы от невиновного
// ограничения. Здесь владелец аккаунта — отдельный пользователь, а испытуемый
// лишь состоит в том же аккаунте, поэтому единственное, что стоит между ним и
// удалением, — `session_revocations_user_fk`.
func seedNonOwningUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	owner := mustSeedUser(t, ctx, pool, suffix+"-owner")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(owner)).Scan(&accID))

	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), accID,
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s-%s@example.com", suffix, uid),
		"Test User "+suffix)
	require.NoError(t, err, "посев пользователя без владения аккаунтом")
	return uid
}

// deleteUser зовёт удаление пользователя тем же путём, что и глагол сервиса:
// writer-транзакция, тот же охранник, то же ограничение целостности.
func deleteUser(t *testing.T, ctx context.Context, repo *kanamepg.Repository, uid domain.UserID) error {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	if derr := w.UsersW().Delete(ctx, uid); derr != nil {
		_ = w.Rollback(ctx)
		return derr
	}
	return w.Commit(ctx)
}

// ───────────────────────────────────────────────────────────────────────────
// Уборка окон темпа заведения (задача #1364)
// ───────────────────────────────────────────────────────────────────────────
//
// Порог этого предмета не объявлен величиной в Go: его несущая часть —
// длительность окна — лежит в действующей строке величин, и уборщик читает её
// оттуда же, откуда читатель-триггер. Поэтому пробы ставят СВОЮ величину строкой
// и меряют исход относительно неё.
//
// Вид пробы берётся отдельным, а не `iam.account`: посев миграции держит
// действующую величину именно на нём, и проба, правящая её, судила бы полосу,
// которую тут же и сломала бы для соседних проб.

// putAdmissionLimit заводит действующую величину темпа для отдельного вида.
func putAdmissionLimit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kind string, maxEvents, windowSeconds int) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.account_admission_rate_limits (kind, max_events, window_seconds)
		VALUES ($1, $2, $3)`, kind, maxEvents, windowSeconds)
	require.NoError(t, err)
}

// putAdmissionWindowAt ставит окно, начавшееся `offset` назад по часам БАЗЫ.
func putAdmissionWindowAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, carrier, kind string, offset time.Duration, admitted int) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.identity_admission_windows (carrier_id, kind, window_started_at, admitted)
		VALUES ($1, $2, now() + make_interval(secs => $3), $4)`,
		carrier, kind, offset.Seconds(), admitted)
	require.NoError(t, err)
}

// countAdmissionWindows — число строк вида. Утверждается ЧИСЛО, а не факт
// вызова: «вызвался» зелено и на уборщике, не снявшем ничего, и на уборщике,
// опустошившем таблицу.
func countAdmissionWindows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kind string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.identity_admission_windows WHERE kind = $1`, kind).Scan(&n))
	return n
}

// TestRetentionSweep_AdmissionWindows_RemovesElapsedKeepsLive — истёкшее окно
// снимается, действующее остаётся.
//
// Строка (б) лежит ВНУТРИ окна: уборщик, взявший порог `now()` вместо
// `now() − window_seconds`, снял бы её — то есть обнулил бы счётчик действующего
// окна и подарил бы носителю полный потолок заново.
func TestRetentionSweep_AdmissionWindows_RemovesElapsedKeepsLive(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewIdentityAdmissionWindowRepo(pool)

	kind := "ret64a.rateWindow"
	const window = 3600
	putAdmissionLimit(t, ctx, pool, kind, 3, window)

	carrierA := "ret64a-elapsed-" + ids.NewID(domain.PrefixUser) // окно истекло
	carrierB := "ret64a-live-" + ids.NewID(domain.PrefixUser)    // окно идёт

	putAdmissionWindowAt(t, ctx, pool, carrierA, kind, -(window*time.Second + time.Minute), 3)
	putAdmissionWindowAt(t, ctx, pool, carrierB, kind, -time.Minute, 3)

	removed, _, err := repo.SweepElapsedAdmissionWindows(ctx, 0, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть РОВНО истёкшая строка")
	require.EqualValues(t, 1, countAdmissionWindows(t, ctx, pool, kind),
		"осталась обязана быть РОВНО строка действующего окна")

	var live int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.identity_admission_windows WHERE kind = $1 AND carrier_id = $2`,
		kind, carrierB).Scan(&live))
	require.EqualValues(t, 1, live,
		"снята строка ДЕЙСТВУЮЩЕГО окна: счётчик обнулён, носителю подарен полный потолок заново")
}

// TestRetentionSweep_AdmissionWindows_ZeroCeilingKeepsTheRow — вид, чья
// действующая величина не допускает НИ ОДНОГО заведения в окне, строку
// сохраняет.
//
// Это несущее условие уборки, а не осторожность. Ветвь вставки триггера
// безусловна, ветвь правки — под условием `<= max_events`. При `max_events = 0`
// снятая строка означает разрешение там, где администратор запретил всё; при
// `max_events >= 1` обе ветви приводят к одному состоянию и одному исходу.
//
// Вторая половина пробы — положительный контроль: та же истёкшая строка при
// величине `1` снимается. Без него проба зеленела бы на уборщике, не снимающем
// ничего.
func TestRetentionSweep_AdmissionWindows_ZeroCeilingKeepsTheRow(t *testing.T) {
	ctx, pool := retentionPool(t)
	repo := kanamepg.NewIdentityAdmissionWindowRepo(pool)

	const window = 3600
	elapsed := -(window*time.Second + time.Minute)

	zeroKind := "ret64b.zeroCeiling"
	oneKind := "ret64b.oneCeiling"
	putAdmissionLimit(t, ctx, pool, zeroKind, 0, window)
	putAdmissionLimit(t, ctx, pool, oneKind, 1, window)

	carrier := "ret64b-" + ids.NewID(domain.PrefixUser)
	putAdmissionWindowAt(t, ctx, pool, carrier, zeroKind, elapsed, 0)
	putAdmissionWindowAt(t, ctx, pool, carrier, oneKind, elapsed, 1)

	removed, _, err := repo.SweepElapsedAdmissionWindows(ctx, 0, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть РОВНО строка вида, допускающего заведение")

	require.EqualValues(t, 1, countAdmissionWindows(t, ctx, pool, zeroKind),
		"снята строка вида с нулевым потолком: её отсутствие даёт носителю безусловное заведение "+
			"по ветви вставки — то есть разрешение там, где администратор запретил всё")
	require.EqualValues(t, 0, countAdmissionWindows(t, ctx, pool, oneKind),
		"истёкшая строка вида с потолком 1 НЕ снята — уборка не убирает ничего")
}
