// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// recovery_code_one_live_integration_test.go — у личности один живой код
// восстановления и под конкуренцией тоже (задача PRO-Robotech/kaname#776;
// приёмка `docs/engineering/acceptance/recovery-code-one-live-per-person.md`,
// редакция 3, сценарии RCL-02 и RCL-05).
//
// Сцены построены однократной задержкой на снятии кодов (`installOneShotHold`
// на `recovery_codes`, `DELETE`): держатель снял коды и спит, не
// зафиксировавшись, пока прочие участники не встанут в ожидание ЗАМКА; не
// встали — отказ фикстуры (`requireHoldSceneBuilt`), а не вердикт о предмете.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const recoveryOneLiveHold = "probe_recovery_one_live_hold"

// liveRecoveryCodes — неприменённые коды личности, чтением вне транзакций.
func liveRecoveryCodes(t *testing.T, l *recoveryLockOrderLane, p writerPerson) int {
	t.Helper()
	var n int
	require.NoError(t, l.s.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`, string(p.id)).Scan(&n))
	return n
}

// recoveryLettersTo — строки очереди `mail.recovery.send` личности на адрес to.
func recoveryLettersTo(t *testing.T, l *recoveryLockOrderLane, p writerPerson, to string) int {
	t.Helper()
	var n int
	require.NoError(t, l.s.pool.QueryRow(context.Background(), `SELECT count(*) FROM kaname.invite_mail_outbox
		 WHERE event_type = 'mail.recovery.send' AND payload->>'user_id' = $1 AND payload->>'to' = $2`,
		string(p.id), to).Scan(&n))
	return n
}

// TestIntegration_RCL02_ConcurrentRequestsLeaveOneLiveCode — N одновременных
// запросов кода одной личности: писем N, исход каждого «поставлено», живой код
// один — тот, что в строке очереди с наибольшим `id` (Р1, Р3, Д1).
func TestIntegration_RCL02_ConcurrentRequestsLeaveOneLiveCode(t *testing.T) {
	const n = 8
	l := newRecoveryLockOrderLane(t)
	ctx := context.Background()
	pool := l.s.pool

	p := l.seedWithLiveCode(t)
	installOneShotHold(t, ctx, pool, recoveryOneLiveHold, "recovery_codes", "DELETE")
	queuedBefore := l.observer.count(humansession.RecoveryRequestQueued)
	failedBefore := l.observer.count(humansession.RecoveryRequestStoreFailed)
	lettersBefore := recoveryLettersTo(t, l, p, p.email)

	armOneShotHold(t, ctx, pool, recoveryOneLiveHold, n-1)
	start := make(chan struct{})
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- l.requestRecovery(ctx, p)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	disarmOneShotHold(t, ctx, pool, recoveryOneLiveHold)
	waiters := requireHoldSceneBuilt(t, ctx, pool, recoveryOneLiveHold)
	for err := range errs {
		require.NoError(t, err, "ответ запроса один при любом исходе (Ф5-01)")
	}

	queued := l.observer.count(humansession.RecoveryRequestQueued) - queuedBefore
	failed := l.observer.count(humansession.RecoveryRequestStoreFailed) - failedBefore
	letters := recoveryLettersTo(t, l, p, p.email) - lettersBefore
	live := liveRecoveryCodes(t, l, p)
	t.Logf("запросов %d · ждавших замка %d · поставлено %d · store-failed %d · писем %d · живых кодов %d",
		n, waiters, queued, failed, letters, live)
	assert.Equal(t, n, queued, "каждый принятый запрос ставит письмо (Р3)")
	assert.Zero(t, failed, "проигрыш одновременному запросу — не store-failed (Р3)")
	assert.Equal(t, n, letters, "писем прибавилось ровно N")
	require.Equal(t, 1, live, "живой код у личности один (Р1)")

	var lastCode, liveDigest string
	require.NoError(t, pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
		 WHERE event_type = 'mail.recovery.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
		string(p.id)).Scan(&lastCode))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT code_digest FROM kaname.recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`,
		string(p.id)).Scan(&liveDigest))
	assert.Equal(t, string(domain.PresentedRecoveryCode(lastCode).Digest()), liveDigest,
		"живой код — тот, что в последнем поставленном письме (Д1)")
}

// TestIntegration_RCL05_RequestAfterAddressChangeGetsNoCode — исход смены
// адреса держит задержку; запрос кода для прежнего адреса приходит в окно.
// Запрос судится адресом на момент ЗАПИСИ (Р4): исход `no-row`, письма на
// прежний адрес нет, живых кодов ноль. Положительный контроль — запрос для
// нового адреса ставит письмо.
func TestIntegration_RCL05_RequestAfterAddressChangeGetsNoCode(t *testing.T) {
	l := newRecoveryLockOrderLane(t)
	ctx := context.Background()
	pool := l.s.pool

	p := l.seedWithPendingChange(t)
	installOneShotHold(t, ctx, pool, recoveryOneLiveHold, "recovery_codes", "DELETE")
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)
	queuedBefore := l.observer.count(humansession.RecoveryRequestQueued)
	noRowBefore := l.observer.count(humansession.RecoveryRequestNoRow)
	oldLetters := recoveryLettersTo(t, l, p, p.email)

	r := runRecoveryOverlap(t, l, p, l.confirmChange, l.requestRecovery)
	require.NoError(t, r.holderErr, "исход смены адреса (EC-02)")
	require.NoError(t, r.otherErr, "ответ запроса один при любом исходе (Ф5-01)")

	queued := l.observer.count(humansession.RecoveryRequestQueued) - queuedBefore
	noRow := l.observer.count(humansession.RecoveryRequestNoRow) - noRowBefore
	letters := recoveryLettersTo(t, l, p, p.email) - oldLetters
	live := liveRecoveryCodes(t, l, p)
	t.Logf("ждавших замка %d · поставлено %d · no-row %d · писем на прежний адрес +%d · живых кодов %d",
		r.waiters, queued, noRow, letters, live)
	assert.Zero(t, queued, "запрос после смены адреса кода на прежний адрес не выдаёт (Р4)")
	assert.Equal(t, 1, noRow, "исход запроса — no-row (Д3)")
	assert.Zero(t, letters, "письма на прежний адрес после смены нет")
	assert.Zero(t, live, "живых кодов у личности ноль")

	// Положительный контроль: запрос для нового адреса ставит письмо.
	var newEmail string
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM kaname.users WHERE id = $1`, string(p.id)).Scan(&newEmail))
	require.NotEqual(t, p.email, newEmail, "предпосылка: адрес сменён")
	moved := p
	moved.email = newEmail
	require.NoError(t, l.requestRecovery(ctx, moved))
	assert.Equal(t, 1, recoveryLettersTo(t, l, moved, newEmail), "письмо на новый адрес поставлено")
	assert.Equal(t, 1, liveRecoveryCodes(t, l, moved), "живой код — для нового адреса")

	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("pg_stat_database.deadlocks +%d", deadlocksAfter-deadlocksBefore)
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "ни одна транзакция не получает 40P01")
}
