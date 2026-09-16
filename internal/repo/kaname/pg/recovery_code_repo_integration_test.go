// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_code_repo_integration_test.go — сторона ХРАНИЛИЩА кода
// восстановления (фаза Ф5, задача `kacho#1271`; приёмка
// `docs/engineering/acceptance/recovery-of-access.md`).
//
// Пробы уровня I на настоящей базе: намерение письма атомарно со строкой кода
// (Ф5-09); применение — ОДИН оператор, под конкуренцией проходит ровно одно
// предъявление (Ф5-05, Р1); истёкший код не применяется и не оживает (Ф5-04);
// свёртка, прочитанная из строки, предъявлением не является (Ф5-07); новый
// запрос вытесняет неприменённые коды личности; журнал завершений принимает
// поток без внешнего субъекта (Р4); уборка снимает применённые и истёкшие.
//
// Часы — пробы (форма Ф-д): каждый момент задаётся явно, а не берётся у стены.
package pg_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const rcTTL = 5 * time.Minute

func rcCode(t *testing.T, id string, user domain.UserID, issued time.Time) (domain.RecoveryCode, domain.RecoveryCodeValue) {
	t.Helper()
	value, err := domain.NewRecoveryCodeValue()
	require.NoError(t, err)
	return domain.RecoveryCode{
		ID: domain.RecoveryCodeID(id), UserID: user, Digest: value.Digest(),
		IssuedAt: issued, ExpiresAt: issued.Add(rcTTL),
	}, value
}

func rcInsert(t *testing.T, repo *pg.HumanSessionRepo, c domain.RecoveryCode) {
	t.Helper()
	ctx := context.Background()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertRecoveryCode(ctx, c))
	require.NoError(t, w.Commit(ctx))
}

func rcConsume(t *testing.T, repo *pg.HumanSessionRepo, user domain.UserID, digest domain.CodeDigest, now time.Time) (domain.RecoveryCode, bool) {
	t.Helper()
	ctx := context.Background()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	got, ok, err := w.ConsumeRecoveryCode(ctx, user, digest, now)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return got, ok
}

// TestRecoveryCodes_F5_09_MailIntentIsAtomicWithTheCodeRow — Ф5-09: строка
// кода и намерение письма появляются вместе либо не появляются вовсе; вид
// события — свой, отличный от приглашения.
func TestRecoveryCodes_F5_09_MailIntentIsAtomicWithTheCodeRow(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rc09", 1)[0]
	code, value := rcCode(t, "rcv-09a", user, hsBase)
	intent := humansession.RecoveryMailIntent{
		UserID: user, AccountID: "acc-rc09", To: "rc09-00@example.invalid", Code: value, ValidFor: rcTTL,
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertRecoveryCode(ctx, code))
	require.NoError(t, w.EmitRecoveryMail(ctx, intent))
	require.NoError(t, w.Rollback(ctx))

	var codes, letters int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, string(user)).Scan(&codes))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM invite_mail_outbox WHERE resource_id = $1`, string(user)).Scan(&letters))
	require.Zero(t, codes, "откат не оставил кода")
	require.Zero(t, letters, "откат не оставил намерения: письма о коде, которого нет, не бывает")

	// Положительный контроль — фиксация оставляет оба, и вид события свой.
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertRecoveryCode(ctx, code))
	require.NoError(t, w.EmitRecoveryMail(ctx, intent))
	require.NoError(t, w.Commit(ctx))

	var eventType, to, letterCode string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, payload->>'to', payload->>'code' FROM invite_mail_outbox WHERE resource_id = $1`,
		string(user)).Scan(&eventType, &to, &letterCode))
	require.Equal(t, "mail.recovery.send", eventType, "вид события объявлен и отличен от приглашения (Р3)")
	require.NotEqual(t, "mail.invite.send", eventType)
	require.Equal(t, "rc09-00@example.invalid", to)
	require.Equal(t, value.Letter(), letterCode, "письмо несёт код в форме для человека")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id = $1`, string(user)).Scan(&codes))
	require.Equal(t, 1, codes)
}

// TestRecoveryCodes_F5_03_05_ConsumeIsOneOperatorAndWinsOnce — Р1, Ф5-03,
// Ф5-05: применение — один оператор; повтор — отказ; под конкуренцией из N
// предъявлений одного кода проходит РОВНО одно.
func TestRecoveryCodes_F5_03_05_ConsumeIsOneOperatorAndWinsOnce(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rc03", 1)[0]
	code, value := rcCode(t, "rcv-03a", user, hsBase)
	rcInsert(t, repo, code)

	got, ok := rcConsume(t, repo, user, value.Digest(), hsBase.Add(time.Minute))
	require.True(t, ok, "Ф5-03: код в срок применяется")
	require.Equal(t, code.ID, got.ID, "оператор возвращает идентификатор потока — ключ идемпотентности журнала (Р4)")
	require.NotNil(t, got.ConsumedAt)

	_, ok = rcConsume(t, repo, user, value.Digest(), hsBase.Add(2*time.Minute))
	require.False(t, ok, "Ф5-05: второе предъявление — отказ")

	// Конкуренция: свежий код, N параллельных предъявлений — одно проходит.
	code2, value2 := rcCode(t, "rcv-03b", user, hsBase)
	rcInsert(t, repo, code2)
	const n = 8
	var wg sync.WaitGroup
	wins := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				wins <- false
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			_, ok, err := w.ConsumeRecoveryCode(ctx, user, value2.Digest(), hsBase.Add(time.Minute))
			if err != nil || !ok {
				wins <- false
				return
			}
			wins <- w.Commit(ctx) == nil
		}()
	}
	wg.Wait()
	close(wins)
	won := 0
	for x := range wins {
		if x {
			won++
		}
	}
	require.Equal(t, 1, won, "Ф5-05: решение принимает один оператор базы — из %d предъявлений проходит ровно одно", n)
}

// TestRecoveryCodes_F5_04_ExpiredIsRefusedAndDoesNotRevive — Ф5-04: после срока
// отказ; повтор того же кода его не оживляет; граница срока включающая.
func TestRecoveryCodes_F5_04_ExpiredIsRefusedAndDoesNotRevive(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	user := lmPeople(t, pool, "rc04", 1)[0]
	code, value := rcCode(t, "rcv-04a", user, hsBase)
	rcInsert(t, repo, code)

	_, ok := rcConsume(t, repo, user, value.Digest(), hsBase.Add(rcTTL))
	require.False(t, ok, "в сам момент срока кода уже нет")
	_, ok = rcConsume(t, repo, user, value.Digest(), hsBase.Add(rcTTL+time.Second))
	require.False(t, ok, "Ф5-04: после срока — отказ")
	_, ok = rcConsume(t, repo, user, value.Digest(), hsBase.Add(rcTTL+time.Minute))
	require.False(t, ok, "Ф5-04: повторное предъявление не оживляет код")

	// Положительный контроль — тот же код до срока проходит.
	code2, value2 := rcCode(t, "rcv-04b", user, hsBase)
	rcInsert(t, repo, code2)
	_, ok = rcConsume(t, repo, user, value2.Digest(), hsBase.Add(rcTTL-time.Second))
	require.True(t, ok)
}

// TestRecoveryCodes_F5_07_StoredDigestPresentedAsACodeIsRefused — Ф5-07:
// значение, которым располагает видевший хранимую строку, предъявлением не
// является: свёртка, поданная как код, даёт свёртку свёртки и не совпадает.
func TestRecoveryCodes_F5_07_StoredDigestPresentedAsACodeIsRefused(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rc07", 1)[0]
	code, value := rcCode(t, "rcv-07a", user, hsBase)
	rcInsert(t, repo, code)

	var stored string
	require.NoError(t, pool.QueryRow(ctx, `SELECT code_digest FROM recovery_codes WHERE id = $1`, string(code.ID)).Scan(&stored))
	require.NotEqual(t, value.Letter(), stored, "в строке лежит не код")

	presented := domain.PresentedRecoveryCode(stored)
	_, ok := rcConsume(t, repo, user, presented.Digest(), hsBase.Add(time.Minute))
	require.False(t, ok, "Ф5-07: прочитанное из хранилища предъявлением не является")

	// Положительный контроль: настоящий код в тот же срок проходит.
	_, ok = rcConsume(t, repo, user, domain.PresentedRecoveryCode(value.Letter()).Digest(), hsBase.Add(time.Minute))
	require.True(t, ok)
}

// TestRecoveryCodes_ChangedUserOrForeignDigestIsRefused — код привязан к
// личности: предъявление чужому адресу (другой user_id) — отказ, как и код,
// которого никто не выдавал.
func TestRecoveryCodes_ChangedUserOrForeignDigestIsRefused(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	people := lmPeople(t, pool, "rcfr", 2)
	code, value := rcCode(t, "rcv-fr-a", people[0], hsBase)
	rcInsert(t, repo, code)

	_, ok := rcConsume(t, repo, people[1], value.Digest(), hsBase.Add(time.Minute))
	require.False(t, ok, "код одной личности не применяется у другой")
	stranger, err := domain.NewRecoveryCodeValue()
	require.NoError(t, err)
	_, ok = rcConsume(t, repo, people[0], stranger.Digest(), hsBase.Add(time.Minute))
	require.False(t, ok, "невыданный код — отказ")
	_, ok = rcConsume(t, repo, people[0], value.Digest(), hsBase.Add(time.Minute))
	require.True(t, ok, "положительный контроль: свой код у своей личности проходит")
}

// TestRecoveryCodes_NewRequestSupersedesTheUnconsumedOnes — новый запрос
// вытесняет неприменённые коды личности: живой код у личности ровно один, и
// это ограничивает мишень перебора.
func TestRecoveryCodes_NewRequestSupersedesTheUnconsumedOnes(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rcsp", 1)[0]
	first, firstValue := rcCode(t, "rcv-sp-a", user, hsBase)
	rcInsert(t, repo, first)

	second, secondValue := rcCode(t, "rcv-sp-b", user, hsBase.Add(time.Minute))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	n, err := w.SupersedeRecoveryCodes(ctx, user)
	require.NoError(t, err)
	require.Equal(t, 1, n, "вытеснен ровно один неприменённый код")
	require.NoError(t, w.InsertRecoveryCode(ctx, second))
	require.NoError(t, w.Commit(ctx))

	_, ok := rcConsume(t, repo, user, firstValue.Digest(), hsBase.Add(2*time.Minute))
	require.False(t, ok, "вытесненный код не применяется")
	_, ok = rcConsume(t, repo, user, secondValue.Digest(), hsBase.Add(2*time.Minute))
	require.True(t, ok, "положительный контроль: новый код применяется")
}

// TestRecoveryCompletions_F5_16_OurFlowWritesTheLedgerWithoutAnExternalSubject —
// Р4: журнал принимает поток без внешнего субъекта; повтор ключа — не вторая
// запись (Ф5-16).
func TestRecoveryCompletions_F5_16_OurFlowWritesTheLedgerWithoutAnExternalSubject(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rc16", 1)[0]

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err := w.InsertRecoveryCompletion(ctx, domain.RecoveryCompletion{
		RecoveryJTI: "rcv-16a", UserID: user, RevokedSessionCount: 1,
	})
	require.NoError(t, err)
	require.True(t, inserted)
	require.NoError(t, w.Commit(ctx))

	var ext *string
	require.NoError(t, pool.QueryRow(ctx, `SELECT external_id FROM recovery_completions WHERE recovery_jti = $1`, "rcv-16a").Scan(&ext))
	require.Nil(t, ext, "наш поток внешнего субъекта не называет: столбец NULL")

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	inserted, err = w.InsertRecoveryCompletion(ctx, domain.RecoveryCompletion{
		RecoveryJTI: "rcv-16a", UserID: user, RevokedSessionCount: 1,
	})
	require.NoError(t, err)
	require.False(t, inserted, "Ф5-16: повтор ключа — бездействие")
	require.NoError(t, w.Commit(ctx))
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rcv-16a").Scan(&n))
	require.Equal(t, 1, n)
}

// TestRecoveryCodes_SweepRemovesConsumedAndExpiredOnly — уборка (форма Ф-ж):
// применённые и истёкшие строки снимаются, живой код остаётся.
func TestRecoveryCodes_SweepRemovesConsumedAndExpiredOnly(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	user := lmPeople(t, pool, "rcsw", 1)[0]
	// Часы уборки — базы; строки датируются от «сейчас» базы.
	var dbNow time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow))

	expired, _ := rcCode(t, "rcv-sw-expired", user, dbNow.Add(-time.Hour))
	consumed, consumedValue := rcCode(t, "rcv-sw-consumed", user, dbNow.Add(-time.Minute))
	live, _ := rcCode(t, "rcv-sw-live", user, dbNow)
	rcInsert(t, repo, expired)
	rcInsert(t, repo, consumed)
	rcInsert(t, repo, live)
	_, ok := rcConsume(t, repo, user, consumedValue.Digest(), dbNow)
	require.True(t, ok)

	removed, full, err := repo.SweepUnservableRecoveryCodes(ctx, 0, 100)
	require.NoError(t, err)
	require.False(t, full)
	require.EqualValues(t, 2, removed, "снимаются истёкшая и применённая")

	var ids []string
	rows, err := pool.Query(ctx, `SELECT id FROM recovery_codes WHERE user_id = $1`, string(user))
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	rows.Close()
	require.Equal(t, []string{"rcv-sw-live"}, ids, "живой код уборка не трогает")

	_, _, err = repo.SweepUnservableRecoveryCodes(ctx, 0, 0)
	require.Error(t, err, "партия обязана быть положительной")
}
