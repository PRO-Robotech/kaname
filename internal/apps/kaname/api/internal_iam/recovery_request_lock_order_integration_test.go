// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// recovery_request_lock_order_integration_test.go — ЗАПРОС КОДА ВОССТАНОВЛЕНИЯ
// БЕРЁТ СТРОКУ ЛИЧНОСТИ РАНЬШЕ СТРОК КОДА (задача kaname#770, находка ревью
// распределённых свойств).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Исход смены адреса (`RegistrationStore.EmailChangeWriter`) открывается
// замком строки личности `FOR UPDATE` (kaname#770) и той же транзакцией снимает
// неприменённые коды восстановления. Запрос кода восстановления снимает те же
// коды и вставляет новый — вставка проверкой внешнего ключа берёт строку
// личности `FOR KEY SHARE`, с `FOR UPDATE` несовместимой. Запрос, взявший
// строки кода РАНЬШЕ личности, держит коды и ждёт личность, исход смены держит
// личность и ждёт коды — встречный порядок. Удаление личности (`FOR UPDATE` и
// каскад на коды) встречается с таким запросом тем же образом. Запрос —
// анонимный глагол: адрес называет любой.
//
// Порядок, который снимает встречу, — «личность → всё прочее»: запрос
// открывает транзакцию ключевым замком строки личности (`Store.PersonWriter`).
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК СТРОИТСЯ СЦЕНА И ЧТО УТВЕРЖДАЕТСЯ
//
// Запрос кода — НАСТОЯЩИЙ вариант использования (постановка на месте,
// `SyncDispatcher`) над настоящими адаптерами; у личности заранее посеян живой
// код. Одноразовая задержка стоит на операторе снятия кодов: запрос держит их,
// второй участник приходит в это окно, и сцена построена, только когда
// держатель видел его ждущим ЗАМКА (`requireHoldSceneBuilt`). Утверждается:
// взаимных блокировок ноль (`pg_stat_database.deadlocks` +0), второй участник
// зафиксирован, письмо с кодом поставлено в каждом прогоне.
//
// Контрольная рука — транзакция запроса с прежним порядком (коды, затем
// вставка кода без замка личности) в той же сцене против исхода смены адреса:
// она обязана давать взаимную блокировку в каждом прогоне. Без неё «ноль»
// сцен был бы неотличим от сцены, которая блокировку увидеть не способна.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const recoveryLockOrderHold = "probe_recovery_request_hold"

// queuedRecoveryObserver — счёт исходов запроса: ответ запроса один при любом
// исходе (Р2), и только клетка наблюдателя говорит, легли ли код и письмо.
type queuedRecoveryObserver struct {
	humansession.NopObserver
	mu       sync.Mutex
	outcomes map[humansession.RecoveryRequestOutcome]int
}

func (o *queuedRecoveryObserver) RecoveryRequestObserved(outcome humansession.RecoveryRequestOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.outcomes == nil {
		o.outcomes = map[humansession.RecoveryRequestOutcome]int{}
	}
	o.outcomes[outcome]++
}

func (o *queuedRecoveryObserver) count(outcome humansession.RecoveryRequestOutcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

// recoveryLockOrderLane — полоса сцен: запрос кода со счётом исходов и глаголы
// смены адреса тем же составом, что в композиционном корне.
type recoveryLockOrderLane struct {
	*sessionWriterLane
	observer      *queuedRecoveryObserver
	recovery      *humansession.RequestRecoveryUseCase
	changeRequest *humansession.RequestEmailChangeUseCase
	changeConfirm *humansession.ConfirmEmailChangeUseCase
	codes         map[domain.UserID]string
}

func newRecoveryLockOrderLane(t *testing.T) *recoveryLockOrderLane {
	t.Helper()
	l := &recoveryLockOrderLane{sessionWriterLane: newSessionWriterLane(t), observer: &queuedRecoveryObserver{},
		codes: map[domain.UserID]string{}}
	var err error
	l.recovery, err = humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: l.s.sessions, CodeTTL: 5 * time.Minute, Dispatcher: humansession.SyncDispatcher{}, Observer: l.observer,
		Sources: l.s.sessions, SourcePace: humansession.SourcePace{Limit: 10000, Window: time.Hour},
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
		Now:       time.Now,
	})
	require.NoError(t, err)
	deps := humansession.EmailChangeDeps{
		Store:     sceneEmailChangeStore{sessions: l.s.sessions, inner: kanamepg.NewRegistrationStore(l.s.pool)},
		Methods:   kanamepg.NewLoginMethodRepo(l.s.pool),
		Pace:      humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour},
		Freshness: 15 * time.Minute,
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 10000, Window: time.Hour},
	}
	l.changeRequest, err = humansession.NewRequestEmailChangeUseCase(deps)
	require.NoError(t, err)
	l.changeConfirm, err = humansession.NewConfirmEmailChangeUseCase(deps)
	require.NoError(t, err)
	return l
}

// seedWithLiveCode — личность с живым кодом восстановления: запрос в сцене
// снимает его оператором, на котором стоит задержка, и держит его строку.
func (l *recoveryLockOrderLane) seedWithLiveCode(t *testing.T) writerPerson {
	t.Helper()
	ctx := context.Background()
	p := l.seedPerson(t)
	before := l.observer.count(humansession.RecoveryRequestQueued)
	require.NoError(t, l.recovery.Execute(ctx, humansession.RequestRecoveryInput{Email: p.email, Source: writerSceneSource}),
		"посев: запрос кода")
	require.Equal(t, before+1, l.observer.count(humansession.RecoveryRequestQueued), "посев: код выдан, письмо в очереди")
	var live int
	require.NoError(t, l.s.pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`, string(p.id)).Scan(&live))
	require.Equal(t, 1, live, "посев: у личности живой код восстановления")
	return p
}

// seedWithPendingChange — к живому коду восстановления добавлена отложенная
// смена адреса с кодом из строки очереди.
func (l *recoveryLockOrderLane) seedWithPendingChange(t *testing.T) writerPerson {
	t.Helper()
	ctx := context.Background()
	p := l.seedWithLiveCode(t)
	newEmail := "scene-rq-" + strings.ToLower(ids.NewID("tst")[3:13]) + "@example.invalid"
	_, err := l.changeRequest.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: p.bearer, NewEmail: newEmail})
	require.NoError(t, err, "посев: запрос смены адреса")
	var code string
	require.NoError(t, l.s.pool.QueryRow(ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox
		 WHERE event_type = 'mail.email-change.send' AND payload->>'user_id' = $1 ORDER BY id DESC LIMIT 1`,
		string(p.id)).Scan(&code), "посев: код смены из строки очереди")
	require.NotEmpty(t, code, "посев: письмо смены несёт код")
	l.codes[p.id] = code
	return p
}

func (l *recoveryLockOrderLane) confirmChange(ctx context.Context, p writerPerson) error {
	_, err := l.changeConfirm.Execute(ctx, humansession.ConfirmEmailChangeInput{Bearer: p.bearer, Code: l.codes[p.id]})
	return err
}

func (l *recoveryLockOrderLane) requestRecovery(ctx context.Context, p writerPerson) error {
	return l.recovery.Execute(ctx, humansession.RequestRecoveryInput{Email: p.email, Source: writerSceneSource})
}

// recoveryOverlapRound — исход одного прогона сцены.
type recoveryOverlapRound struct {
	holderErr, otherErr error
	waiters             int
}

// runRecoveryOverlap — прогон: держатель снимает коды и спит в задержке,
// второй участник приходит в окно.
func runRecoveryOverlap(t *testing.T, l *recoveryLockOrderLane, p writerPerson,
	holder, other func(ctx context.Context, p writerPerson) error,
) recoveryOverlapRound {
	t.Helper()
	ctx := context.Background()
	pool := l.s.pool
	holderDone := make(chan error, 1)
	otherDone := make(chan error, 1)
	armOneShotHold(t, ctx, pool, recoveryLockOrderHold, 1)
	go func() { holderDone <- holder(ctx, p) }()
	awaitSleepingBackend(t, ctx, pool)
	go func() { otherDone <- other(ctx, p) }()
	r := recoveryOverlapRound{holderErr: <-holderDone, otherErr: <-otherDone}
	disarmOneShotHold(t, ctx, pool, recoveryLockOrderHold)
	r.waiters = requireHoldSceneBuilt(t, ctx, pool, recoveryLockOrderHold)
	return r
}

// TestIntegration_RecoveryRequestAndEmailChangeConfirmDoNotDeadlock — запрос
// кода держит снятые коды, исход смены адреса приходит в окно.
func TestIntegration_RecoveryRequestAndEmailChangeConfirmDoNotDeadlock(t *testing.T) {
	l := newRecoveryLockOrderLane(t)
	ctx := context.Background()
	pool := l.s.pool

	// Законный близнец: та же личность с тем же посевом — оба глагола по
	// очереди, без конкуренции, фиксируются.
	lone := l.seedWithPendingChange(t)
	require.NoError(t, l.requestRecovery(ctx, lone), "близнец: запрос кода без конкурента")
	require.NoError(t, l.confirmChange(ctx, lone), "близнец: исход смены без конкурента")

	installOneShotHold(t, ctx, pool, recoveryLockOrderHold, "recovery_codes", "DELETE")
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)
	queuedBefore := l.observer.count(humansession.RecoveryRequestQueued)

	const rounds = 3
	var waiters, confirmFailures int
	for round := 0; round < rounds; round++ {
		p := l.seedWithPendingChange(t)
		queuedBefore++ // посев выдал код
		r := runRecoveryOverlap(t, l, p, l.requestRecovery, l.confirmChange)
		waiters += r.waiters
		require.NoError(t, r.holderErr, "ответ запроса кода один при любом исходе")
		if r.otherErr != nil {
			confirmFailures++
		}
		t.Logf("прогон %d: запрос кода: ошибка=%v · исход смены адреса: ошибка=%v", round, r.holderErr, r.otherErr)
	}
	queued := l.observer.count(humansession.RecoveryRequestQueued) - queuedBefore
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("прогонов %d · ждавших замка %d · кодов, выданных запросом в сцене, %d · отказов исхода смены %d · "+
		"pg_stat_database.deadlocks +%d", rounds, waiters, queued, confirmFailures, deadlocksAfter-deadlocksBefore)

	assert.Zero(t, deadlocksAfter-deadlocksBefore,
		"pg_stat_database.deadlocks: запрос кода держит строки кода и ждёт личность, "+
			"исход смены адреса держит личность и ждёт строки кода")
	assert.Equal(t, rounds, queued, "запрос кода в сцене обязан выдать код и поставить письмо в каждом прогоне")
	assert.Zero(t, confirmFailures, "отказы исхода смены адреса")
}

// TestIntegration_RecoveryRequestAndIdentityDeletionDoNotDeadlock — запрос
// кода держит снятые коды, удаление личности приходит в окно.
func TestIntegration_RecoveryRequestAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	l := newRecoveryLockOrderLane(t)
	ctx := context.Background()
	pool := l.s.pool

	lone := l.seedWithLiveCode(t)
	require.NoError(t, deletePerson(ctx, l.users, lone.id), "близнец: удаление без конкурента обязано фиксироваться")

	installOneShotHold(t, ctx, pool, recoveryLockOrderHold, "recovery_codes", "DELETE")
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)
	queuedBefore := l.observer.count(humansession.RecoveryRequestQueued)

	const rounds = 3
	var waiters, deletionFailures, survivors int
	for round := 0; round < rounds; round++ {
		p := l.seedWithLiveCode(t)
		queuedBefore++
		r := runRecoveryOverlap(t, l, p, l.requestRecovery, func(ctx context.Context, p writerPerson) error {
			return deletePerson(ctx, l.users, p.id)
		})
		waiters += r.waiters
		require.NoError(t, r.holderErr, "ответ запроса кода один при любом исходе")
		if r.otherErr != nil {
			deletionFailures++
		}
		if personExists(t, ctx, l.s, p.id) {
			survivors++
		}
		t.Logf("прогон %d: запрос кода: ошибка=%v · удаление: ошибка=%v", round, r.holderErr, r.otherErr)
	}
	queued := l.observer.count(humansession.RecoveryRequestQueued) - queuedBefore
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("прогонов %d · ждавших замка %d · кодов, выданных запросом в сцене, %d · отказов удаления %d · "+
		"личностей, переживших удаление, %d · pg_stat_database.deadlocks +%d",
		rounds, waiters, queued, deletionFailures, survivors, deadlocksAfter-deadlocksBefore)

	assert.Zero(t, deadlocksAfter-deadlocksBefore,
		"pg_stat_database.deadlocks: запрос кода держит строки кода и ждёт личность, "+
			"удаление держит личность и ждёт строки кода")
	assert.Equal(t, rounds, queued, "запрос кода, начавший первым, обязан выдать код в каждом прогоне")
	assert.Zero(t, deletionFailures, "отказы удаления личности")
	assert.Zero(t, survivors, "личности, пережившие удаление")
}

// TestIntegration_RecoveryCodesBeforePersonControlArmDeadlocksWithEmailChange —
// контрольная рука: транзакция запроса с прежним порядком (коды, затем вставка
// кода, берущая личность проверкой внешнего ключа) обязана давать взаимную
// блокировку с исходом смены адреса в каждом прогоне.
func TestIntegration_RecoveryCodesBeforePersonControlArmDeadlocksWithEmailChange(t *testing.T) {
	l := newRecoveryLockOrderLane(t)
	ctx := context.Background()
	pool := l.s.pool
	installOneShotHold(t, ctx, pool, recoveryLockOrderHold, "recovery_codes", "DELETE")
	deadlocksBefore := databaseDeadlocks(t, ctx, pool)

	reverse := func(ctx context.Context, p writerPerson) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx,
			`DELETE FROM kaname.recovery_codes WHERE user_id = $1 AND consumed_at IS NULL`, string(p.id)); err != nil {
			return err
		}
		value, err := domain.NewRecoveryCodeValue()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if _, err := tx.Exec(ctx, `
			INSERT INTO kaname.recovery_codes (id, user_id, code_digest, issued_at, expires_at)
			VALUES ($1, $2, $3, $4, $5)`,
			ids.NewHyphenID("rcv"), string(p.id), string(value.Digest()), now, now.Add(time.Minute)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	const rounds = 3
	var waiters, failures int
	for round := 0; round < rounds; round++ {
		p := l.seedWithPendingChange(t)
		r := runRecoveryOverlap(t, l, p, reverse, l.confirmChange)
		waiters += r.waiters
		if r.holderErr != nil || r.otherErr != nil {
			failures++
		}
		t.Logf("прогон %d: прежний порядок: ошибка=%v · исход смены адреса: ошибка=%v", round, r.holderErr, r.otherErr)
	}
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, l.s.dsn, pool)
	t.Logf("прогонов %d · ждавших замка %d · прогонов с отказом %d · pg_stat_database.deadlocks +%d",
		rounds, waiters, failures, deadlocksAfter-deadlocksBefore)
	require.Equal(t, int64(rounds), deadlocksAfter-deadlocksBefore,
		"контрольная рука с прежним порядком обязана давать взаимную блокировку в каждом прогоне — "+
			"иначе сцена запроса кода не способна её увидеть, и её «ноль» ничего не утверждает")
}
