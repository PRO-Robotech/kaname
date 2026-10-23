// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_step_up_repo_integration_test.go — хранилище испытаний ПОВЫШЕНИЯ
// ключом против настоящего Postgres (задача PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, Р2, Р3;
// замысел §2.1, условия пересверки У1, З1, З2).
//
// Инварианты держит база, и каждый судится гонкой либо схемой, а не чтением
// кода адаптера:
//
//   - одно ЖИВОЕ испытание на запись сессии: N одновременных выдач на одной
//     сессии — все без отказа, живое одно; близнец — выдачи на РАЗНЫХ сессиях
//     друг друга не сменяют;
//   - однократность: N одновременных предъявлений одной пары — ровно одно
//     сгорание, проигравшие читают «уже предъявлено»;
//   - принадлежность: снятие записи сессии снимает её испытания;
//   - уборка порогом РЕЕСТРА: только что предъявленное и только что истёкшее
//     остаются (три состояния различимы), давние снимаются;
//   - часы службы: предъявление моментом РАНЬШЕ выдачи (реплика с отстающими
//     часами) схемой не отвергается (У1).
package pg_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// suScene — хранилище повышения и n записей сессии одного человека.
type suScene struct {
	pool     *pgxpool.Pool
	repo     *pg.AccessKeyStepUpRepo
	sessions []domain.HumanSessionID
}

func newSUScene(t *testing.T, tag string, n int) suScene {
	t.Helper()
	pool := akPool(t)
	hs := pg.NewHumanSessionRepo(pool)
	user := lmPeople(t, pool, tag, 1)[0]
	sc := suScene{pool: pool, repo: pg.NewAccessKeyStepUpRepo(pool, pg.NewAccessKeyRepo(pool))}
	for i := 0; i < n; i++ {
		s := hsSession(user, tag+string(rune('a'+i)), time.Now().UTC())
		hsIssue(t, hs, s)
		sc.sessions = append(sc.sessions, s.ID)
	}
	return sc
}

func suRaw(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, domain.AccessKeyChallengeBytes)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func suChallenge(session domain.HumanSessionID, raw []byte, issued time.Time) domain.StepUpChallenge {
	return domain.StepUpChallenge{Challenge: raw, SessionID: session, IssuedAt: issued, ExpiresAt: issued.Add(access_keys.ChallengeTTL)}
}

// rows — строки испытаний записи сессии: всего и живых.
func (sc suScene) rows(t *testing.T, session domain.HumanSessionID) (total, live int) {
	t.Helper()
	require.NoError(t, sc.pool.QueryRow(context.Background(), `
		SELECT count(*), count(*) FILTER (WHERE consumed_at IS NULL)
		  FROM kaname.access_key_step_up_challenges WHERE session_id = $1`, string(session)).Scan(&total, &live))
	return total, live
}

// TestAccessKeyStepUpRepo_ConcurrentIssuesLeaveOneLive — З1: восемь
// одновременных выдач на одной сессии проходят без отказа, живое испытание
// одно, и оно из числа выданных; близнец — выдача на соседней сессии своё
// испытание сохраняет.
func TestAccessKeyStepUpRepo_ConcurrentIssuesLeaveOneLive(t *testing.T) {
	sc := newSUScene(t, "suiss", 2)
	ctx := context.Background()
	now := time.Now().UTC()
	twin := suRaw(t)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[1], twin, now)))

	const n = 8
	raws := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range raws {
		raws[i] = suRaw(t)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], raws[i], now))
		}(i)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		require.NoErrorf(t, err, "выдача %d под одновременной выдачей отказала", i)
	}
	total, live := sc.rows(t, sc.sessions[0])
	require.Equal(t, 1, live, "живое испытание у сессии одно")
	require.Equal(t, 1, total, "сменённые значения в таблице не лежат ни в каком виде")
	won := 0
	for _, r := range raws {
		ok, err := sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], r, now.Add(time.Second))
		require.NoError(t, err)
		if ok {
			won++
		}
	}
	require.Equal(t, 1, won, "предъявимо ровно одно из выданных")

	_, twinLive := sc.rows(t, sc.sessions[1])
	require.Equal(t, 1, twinLive, "близнец: выдачи другой сессии её испытание не сменяют")
	ok, err := sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[1], twin, now.Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok, "близнец: испытание соседней сессии предъявимо")
}

// TestAccessKeyStepUpRepo_IssueAfterConsumeInsertsANewOne — З1, вторая
// сторона: предъявленное из-под ключа «одно живое» уходит, новая выдача
// вставляет новую строку, а предъявленная остаётся «уже предъявлено».
func TestAccessKeyStepUpRepo_IssueAfterConsumeInsertsANewOne(t *testing.T) {
	sc := newSUScene(t, "suafter", 1)
	ctx := context.Background()
	now := time.Now().UTC()
	first, second := suRaw(t), suRaw(t)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], first, now)))
	ok, err := sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], first, now.Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], second, now.Add(2*time.Second))))
	total, live := sc.rows(t, sc.sessions[0])
	require.Equal(t, 2, total, "предъявленное сохранено до уборки, новое вставлено")
	require.Equal(t, 1, live)
	st, err := sc.repo.StepUpChallengeState(ctx, sc.sessions[0], first, now.Add(3*time.Second))
	require.NoError(t, err)
	require.Equal(t, domain.StepUpChallengePresented, st)
}

// TestAccessKeyStepUpRepo_ConsumeRaceHasOneWinner — однократность: восемь
// одновременных сгораний одной пары — ровно одно; проигравшие читают «уже
// предъявлено», а не «не выдавалось».
func TestAccessKeyStepUpRepo_ConsumeRaceHasOneWinner(t *testing.T) {
	sc := newSUScene(t, "surace", 1)
	ctx := context.Background()
	now := time.Now().UTC()
	raw := suRaw(t)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], raw, now)))

	const n = 8
	won := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			won[i], errs[i] = sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], raw, now.Add(time.Second))
		}(i)
	}
	close(start)
	wg.Wait()
	winners := 0
	for i := range won {
		require.NoError(t, errs[i])
		if won[i] {
			winners++
		}
	}
	require.Equal(t, 1, winners, "сгорание одной пары — ровно одно")
	st, err := sc.repo.StepUpChallengeState(ctx, sc.sessions[0], raw, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, domain.StepUpChallengePresented, st, "проигравший читает «уже предъявлено»")
}

// TestAccessKeyStepUpRepo_StatesAreDistinguishedByThePair — три причины
// несгоревшего испытания по паре: чужая сессия — «не выдавалось», истёкшее —
// «истекло»; близнец — своё живое сгорает.
func TestAccessKeyStepUpRepo_StatesAreDistinguishedByThePair(t *testing.T) {
	sc := newSUScene(t, "sustate", 2)
	ctx := context.Background()
	now := time.Now().UTC()
	raw := suRaw(t)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], raw, now)))

	ok, err := sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[1], raw, now.Add(time.Second))
	require.NoError(t, err)
	require.False(t, ok, "испытание S1 в S2 не сгорает")
	st, err := sc.repo.StepUpChallengeState(ctx, sc.sessions[1], raw, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, domain.StepUpChallengeNotIssued, st)

	late := now.Add(access_keys.ChallengeTTL + time.Second)
	ok, err = sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], raw, late)
	require.NoError(t, err)
	require.False(t, ok, "истёкшее не сгорает")
	st, err = sc.repo.StepUpChallengeState(ctx, sc.sessions[0], raw, late)
	require.NoError(t, err)
	require.Equal(t, domain.StepUpChallengeExpired, st)

	ok, err = sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], raw, now.Add(time.Second))
	require.NoError(t, err)
	require.True(t, ok, "близнец: своё живое сгорает")
}

// TestAccessKeyStepUpRepo_ConsumeEarlierThanIssueIsNotRefusedBySchema — У1:
// выдала одна реплика, предъявила другая, чьи часы отстают на секунду.
// Проверки «предъявлено не раньше выдачи» у схемы нет — предъявление принято.
func TestAccessKeyStepUpRepo_ConsumeEarlierThanIssueIsNotRefusedBySchema(t *testing.T) {
	sc := newSUScene(t, "suskew", 1)
	ctx := context.Background()
	issued := time.Now().UTC()
	raw := suRaw(t)
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], raw, issued)))
	ok, err := sc.repo.ConsumeStepUpChallenge(ctx, sc.sessions[0], raw, issued.Add(-time.Second))
	require.NoError(t, err, "предъявление на реплике с отстающими часами отвергнуто схемой")
	require.True(t, ok)
}

// TestAccessKeyStepUpRepo_SessionRemovalTakesItsChallenges — принадлежность:
// снятая запись сессии уносит свои испытания каскадом; соседняя — нет.
func TestAccessKeyStepUpRepo_SessionRemovalTakesItsChallenges(t *testing.T) {
	sc := newSUScene(t, "sucasc", 2)
	ctx := context.Background()
	now := time.Now().UTC()
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[0], suRaw(t), now)))
	require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(sc.sessions[1], suRaw(t), now)))
	_, err := sc.pool.Exec(ctx, `DELETE FROM kaname.human_sessions WHERE id = $1`, string(sc.sessions[0]))
	require.NoError(t, err)
	gone, _ := sc.rows(t, sc.sessions[0])
	kept, _ := sc.rows(t, sc.sessions[1])
	require.Zero(t, gone, "испытания снятой записи сессии сняты каскадом")
	require.Equal(t, 1, kept, "близнец: испытание соседней записи на месте")
}

// suNoReaper — уборщики соседних предметов: реестр без полного набора записей
// не даёт вовсе, а предмет этой пробы — только испытания повышения.
type suNoReaper struct{ akNoReaper }

func (suNoReaper) SweepUnservableChallenges(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

// TestAccessKeyStepUpRepo_SweepRemovesOnlyUnservable — З2: уборщик и порог —
// ровно из записи реестра. Только что предъявленное и только что истёкшее
// остаются (снятая строка читалась бы «не выдавалось»), давние — снимаются.
func TestAccessKeyStepUpRepo_SweepRemovesOnlyUnservable(t *testing.T) {
	sc := newSUScene(t, "susweep", 4)
	ctx := context.Background()
	now := time.Now().UTC()
	ttl := access_keys.ChallengeTTL
	type row struct {
		name      string
		session   domain.HumanSessionID
		raw       []byte
		issued    time.Time
		consumeAt time.Time
	}
	rows := []row{
		{name: "consumed-now", session: sc.sessions[0], raw: suRaw(t), issued: now.Add(-time.Second), consumeAt: now},
		{name: "expired-now", session: sc.sessions[1], raw: suRaw(t), issued: now.Add(-ttl - time.Second)},
		{name: "consumed-old", session: sc.sessions[2], raw: suRaw(t), issued: now.Add(-3 * ttl), consumeAt: now.Add(-3*ttl + time.Second)},
		{name: "expired-old", session: sc.sessions[3], raw: suRaw(t), issued: now.Add(-4 * ttl)},
	}
	for _, r := range rows {
		require.NoError(t, sc.repo.IssueStepUpChallenge(ctx, suChallenge(r.session, r.raw, r.issued)), r.name)
		if !r.consumeAt.IsZero() {
			ok, err := sc.repo.ConsumeStepUpChallenge(ctx, r.session, r.raw, r.consumeAt)
			require.NoError(t, err)
			require.True(t, ok, "фикстура %s: испытание не предъявлено", r.name)
		}
	}

	var subj retention.Subject
	none := suNoReaper{}
	for _, s := range retention.WithHumanSessions(nil, retention.HumanSessionReapers{
		Sessions: none, Failures: none, Codes: none, Enrollments: none, Challenges: none, ChallengeTTL: ttl,
		LongestWindow: 10 * time.Minute, EnrollmentWindow: 15 * time.Minute,
		VerificationCodes: none, SourceWindows: none, BearerLetters: none,
		LetterWindow: 24 * time.Hour, SourceWindow: 10 * time.Minute,
		StepUpChallenges: sc.repo,
	}) {
		if s.Name == retention.SubjectAccessKeyStepUpChallenges {
			subj = s
		}
	}
	require.NotNil(t, subj.Sweep, "в реестре нет предмета %q", retention.SubjectAccessKeyStepUpChallenges)
	n, _, err := subj.Sweep(ctx, subj.Grace, 100)
	require.NoError(t, err)

	state := func(r row) (domain.StepUpChallengeState, int) {
		st, err := sc.repo.StepUpChallengeState(ctx, r.session, r.raw, now)
		require.NoError(t, err)
		total, _ := sc.rows(t, r.session)
		return st, total
	}
	st, total := state(rows[0])
	require.Equal(t, 1, total, "проход с порогом реестра %v снял только что предъявленное", subj.Grace)
	require.Equal(t, domain.StepUpChallengePresented, st)
	st, total = state(rows[1])
	require.Equal(t, 1, total, "проход с порогом реестра %v снял только что истёкшее", subj.Grace)
	require.Equal(t, domain.StepUpChallengeExpired, st)
	_, total = state(rows[2])
	require.Zero(t, total, "предъявленное за пределом срока обязано сниматься")
	_, total = state(rows[3])
	require.Zero(t, total, "истёкшее за пределом срока обязано сниматься")
	require.Equal(t, int64(2), n, "снято ровно два давних испытания")
}
