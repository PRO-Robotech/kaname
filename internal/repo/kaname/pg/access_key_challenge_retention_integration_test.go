// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_challenge_retention_integration_test.go — порог уборки испытаний
// ключей доступа, взятый ИЗ РЕЕСТРА, против настоящего Postgres (kaname#590).
//
// Три состояния испытания (просрочено · не выдавалось · уже предъявлено)
// вызывающему различимы (Ф7-34), повтор результата церемонии отвергается как
// однократное испытание (Ф7-03). Различимость держит только хранение строки:
// снятая строка читается как «не выдавалось». Проба поэтому берёт уборщика и
// порог ровно из записи реестра, которую исполняет проход, а не выписывает
// порог сама — иначе она судила бы свою величину, а не продукта.
package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// akNoReaper — уборщики соседних предметов полосы входа: реестр без полного
// набора записей не даёт вовсе, а предмет этой пробы — только испытания.
type akNoReaper struct{}

func (akNoReaper) SweepUnservableSessions(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepAgedFailures(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepUnservableRecoveryCodes(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepExpiredEnrollments(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepUnservableVerificationCodes(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepAgedSourceWindows(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

func (akNoReaper) SweepExpiredBearerLetters(context.Context, time.Duration, int) (int64, bool, error) {
	return 0, false, nil
}

// akChallengeSubject — запись реестра об испытаниях с настоящим уборщиком.
func akChallengeSubject(t *testing.T, repo *pg.AccessKeyRepo) retention.Subject {
	t.Helper()
	none := akNoReaper{}
	for _, s := range retention.WithHumanSessions(nil, retention.HumanSessionReapers{
		Sessions: none, Failures: none, Codes: none, Enrollments: none, Challenges: repo, ChallengeTTL: access_keys.ChallengeTTL,
		LongestWindow: 10 * time.Minute, EnrollmentWindow: 15 * time.Minute,
		VerificationCodes: none, SourceWindows: none, BearerLetters: none,
		LetterWindow: 24 * time.Hour, SourceWindow: 10 * time.Minute,
	}) {
		if s.Name == retention.SubjectAccessKeyChallenges {
			return s
		}
	}
	t.Fatalf("в реестре полосы входа нет предмета %q", retention.SubjectAccessKeyChallenges)
	return retention.Subject{}
}

// TestAccessKeyChallengeSweep_RegistryGraceKeepsTheStatesDistinguishable —
// проход уборки с порогом реестра не снимает только что предъявленное и только
// что истёкшее испытание: повтор результата церемонии сразу после приёма
// читается как «уже предъявлено» (Ф7-03), а не «не выдавалось». Близнец того
// же прохода — строки старше срока испытания за пределом снимаются: порог не
// превратил уборку в «не убирать ничего».
func TestAccessKeyChallengeSweep_RegistryGraceKeepsTheStatesDistinguishable(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyRepo(pool)
	user := lmPeople(t, pool, "akret", 1)[0]
	ctx := context.Background()
	now := time.Now().UTC()
	ttl := access_keys.ChallengeTTL

	type row struct {
		name      string
		ch        domain.AccessKeyChallenge
		consumeAt time.Time
	}
	mk := func(name string, issued time.Time) domain.AccessKeyChallenge {
		return domain.AccessKeyChallenge{Challenge: []byte(fmt.Sprintf("%-32s", name)), UserID: user,
			Purpose: domain.ChallengeForRegistration, IssuedAt: issued, ExpiresAt: issued.Add(ttl)}
	}
	rows := []row{
		// Предъявлено только что — ровно ak01-finish перед ak03-replay.
		{name: "consumed-now", ch: mk("consumed-now", now.Add(-time.Second)), consumeAt: now},
		// Истекло секунду назад — Ф7-34 обязан назвать «просрочено».
		{name: "expired-now", ch: mk("expired-now", now.Add(-ttl-time.Second))},
		// Близнецы: предъявлено и истекло давно — за пределом срока.
		{name: "consumed-old", ch: mk("consumed-old", now.Add(-3*ttl)), consumeAt: now.Add(-3*ttl + time.Second)},
		{name: "expired-old", ch: mk("expired-old", now.Add(-4*ttl))},
	}
	for _, r := range rows {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.InsertChallenge(ctx, r.ch))
		if !r.consumeAt.IsZero() {
			ok, err := w.ConsumeChallenge(ctx, r.ch.Challenge, user, domain.ChallengeForRegistration, r.consumeAt)
			require.NoError(t, err)
			require.True(t, ok, "фикстура %s: испытание не потреблено", r.name)
		}
		require.NoError(t, w.Commit(ctx))
	}

	subj := akChallengeSubject(t, repo)
	n, _, err := subj.Sweep(ctx, subj.Grace, 100)
	require.NoError(t, err)

	state := func(name string) (domain.AccessKeyChallengeState, bool) {
		c, found, err := repo.Challenge(ctx, []byte(fmt.Sprintf("%-32s", name)), user, domain.ChallengeForRegistration)
		require.NoError(t, err)
		return c.StateAt(now), found
	}
	st, found := state("consumed-now")
	require.True(t, found, "проход с порогом реестра %v снял только что предъявленное испытание: повтор получит «не выдавалось» вместо «уже предъявлено» (Ф7-03, Ф7-34)", subj.Grace)
	require.Equal(t, domain.ChallengeConsumed, st)
	st, found = state("expired-now")
	require.True(t, found, "проход с порогом реестра %v снял только что истёкшее испытание: «просрочено» стало «не выдавалось» (Ф7-34)", subj.Grace)
	require.Equal(t, domain.ChallengeExpired, st)
	_, found = state("consumed-old")
	require.False(t, found, "предъявленное за пределом срока обязано сниматься")
	_, found = state("expired-old")
	require.False(t, found, "истёкшее за пределом срока обязано сниматься")
	require.Equal(t, int64(2), n, "снято ровно два давних испытания")
}
