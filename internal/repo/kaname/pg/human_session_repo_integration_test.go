// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_repo_integration_test.go — сторона ХРАНИЛИЩА сессии человека
// (фаза Ф3, задача `kacho#1269`; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`).
//
// Пробы уровня I на настоящей базе: запись и её чтение по носителю (Ф3-08,
// Ф3-10, Ф3-11), снятие выходом и идемпотентность (Ф3-15), снятие прочих (Ф3-21),
// перевыпуск носителя (Ф3-19), память первой аутентификации под конкуренцией
// (Ф3-50), операция отсечки с причиной и актором записи, чей момент стоит
// (§4.1 п.17, замок Ф1-63/67 — Ф3-16, Ф3-21), счёт неверных предъявлений
// (Ф3-28…30), одна транзакция с событием аудита (Ф3-47), уборка (Ф3-49).
//
// Часы — пробы (форма Ф-д): каждый момент задаётся явно, а не берётся у стены.
package pg_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

var _ humansession.Store = (*pg.HumanSessionRepo)(nil)

func hsPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// hsBase — момент t₀ пробы с ненулевой микросекундной частью: разрешение
// хранилища — микросекунды, и проба обязана его видеть (Ф3-09, Ф3-16).
var hsBase = time.Date(2026, 9, 16, 12, 0, 0, 123456000, time.UTC)

const hsTTL = 24 * time.Hour

func hsSession(user domain.UserID, tag string, at time.Time) domain.HumanSession {
	return domain.HumanSession{
		ID:               domain.HumanSessionID("hss-" + tag),
		UserID:           user,
		AuthenticatedAt:  at,
		LastPresentedAt:  at,
		ExpiresAt:        at.Add(hsTTL),
		AssuranceLevel:   "1",
		PresentedMethods: []string{"password"},
	}
}

func hsIssue(t *testing.T, repo *pg.HumanSessionRepo, s domain.HumanSession) domain.SessionBearer {
	t.Helper()
	ctx := context.Background()
	bearer, err := domain.NewSessionBearer()
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertSession(ctx, s, bearer.Digest()))
	require.NoError(t, w.RememberFirstAuthentication(ctx, s.UserID, s.AuthenticatedAt))
	require.NoError(t, w.Commit(ctx))
	return bearer
}

func hsResolve(t *testing.T, repo *pg.HumanSessionRepo, b domain.SessionBearer, now time.Time) (humansession.Resolved, humansession.NoSessionReason) {
	t.Helper()
	got, reason, err := repo.Resolve(context.Background(), b.Digest(), now)
	require.NoError(t, err)
	return got, reason
}

// TestHumanSessionRepo_F3_08_TwoIssuesAreTwoRecordsResolvedByTheirOwnBearer —
// два входа одной личности дают две различимые записи (Ф1-13); чужой носитель
// не находит ничего; значение носителя непрозрачно и не короче 22 знаков.
func TestHumanSessionRepo_F3_08_TwoIssuesAreTwoRecordsResolvedByTheirOwnBearer(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	people := lmPeople(t, pool, "hs08", 1)

	b1 := hsIssue(t, repo, hsSession(people[0], "08a", hsBase))
	b2 := hsIssue(t, repo, hsSession(people[0], "08b", hsBase.Add(time.Minute)))
	require.NotEqual(t, b1.CookieValue(), b2.CookieValue(), "Ф3-08: два входа — два значения")
	require.GreaterOrEqual(t, len(b1.CookieValue()), 22, "Ф3-08: не короче 22 знаков URL-safe base64")

	got1, r1 := hsResolve(t, repo, b1, hsBase.Add(time.Hour))
	got2, r2 := hsResolve(t, repo, b2, hsBase.Add(time.Hour))
	require.Equal(t, humansession.SessionFound, r1)
	require.Equal(t, humansession.SessionFound, r2)
	require.Equal(t, domain.HumanSessionID("hss-08a"), got1.Session.ID)
	require.Equal(t, domain.HumanSessionID("hss-08b"), got2.Session.ID)
	require.Equal(t, people[0], got1.User.ID)
	require.True(t, got1.Session.AuthenticatedAt.Equal(hsBase), "момент — микросекундный, как положили")
	require.Equal(t, hsBase.Nanosecond(), got1.Session.AuthenticatedAt.Nanosecond(), "разрешение хранилища не усекает микросекунды")

	stranger, err := domain.NewSessionBearer()
	require.NoError(t, err)
	_, rs := hsResolve(t, repo, stranger, hsBase.Add(time.Hour))
	require.Equal(t, humansession.NoSessionUnknown, rs, "Ф3-10 N1: неизвестное значение — «сессии нет»")
}

// TestHumanSessionRepo_F3_11_ExpiryIsAbsoluteOnTheProbeClock — до срока годна,
// в срок и после — нет; предъявления срок не двигают (Ф1-11, Ф1-12, Ф1-53).
func TestHumanSessionRepo_F3_11_ExpiryIsAbsoluteOnTheProbeClock(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	people := lmPeople(t, pool, "hs11", 1)
	b := hsIssue(t, repo, hsSession(people[0], "11a", hsBase))
	eps := time.Second

	_, r := hsResolve(t, repo, b, hsBase.Add(hsTTL-2*eps))
	require.Equal(t, humansession.SessionFound, r, "Ф1-12: до срока годна")
	_, r = hsResolve(t, repo, b, hsBase.Add(hsTTL-eps))
	require.Equal(t, humansession.SessionFound, r, "обращение срок не сдвигает")
	_, r = hsResolve(t, repo, b, hsBase.Add(hsTTL))
	require.Equal(t, humansession.NoSessionExpired, r, "граница включающая: в сам момент срока сессии нет")
	_, r = hsResolve(t, repo, b, hsBase.Add(hsTTL+eps))
	require.Equal(t, humansession.NoSessionExpired, r, "Ф1-11")
}

// TestHumanSessionRepo_F3_10_BlockedPersonResolvesToNoSession — живая запись
// заблокированной личности — «сессии нет» (N4), причина — только в исходе.
func TestHumanSessionRepo_F3_10_BlockedPersonResolvesToNoSession(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	people := lmPeople(t, pool, "hs10", 1)
	b := hsIssue(t, repo, hsSession(people[0], "10a", hsBase))
	_, err := pool.Exec(context.Background(), `UPDATE users SET invite_status = 'BLOCKED' WHERE id = $1`, string(people[0]))
	require.NoError(t, err)

	got, r := hsResolve(t, repo, b, hsBase.Add(time.Hour))
	require.Equal(t, humansession.NoSessionBlocked, r)
	require.Empty(t, got.Session.ID, "на «сессии нет» состав пуст")

	_, err = pool.Exec(context.Background(), `UPDATE users SET invite_status = 'ACTIVE' WHERE id = $1`, string(people[0]))
	require.NoError(t, err)
	_, r = hsResolve(t, repo, b, hsBase.Add(time.Hour))
	require.Equal(t, humansession.SessionFound, r, "положительный контроль: снятие блокировки возвращает сессию")
}

// TestHumanSessionRepo_F3_15_EndingOneSessionLeavesTheOtherAndIsIdempotent —
// выход гасит СВОЮ запись, вторая жива; второй выход ничего не пишет (Ф1-14,
// Ф1-18, Ф1-57, Ф1-64).
func TestHumanSessionRepo_F3_15_EndingOneSessionLeavesTheOtherAndIsIdempotent(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs15", 1)
	b1 := hsIssue(t, repo, hsSession(people[0], "15a", hsBase))
	b2 := hsIssue(t, repo, hsSession(people[0], "15b", hsBase.Add(time.Minute)))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	ended, err := w.EndSession(ctx, "hss-15a", hsBase.Add(time.Hour), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, ended)
	require.NoError(t, w.Commit(ctx))

	_, r1 := hsResolve(t, repo, b1, hsBase.Add(2*time.Hour))
	require.Equal(t, humansession.NoSessionEnded, r1, "Ф1-14: сохранённая копия после выхода — «сессии нет»")
	_, r2 := hsResolve(t, repo, b2, hsBase.Add(2*time.Hour))
	require.Equal(t, humansession.SessionFound, r2, "Ф1-57: вторая жива")

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	ended, err = w.EndSession(ctx, "hss-15a", hsBase.Add(3*time.Hour), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.False(t, ended, "Ф1-18: второй выход не пишет ничего")
	ended, err = w.EndSession(ctx, "hss-absent", hsBase.Add(3*time.Hour), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.False(t, ended, "Ф3-18: выход без записи — ничего не записано")
	require.NoError(t, w.Commit(ctx))
}

// TestHumanSessionRepo_F3_21_EndOtherSessionsKeepsTheCurrent — три сессии,
// снятие прочих из средней: S1 и S3 сняты, S2 жива (Ф1-15, Ф1-65). Отрицательные
// контроли Ф1-65 названы поимённо: реализация «одна прочая» либо «все позже
// меняющей» краснеет здесь на S1 и на S3 соответственно.
func TestHumanSessionRepo_F3_21_EndOtherSessionsKeepsTheCurrent(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs21", 1)
	b1 := hsIssue(t, repo, hsSession(people[0], "21a", hsBase))
	b2 := hsIssue(t, repo, hsSession(people[0], "21b", hsBase.Add(time.Minute)))
	b3 := hsIssue(t, repo, hsSession(people[0], "21c", hsBase.Add(2*time.Minute)))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	n, err := w.EndOtherSessions(ctx, people[0], "hss-21b", hsBase.Add(time.Hour), domain.RevokeReasonPasswordChange)
	require.NoError(t, err)
	require.Equal(t, 2, n, "снято ровно две прочие")
	require.NoError(t, w.Commit(ctx))

	now := hsBase.Add(2 * time.Hour)
	_, r1 := hsResolve(t, repo, b1, now)
	_, r2 := hsResolve(t, repo, b2, now)
	_, r3 := hsResolve(t, repo, b3, now)
	require.Equal(t, humansession.NoSessionEnded, r1, "Ф1-65: раньше меняющей — снята (контроль «все позже меняющей»)")
	require.Equal(t, humansession.SessionFound, r2, "Ф1-15: текущая жива")
	require.Equal(t, humansession.NoSessionEnded, r3, "Ф1-65: позже меняющей — снята (контроль «одна прочая»)")

	// Положительный контроль на двух сессиях: снятие прочих из одной — одна снята.
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	n, err = w.EndOtherSessions(ctx, people[0], "hss-21b", hsBase.Add(3*time.Hour), domain.RevokeReasonPasswordChange)
	require.NoError(t, err)
	require.Equal(t, 0, n, "снятые повторно не считаются: их уже нет")
	require.NoError(t, w.Commit(ctx))
}

// TestHumanSessionRepo_F3_19_RotateBearerKeepsMomentAndExpiry — перевыпуск:
// прежний носитель даёт «сессии нет», новый — ту же запись с тем же моментом
// аутентификации и сроком; момент последнего предъявления сдвинут (Ф11 Р5, Р6).
func TestHumanSessionRepo_F3_19_RotateBearerKeepsMomentAndExpiry(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs19", 1)
	old := hsIssue(t, repo, hsSession(people[0], "19a", hsBase))
	fresh, err := domain.NewSessionBearer()
	require.NoError(t, err)
	presented := hsBase.Add(30 * time.Minute)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.RotateBearer(ctx, "hss-19a", fresh.Digest(), presented))
	require.NoError(t, w.Commit(ctx))

	_, rOld := hsResolve(t, repo, old, presented.Add(time.Minute))
	require.Equal(t, humansession.NoSessionUnknown, rOld, "прежний носитель после перевыпуска — «сессии нет»")
	got, rNew := hsResolve(t, repo, fresh, presented.Add(time.Minute))
	require.Equal(t, humansession.SessionFound, rNew)
	require.True(t, got.Session.AuthenticatedAt.Equal(hsBase), "Ф1-53: момент аутентификации прежний")
	require.True(t, got.Session.ExpiresAt.Equal(hsBase.Add(hsTTL)), "Ф1-53: срок прежний — считается от выдачи")
	require.True(t, got.Session.LastPresentedAt.Equal(presented), "Ф11 Р6: момент последнего предъявления сдвинут")
}

// TestHumanSessionRepo_F3_50_FirstAuthenticationIsTheMinimumUnderConcurrency —
// две параллельные выдачи t₁ < t₂ при обратном порядке фиксации дают t₁; уборка
// и третья выдача не поднимают (Р5). Отрицательный контроль назван: «первая
// запись побеждает» при обратном порядке даёт t₂ и обязана краснеть.
func TestHumanSessionRepo_F3_50_FirstAuthenticationIsTheMinimumUnderConcurrency(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs50", 1)
	t1 := hsBase
	t2 := hsBase.Add(time.Minute)

	// Обратный порядок фиксации: t₂ фиксируется ПЕРВЫМ, t₁ — вторым, пока
	// первая транзакция уже закрыта. Минимум коммутативен и даёт t₁.
	for _, at := range []time.Time{t2, t1} {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.RememberFirstAuthentication(ctx, people[0], at))
		require.NoError(t, w.Commit(ctx))
	}
	got, found, err := repo.FirstAuthentication(ctx, people[0])
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, got.Equal(t1), "минимум при обратном порядке фиксации: %s, ждали %s", got, t1)

	// Параллельно, настоящей конкуренцией: N писателей с возрастающими моментами
	// на новой личности — стоящей остаётся наименьший.
	people2 := lmPeople(t, pool, "hs5b", 1)
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := writers - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				errs <- err
				return
			}
			if err := w.RememberFirstAuthentication(ctx, people2[0], hsBase.Add(time.Duration(i)*time.Second)); err != nil {
				_ = w.Rollback(ctx)
				errs <- err
				return
			}
			errs <- w.Commit(ctx)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	got, found, err = repo.FirstAuthentication(ctx, people2[0])
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, got.Equal(hsBase), "под конкуренцией стоит минимум")

	// Третья выдача позже — не поднимает.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.RememberFirstAuthentication(ctx, people2[0], hsBase.Add(time.Hour)))
	require.NoError(t, w.Commit(ctx))
	got, _, err = repo.FirstAuthentication(ctx, people2[0])
	require.NoError(t, err)
	require.True(t, got.Equal(hsBase), "единственный писатель — выдача, и он не поднимает")
}

// TestUserTokenRevocations_F3_16_ReasonAndActorFollowTheAcceptedMoment — замок
// Ф1-63/67 (§4.1 п.17): отброшенный момент не переносит на стоящую запись ни
// причины, ни актора; на равных стоит последняя; больший момент ставит своё.
// Отрицательный контроль назван: сегодняшняя операция (`= EXCLUDED.` у обоих)
// краснеет на первом утверждении и молчит на положительном контроле.
func TestUserTokenRevocations_F3_16_ReasonAndActorFollowTheAcceptedMoment(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	revs := pg.NewUserTokenRevocationRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs16", 2)
	subject, admin := people[0], people[1]
	tc := hsBase.Add(time.Hour)

	upsert := func(at time.Time, reason string, actor domain.UserID) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{UserID: subject, RevokeBefore: at, Reason: reason}, actor))
		require.NoError(t, w.Commit(ctx))
	}
	read := func() (time.Time, string, string) {
		var at time.Time
		var reason string
		var actor *string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT revoke_before, reason, revoked_by_user_id FROM user_token_revocations WHERE user_id = $1`,
			string(subject)).Scan(&at, &reason, &actor))
		a := ""
		if actor != nil {
			a = *actor
		}
		return at, reason, a
	}

	// Стоящая запись — принудительный выход администратора в t꜀.
	upsert(tc, "admin-force-logout", admin)
	// Наш выход датирует отсечку t₁ − 1 µs — НИЖЕ стоящей: момент отброшен,
	// причина и актор ОБЯЗАНЫ остаться прежними (Ф1-63).
	upsert(hsBase.Add(-time.Microsecond), domain.RevokeReasonLogout, subject)
	at, reason, actor := read()
	require.True(t, at.Equal(tc), "момент стоящей записи прежний")
	require.Equal(t, "admin-force-logout", reason, "Ф1-63: отброшенный момент не переносит причины")
	require.Equal(t, string(admin), actor, "Ф1-63: отброшенный момент не переносит актора")

	// Равный момент — стоит последняя (Ф1 §4.2 «запись монотонна»).
	upsert(tc, domain.RevokeReasonPasswordChange, subject)
	at, reason, actor = read()
	require.True(t, at.Equal(tc))
	require.Equal(t, domain.RevokeReasonPasswordChange, reason, "на равных стоит последняя")
	require.Equal(t, string(subject), actor)

	// Положительный контроль: больший момент ставит своё — принудительный выход
	// ПОСЛЕ нашего выхода.
	upsert(tc.Add(time.Minute), "admin-force-logout", admin)
	at, reason, actor = read()
	require.True(t, at.Equal(tc.Add(time.Minute)))
	require.Equal(t, "admin-force-logout", reason)
	require.Equal(t, string(admin), actor)

	// Тот же оператор у существующего писателя `now` — семантика одна на дерево.
	require.NoError(t, revs.UpsertRevokeAll(ctx, domain.UserTokenRevocation{UserID: subject, RevokeBefore: tc, Reason: "older"}, subject))
	_, reason, _ = read()
	require.Equal(t, "admin-force-logout", reason, "существующий писатель зовёт ту же операцию: ниже стоящего — не переписывает")
}

// TestHumanSessionRepo_F3_28_FailureCountIsPerScopeAndWindow — счёт по адресу и
// по источнику ведётся раздельно и в окне; сброс снимает счёт одной оси.
func TestHumanSessionRepo_F3_28_FailureCountIsPerScopeAndWindow(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "a@example.invalid", hsBase.Add(time.Duration(i)*time.Second)))
		require.NoError(t, w.RecordFailure(ctx, humansession.FailureBySource, "203.0.113.7", hsBase.Add(time.Duration(i)*time.Second)))
	}
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "a@example.invalid", hsBase.Add(-time.Hour)))
	require.NoError(t, w.Commit(ctx))

	n, err := repo.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", hsBase.Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, 3, n, "в окне — три; старая вне окна не считается")
	n, err = repo.CountFailures(ctx, humansession.FailureBySource, "203.0.113.7", hsBase.Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	n, err = repo.CountFailures(ctx, humansession.FailureByAddress, "b@example.invalid", hsBase.Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, 0, n, "другой ключ не задет")

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.ResetFailures(ctx, humansession.FailureByAddress, "a@example.invalid"))
	require.NoError(t, w.Commit(ctx))
	n, err = repo.CountFailures(ctx, humansession.FailureByAddress, "a@example.invalid", hsBase.Add(-time.Hour*2))
	require.NoError(t, err)
	require.Equal(t, 0, n, "успешный вход обнуляет счёт по адресу")
	n, err = repo.CountFailures(ctx, humansession.FailureBySource, "203.0.113.7", hsBase.Add(-time.Minute))
	require.NoError(t, err)
	require.Equal(t, 3, n, "счёт по источнику сбросом адреса не задет")
}

// TestHumanSessionRepo_F3_47_AuditRowAndSessionShareOneTransaction — подставной
// отказ (откат) после записи сессии и события не оставляет ни того, ни другого.
func TestHumanSessionRepo_F3_47_AuditRowAndSessionShareOneTransaction(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs47", 1)
	bearer, err := domain.NewSessionBearer()
	require.NoError(t, err)

	var before int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox`).Scan(&before))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertSession(ctx, hsSession(people[0], "47a", hsBase), bearer.Digest()))
	require.NoError(t, w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType: "iam.session.issued", TenantAccountID: "",
		Payload: map[string]any{"user_id": string(people[0]), "session_id": "hss-47a", "method": "password"},
	}))
	require.NoError(t, w.Rollback(ctx))

	_, r := hsResolve(t, repo, bearer, hsBase.Add(time.Minute))
	require.Equal(t, humansession.NoSessionUnknown, r, "откат не оставил записи")
	var after int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox`).Scan(&after))
	require.Equal(t, before, after, "откат не оставил события")

	// Положительный контроль — фиксация оставляет оба.
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.InsertSession(ctx, hsSession(people[0], "47a", hsBase), bearer.Digest()))
	require.NoError(t, w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType: "iam.session.issued",
		Payload:   map[string]any{"user_id": string(people[0]), "session_id": "hss-47a", "method": "password"},
	}))
	require.NoError(t, w.Commit(ctx))
	_, r = hsResolve(t, repo, bearer, hsBase.Add(time.Minute))
	require.Equal(t, humansession.SessionFound, r)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox`).Scan(&after))
	require.Equal(t, before+1, after)
}

// TestHumanSessionRepo_F3_49_SweepRemovesUnservableRowsOnly — уборка снимает
// истёкшие и снятые записи и не трогает живые; память первой аутентификации
// уборке не подлежит. Здесь порог — на управляемых часах уборщика.
func TestHumanSessionRepo_F3_49_SweepRemovesUnservableRowsOnly(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs49", 1)
	now := time.Now().UTC()
	expired := hsIssue(t, repo, hsSession(people[0], "49x", now.Add(-hsTTL-time.Hour)))
	live := hsIssue(t, repo, hsSession(people[0], "49l", now.Add(-time.Hour)))
	ended := hsIssue(t, repo, hsSession(people[0], "49e", now.Add(-2*time.Hour)))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.EndSession(ctx, "hss-49e", now.Add(-time.Hour), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	removed, full, err := repo.SweepUnservableSessions(ctx, 0, 100)
	require.NoError(t, err)
	require.False(t, full)
	require.EqualValues(t, 2, removed, "перепись: осмотрено 3 · снято 2")

	_, r := hsResolve(t, repo, live, now)
	require.Equal(t, humansession.SessionFound, r, "живая не тронута")
	_, r = hsResolve(t, repo, expired, now)
	require.Equal(t, humansession.NoSessionUnknown, r, "истёкшая снята")
	_, r = hsResolve(t, repo, ended, now)
	require.Equal(t, humansession.NoSessionUnknown, r, "снятая убрана")

	_, found, err := repo.FirstAuthentication(ctx, people[0])
	require.NoError(t, err)
	require.True(t, found, "Р5: память первой аутентификации уборке не подлежит")

	// Следы неверных предъявлений старше окна тоже убираются.
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "x@example.invalid", now.Add(-3*time.Hour)))
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "x@example.invalid", now))
	require.NoError(t, w.Commit(ctx))
	removed, _, err = repo.SweepAgedFailures(ctx, time.Hour, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed)
	n, err := repo.CountFailures(ctx, humansession.FailureByAddress, "x@example.invalid", now.Add(-24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, n, "свежий след остался")
}

// TestHumanSessionRepo_F3_19_ReplaceLoginVerifierIsOneStatement — замещение
// материала одним оператором (ID-PW-1 PWV-10): два одновременных замещения
// одним значением — запись ровно одна; у человека без способа — replaced=false.
func TestHumanSessionRepo_F3_19_ReplaceLoginVerifierIsOneStatement(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	methods := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs1r", 2)
	_, err := methods.Create(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, "$2a$12$old.material.old.material.old.material.old.material.oldmat")})
	require.NoError(t, err)

	fresh := lmVerifier(t, "$argon2id$v=19$m=65536,t=3,p=4$cHJvYmUtc2FsdC1mMw$cHJvYmUtaGFzaC1mMy1yZXBsYWNl")
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			require.NoError(t, err)
			replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: fresh})
			require.NoError(t, err)
			require.NoError(t, w.Commit(ctx))
			results <- replaced
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		require.True(t, r, "оба замещения проходят")
	}
	require.Equal(t, 1, lmCount(t, pool, people[0]), "запись ровно одна")
	got, err := methods.Get(ctx, people[0], domain.LoginMethodPassword)
	require.NoError(t, err)
	require.Equal(t, fresh.Reveal(), got.Verifier.Reveal())

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: people[1], Kind: domain.LoginMethodPassword, Verifier: fresh})
	require.NoError(t, err)
	require.False(t, replaced, "у человека без способа замещать нечего")
	require.NoError(t, w.Rollback(ctx))
	t.Logf("перепись: %s", fmt.Sprintf("замещений 2 параллельно · строк 1"))
}

// TestHumanSessionRepo_F3_28_OldestFailureInWindowNamesTheRetryAfter — самый
// ранний след в окне — тот, по которому считается конец окна; вне окна и без
// следов — «нет ни одного», а не ошибка.
func TestHumanSessionRepo_F3_28_OldestFailureInWindowNamesTheRetryAfter(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	_, found, err := repo.OldestFailureSince(ctx, humansession.FailureByAddress, "o@example.invalid", hsBase)
	require.NoError(t, err)
	require.False(t, found)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "o@example.invalid", hsBase.Add(-time.Hour)))
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "o@example.invalid", hsBase.Add(time.Second)))
	require.NoError(t, w.RecordFailure(ctx, humansession.FailureByAddress, "o@example.invalid", hsBase.Add(5*time.Second)))
	require.NoError(t, w.Commit(ctx))

	at, found, err := repo.OldestFailureSince(ctx, humansession.FailureByAddress, "o@example.invalid", hsBase)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, at.Equal(hsBase.Add(time.Second)), "самый ранний В ОКНЕ, а не вообще: %s", at)
}

// TestHumanSessionRepo_F3_23_ClearPasswordChangeRequired — требование снимается
// с записи и видно резолву (Ф5-24).
func TestHumanSessionRepo_F3_23_ClearPasswordChangeRequired(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "hs23", 1)
	s := hsSession(people[0], "23a", hsBase)
	s.PasswordChangeRequired = true
	s.PresentedMethods = []string{"recovery_code"}
	b := hsIssue(t, repo, s)
	got, r := hsResolve(t, repo, b, hsBase.Add(time.Minute))
	require.Equal(t, humansession.SessionFound, r)
	require.True(t, got.Session.PasswordChangeRequired)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.ClearPasswordChangeRequired(ctx, "hss-23a"))
	require.NoError(t, w.Commit(ctx))
	got, _ = hsResolve(t, repo, b, hsBase.Add(time.Minute))
	require.False(t, got.Session.PasswordChangeRequired, "Ф5-24: поле снято")
}
