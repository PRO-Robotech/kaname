// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_set_writers_person_first_integration_test.go — ПИСАТЕЛИ НЕСКОЛЬКИХ
// СЕССИЙ ОДНОГО ЧЕЛОВЕКА БЕРУТ СТРОКУ ЛИЧНОСТИ РАНЬШЕ ЛЮБОЙ ДРУГОЙ (задача
// kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Писатели, снимающие несколько записей сессии одного человека, — вызывающие
// двери `EndOtherSessions`: принудительный выход, смена пароля, снятие второго
// фактора, завершение восстановления (перепись с предикатом — у
// `lockPersonForSessionSetSQL`; уборка, в эту сериализацию не входящая, судится
// своей сценой в `repo/kaname/pg`). Двое из них снимают прочие записи и затем
// пишут в свою — строки сессии берутся «прочие → своя», а принудительный выход
// берёт все одним оператором в порядке просмотра. Порядки встречные, и
// соседняя сцена смены пароля (`force_logout_concurrent_teardown_integration_test.go`)
// ловит это взаимной блокировкой. Здесь — две сцены того же класса, которых там нет:
//
//   - снятие второго фактора первым против принудительного выхода — вторая
//     форма «прочие → своя» (`EndOtherSessions` → `PresentInSession`);
//   - смена пароля настоящим вариантом использования против удаления личности.
//     Смена берёт строку способа входа РАНЬШЕ строк сессии, а удаление берёт
//     личность и каскадом — строку способа входа. Если строка личности у смены
//     не первая, порядки встречные и здесь.
//
// Утверждается одно и то же: ни одна транзакция не проигрывает взаимной
// блокировкой (`pg_stat_database.deadlocks` +0), каждая фиксируется, конечное
// состояние связно.
//
// Сцены строятся тем же набором, что соседние: одноразовая задержка
// триггером, запуск второго участника, когда первый виден спящим, и сцена
// считается построенной, только когда держатель видел второго ждущим ЗАМКА
// (`requireHoldSceneBuilt`).

import (
	"context"
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// secondFactorRemovalSessionWrites — операторы снятия второго фактора над
// записями сессии, в ТОМ порядке, в каком их исполняет
// `RemoveSecondFactorUseCase.Execute` (`humansession/sf_remove.go`): снятие
// прочих записей → предъявление в своей записи (новый носитель, множество,
// уровень) → фиксация, одной транзакцией писателя сессии. Сверка кода, снятие
// строки фактора, сброс счёта и записи событий опущены: они не берут ни одной
// строки, которую берёт принудительный выход.
func secondFactorRemovalSessionWrites(ctx context.Context, repo *kanamepg.HumanSessionRepo, uid domain.UserID,
	keep domain.HumanSessionID, rotated domain.BearerDigest,
) (int, error) {
	w, err := repo.Writer(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = w.Rollback(ctx) }()
	now := time.Now().UTC()
	n, err := w.EndOtherSessions(ctx, uid, keep, now, domain.RevokeReasonSecondFactorRemoved)
	if err != nil {
		return 0, err
	}
	if err := w.PresentInSession(ctx, keep, []string{"password", "lookup_secret"}, "2", rotated, now); err != nil {
		return 0, err
	}
	if err := w.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

// TestIntegration_SecondFactorRemovalThenForceLogoutEndsEachSessionOnce —
// снятие второго фактора начало первым и держит прочие записи, ещё не
// предъявив в своей; принудительный выход пришёл в это окно.
func TestIntegration_SecondFactorRemovalThenForceLogoutEndsEachSessionOnce(t *testing.T) {
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
	)
	var denominator, sumEnded, lockWaiters, removalFailures, logoutFailures int
	for round := 0; round < rounds; round++ {
		uid := seedForceLogoutUser(t, ctx, s.pool)
		ids := seedLiveSessions(t, ctx, s, uid, sessionsPerPerson)
		keep := ids[0]
		rotated := domain.BearerDigest(freshBearerDigest(t))
		live := liveSessionCount(t, ctx, s.pool, uid)
		require.Equal(t, sessionsPerPerson, live, "прогон %d: знаменатель сцены", round)
		denominator += live

		type sfOutcome struct {
			ended int
			err   error
		}
		sfDone := make(chan sfOutcome, 1)
		flDone := make(chan error, 1)
		armOneShotHold(t, ctx, s.pool, concurrentTeardownHold, 1)
		go func() {
			n, err := secondFactorRemovalSessionWrites(ctx, s.sessions, uid, keep, rotated)
			sfDone <- sfOutcome{n, err}
		}()
		awaitSleepingBackend(t, ctx, s.pool)
		go func() { flDone <- s.forceLogout(uid) }()
		sf := <-sfDone
		flErr := <-flDone
		disarmOneShotHold(t, ctx, s.pool, concurrentTeardownHold)
		lockWaiters += requireHoldSceneBuilt(t, ctx, s.pool, concurrentTeardownHold)

		records := forceLogoutRecords(t, ctx, s.pool, uid)
		flEnded, flFailed := endedSessionsOfRecords(t, records)
		committed := flEnded
		if sf.err == nil {
			committed += sf.ended
		} else {
			removalFailures++
		}
		if flErr != nil {
			logoutFailures++
		}
		sumEnded += committed
		after := liveSessionCount(t, ctx, s.pool, uid)
		t.Logf("прогон %d: живых до %d · выход: ошибка=%v снято=%d «не снято»=%d · "+
			"снятие фактора: ошибка=%v снято=%d · Σ зафиксированных %d · живых после %d",
			round, live, flErr, flEnded, flFailed, sf.err, sf.ended, committed, after)

		assert.NoError(t, flErr, "прогон %d: принудительный выход", round)
		assert.NoError(t, sf.err, "прогон %d: снятие второго фактора, начавшее первым", round)
		assert.Equal(t, live, committed,
			"прогон %d: Σ снятых зафиксированными транзакциями обязана равняться числу живых "+
				"записей до сцены", round)
		assert.Zero(t, after, "прогон %d: живые записи после сцены", round)
	}

	aborted := s.refusals.aborted()
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, s.dsn, s.pool)
	t.Logf("прогонов %d · знаменатель %d · Σ снятых зафиксированными %d · ждавших замка %d · "+
		"отказов выхода %d · отказов снятия фактора %d · ABORTED выхода %d · pg_stat_database.deadlocks +%d",
		rounds, denominator, sumEnded, lockWaiters, logoutFailures, removalFailures,
		aborted, deadlocksAfter-deadlocksBefore)

	require.Positive(t, denominator, "знаменатель пуст — сумма ниже равнялась бы нулю на пустом месте")
	assert.Equal(t, denominator, sumEnded, "Σ снятых зафиксированными транзакциями по всем прогонам")
	assert.Zero(t, aborted, "ABORTED (40P01) выхода против снятия второго фактора")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
	assert.Zero(t, logoutFailures, "отказы принудительного выхода")
	assert.Zero(t, removalFailures, "отказы снятия второго фактора")
}

// ─────────────────────────────────────────────────────────────────────────────
// Смена пароля настоящим вариантом использования против удаления личности.

const (
	passwordScenePassword    = "the-current-passphrase-340"
	passwordSceneNewPassword = "the-replacing-passphrase-340"
	verifierReplacedHold     = "probe_verifier_replaced_hold"
)

// quietVerifyObserver — приёмник исходов проверяющего пароля; исходы сцены
// судятся по ответу и базе, а не по счёту.
type quietVerifyObserver struct{}

func (quietVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

// newChangePasswordOver — смена пароля над настоящими адаптерами, собранная
// теми же конструкторами, что в корне полосы входа (`cmd/kaname/loginlane.go`).
func newChangePasswordOver(t *testing.T, s *concurrencyScene) (*humansession.ChangePasswordUseCase, *passwordverify.Hasher) {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4,
		},
	})
	require.NoError(t, err)
	verifier, err := passwordverify.New(4, quietVerifyObserver{})
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy-of-the-probe")
	require.NoError(t, err)
	require.NoError(t, verifier.SetDecoy(decoy))
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, logger)
	require.NoError(t, err)
	change, err := humansession.NewChangePasswordUseCase(humansession.ChangePasswordDeps{
		Store: s.sessions, Methods: kanamepg.NewLoginMethodRepo(s.pool), Verifier: verifier, Hasher: hasher, Rule: rule,
		Limits: humansession.Limits{
			AddressAttempts: 5, AddressWindow: 10 * time.Minute, SourceAttempts: 50, SourceWindow: 10 * time.Minute,
		},
		Now: time.Now, Logger: logger,
	})
	require.NoError(t, err)
	return change, hasher
}

// seedPasswordPerson — участник аккаунта (не владелец: владельца удаление не
// берёт вовсе) со способом входа паролем и n живыми записями сессии. Отвечает
// носителем первой записи — той, из которой идёт смена.
func seedPasswordPerson(t *testing.T, ctx context.Context, s *concurrencyScene, hasher *passwordverify.Hasher,
	owner domain.UserID, n int,
) (domain.UserID, domain.SessionBearer) {
	t.Helper()
	uid := seedAccountMember(t, ctx, s.pool, owner)
	v, err := hasher.Hash(passwordScenePassword)
	require.NoError(t, err)
	_, err = s.pool.Exec(ctx,
		`INSERT INTO kaname.user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', $2)`,
		string(uid), v.Reveal())
	require.NoError(t, err, "способ входа паролем")
	bearer, err := domain.NewSessionBearer()
	require.NoError(t, err)
	seedOwnLoginSession(t, ctx, s.pool, uid, string(bearer.Digest()))
	requireLiveBefore(t, ctx, s.sessions, string(bearer.Digest()))
	seedLiveSessions(t, ctx, s, uid, n-1)
	return uid, bearer
}

// deletePerson — удаление личности тем писателем, которым его исполняет
// полоса удаления (`UsersW().Delete`).
func deletePerson(ctx context.Context, users *kanamepg.Repository, uid domain.UserID) error {
	w, err := users.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.UsersW().Delete(ctx, uid); err != nil {
		return err
	}
	return w.Commit(ctx)
}

func personExists(t *testing.T, ctx context.Context, s *concurrencyScene, uid domain.UserID) bool {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(ctx, `SELECT count(*) FROM kaname.users WHERE id = $1`, string(uid)).Scan(&n))
	return n == 1
}

// TestIntegration_PasswordChangeAndIdentityDeletionDoNotDeadlock — смена пароля
// начала первой и держит строку способа входа; удаление личности пришло в это
// окно. Обе транзакции обязаны зафиксироваться, личности после сцены нет.
//
// Законный близнец — первый шаг пробы: та же личность с тем же посевом
// удаляется без конкурента и фиксируется. Без него отказ удаления в сцене мог
// бы прийти от посева, а не от порядка замков.
func TestIntegration_PasswordChangeAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	s := newConcurrencyScene(t)
	change, hasher := newChangePasswordOver(t, s)
	users := kanamepg.New(s.pool, nil)
	owner := seedForceLogoutUser(t, ctx, s.pool)

	lone, _ := seedPasswordPerson(t, ctx, s, hasher, owner, 3)
	require.NoError(t, deletePerson(ctx, users, lone), "фикстура: удаление без конкурента обязано фиксироваться")
	require.False(t, personExists(t, ctx, s, lone), "фикстура: личность удалена")

	installOneShotHold(t, ctx, s.pool, verifierReplacedHold, "user_login_methods", "UPDATE")
	deadlocksBefore := databaseDeadlocks(t, ctx, s.pool)

	const (
		rounds            = 3
		sessionsPerPerson = 3
	)
	var lockWaiters, changeFailures, deletionFailures, deletionAborted, survivors int
	for round := 0; round < rounds; round++ {
		uid, bearer := seedPasswordPerson(t, ctx, s, hasher, owner, sessionsPerPerson)

		changeDone := make(chan error, 1)
		deleteDone := make(chan error, 1)
		armOneShotHold(t, ctx, s.pool, verifierReplacedHold, 1)
		go func() {
			_, err := change.Execute(ctx, humansession.ChangePasswordInput{
				Bearer: bearer, CurrentPassword: passwordScenePassword,
				NewPassword: passwordSceneNewPassword, Source: "203.0.113.7",
			})
			changeDone <- err
		}()
		awaitSleepingBackend(t, ctx, s.pool)
		go func() { deleteDone <- deletePerson(ctx, users, uid) }()
		changeErr := <-changeDone
		deleteErr := <-deleteDone
		disarmOneShotHold(t, ctx, s.pool, verifierReplacedHold)
		lockWaiters += requireHoldSceneBuilt(t, ctx, s.pool, verifierReplacedHold)

		if changeErr != nil {
			changeFailures++
		}
		if deleteErr != nil {
			deletionFailures++
			if stderrors.Is(deleteErr, iamerr.ErrAborted) {
				deletionAborted++
			}
		}
		exists := personExists(t, ctx, s, uid)
		if exists {
			survivors++
		}
		t.Logf("прогон %d: смена пароля: ошибка=%v · удаление: ошибка=%v · личность после: %v",
			round, changeErr, deleteErr, exists)
	}

	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, s.dsn, s.pool)
	t.Logf("прогонов %d · ждавших замка %d · отказов смены пароля %d · отказов удаления %d (ABORTED %d) · "+
		"личностей, переживших удаление, %d · pg_stat_database.deadlocks +%d",
		rounds, lockWaiters, changeFailures, deletionFailures, deletionAborted, survivors,
		deadlocksAfter-deadlocksBefore)

	assert.Zero(t, deadlocksAfter-deadlocksBefore,
		"pg_stat_database.deadlocks: смена пароля держит строку способа входа и ждёт личность, "+
			"удаление держит личность и ждёт строку способа входа")
	assert.Zero(t, changeFailures, "отказы смены пароля, начавшей первой")
	assert.Zero(t, deletionFailures, "отказы удаления личности")
	assert.Zero(t, survivors, "личности, пережившие удаление")
}
