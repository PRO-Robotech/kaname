// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_identity_deletion_final_state_integration_test.go — ПРИНУДИТЕЛЬНЫЙ
// ВЫХОД ПРОТИВ УДАЛЕНИЯ ЛИЧНОСТИ ОСТАВЛЯЕТ СВЯЗНОЕ КОНЕЧНОЕ СОСТОЯНИЕ (задача
// kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — КОНЕЧНОЕ СОСТОЯНИЕ, А НЕ ОТСУТСТВИЕ ОТКАЗА
//
// Соседняя проба (`force_logout_identity_deletion_race_integration_test.go`)
// утверждает, что выход, начавший первым, и удаление не блокируют друг друга.
// Эта утверждает, ЧТО ОСТАЁТСЯ в базе, в обоих порядках и в двух сценах —
// строки отсечки у личности нет и строка есть:
//
//   - личности нет, её записей сессии нет, её отсечки нет — в любом порядке;
//   - выход либо зафиксирован ЦЕЛИКОМ (одна запись «снято» с числом, равным
//     числу живых записей до сцены; операция завершена без ошибки), либо не
//     зафиксировал НИЧЕГО (записей события нет; операция завершена ошибкой, и
//     ответ тот же, что у выхода над личностью, которой нет вовсе);
//   - взаимных блокировок ноль, и ответ ни одного участника — не INTERNAL.
//
// Ответ «выход над отсутствующей личностью» не выписан литералом: его
// производит сам продукт, последовательным вызовом до сцен, и это же — законный
// близнец, отличающийся от сцены ровно тем, что удаление не конкурирует.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ЗАДАН ПОРЯДОК — ЗАМКОМ
//
// Первый участник задерживается одноразовым триггером уровня оператора,
// держа свои замки: выход — после снятия записей сессии, удаление — после
// удаления строки личности и её каскада. Второй запускается, когда первый
// виден спящим, и сцена построена, только когда второй виден ждущим замка.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const (
	deletionRaceLogoutHold   = "probe_deletion_race_logout_hold"
	deletionRaceDeletionHold = "probe_deletion_race_deletion_hold"
)

// identityRemnants — что осталось в базе о личности после сцены.
type identityRemnants struct {
	user, sessions, userCutoffs, mintedCutoffs int
}

func remnantsOf(t *testing.T, ctx context.Context, s *concurrencyScene, uid domain.UserID) identityRemnants {
	t.Helper()
	var r identityRemnants
	require.NoError(t, s.pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kaname.users WHERE id = $1),
		       (SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1),
		       (SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1),
		       (SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1)`,
		string(uid)).Scan(&r.user, &r.sessions, &r.userCutoffs, &r.mintedCutoffs))
	return r
}

// forceLogoutOperationOf — терминальность и код ошибки операции выхода над
// личностью. Код у успешной операции не записан (NULL) и читается нулём — `OK`.
func forceLogoutOperationOf(t *testing.T, ctx context.Context, s *concurrencyScene, uid domain.UserID) (done bool, code int) {
	t.Helper()
	require.NoError(t, s.pool.QueryRow(ctx, `
		SELECT done, COALESCE(error_code, 0) FROM kaname.operations
		 WHERE description = 'Force logout user ' || $1`, string(uid)).Scan(&done, &code))
	return done, code
}

// seedPriorCutoff — строка отсечки ДО сцены, той же дверью, какой её кладёт
// собственный выход человека (писатель сессии, `UpsertCutoff`). Момент — час
// назад: живые записи сессии моложе и резолвятся дальше.
func seedPriorCutoff(t *testing.T, ctx context.Context, s *concurrencyScene, uid domain.UserID) {
	t.Helper()
	w, err := s.sessions.Writer(ctx)
	require.NoError(t, err, "транзакция посева отсечки")
	defer func() { _ = w.Rollback(ctx) }()
	require.NoError(t, w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: uid, RevokeBefore: time.Now().UTC().Add(-time.Hour), Reason: domain.RevokeReasonLogout,
	}, uid), "посев отсечки")
	require.NoError(t, w.Commit(ctx), "фиксация посева отсечки")
}

func deleteIdentity(ctx context.Context, users *kanamepg.Repository, uid domain.UserID) error {
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

// absentIdentityAnswer — ответ выхода над личностью, которой нет вовсе:
// последовательный вызов, без конкуренции. Это законный близнец позднего
// выхода в сцене «удаление первым».
func absentIdentityAnswer(t *testing.T, s *concurrencyScene) codes.Code {
	t.Helper()
	err := s.forceLogout(domain.UserID(ids.NewID(domain.PrefixUser)))
	require.Error(t, err, "выход над отсутствующей личностью обязан отказать")
	code := status.Code(err)
	require.NotContains(t, []codes.Code{codes.Internal, codes.Unknown, codes.OK}, code,
		"выход над отсутствующей личностью отвечает %s %q — это не ответ «личности нет»",
		code, status.Convert(err).Message())
	return code
}

func TestIntegration_ForceLogoutThenIdentityDeletionLeavesACoherentEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	forceLogoutAgainstIdentityDeletion(t, false)
}

func TestIntegration_IdentityDeletionThenForceLogoutLeavesACoherentEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	forceLogoutAgainstIdentityDeletion(t, true)
}

func forceLogoutAgainstIdentityDeletion(t *testing.T, deletionFirst bool) {
	t.Helper()
	ctx := context.Background()
	s := newConcurrencyScene(t)
	users := kanamepg.New(s.pool, nil)
	owner := seedForceLogoutUser(t, ctx, s.pool)
	absentAnswer := absentIdentityAnswer(t, s)
	hold := deletionRaceLogoutHold
	if deletionFirst {
		hold = deletionRaceDeletionHold
		installOneShotHold(t, ctx, s.pool, hold, "users", "DELETE")
	} else {
		installOneShotHold(t, ctx, s.pool, hold, "human_sessions", "UPDATE OF ended_at")
	}
	deadlocksBefore := databaseDeadlocks(t, ctx, s.pool)

	const (
		roundsPerScene    = 3
		sessionsPerPerson = 2
	)
	scenes := []struct {
		name        string
		priorCutoff bool
	}{{"строки отсечки нет", false}, {"строка отсечки есть", true}}

	var rounds, denominator, deletionAborted, logoutCommitted, logoutNothing int
	for _, sc := range scenes {
		for round := 0; round < roundsPerScene; round++ {
			rounds++
			target := seedAccountMember(t, ctx, s.pool, owner)
			if sc.priorCutoff {
				seedPriorCutoff(t, ctx, s, target)
			}
			seedLiveSessions(t, ctx, s, target, sessionsPerPerson)
			live := liveSessionCount(t, ctx, s.pool, target)
			require.Equal(t, sessionsPerPerson, live, "%s, прогон %d: знаменатель сцены", sc.name, round)
			before := remnantsOf(t, ctx, s, target)
			wantCutoffs := 0
			if sc.priorCutoff {
				wantCutoffs = 1
			}
			require.Equal(t, wantCutoffs, before.userCutoffs, "%s, прогон %d: посев отсечки", sc.name, round)
			denominator += live

			flDone := make(chan error, 1)
			delDone := make(chan error, 1)
			runFL := func() { flDone <- s.forceLogout(target) }
			runDelete := func() { delDone <- deleteIdentity(ctx, users, target) }

			armOneShotHold(t, ctx, s.pool, hold)
			if deletionFirst {
				go runDelete()
				awaitSleepingBackend(t, ctx, s.pool)
				go runFL()
			} else {
				go runFL()
				awaitSleepingBackend(t, ctx, s.pool)
				go runDelete()
			}
			awaitLockWaiters(t, ctx, s.pool, 1)
			flErr := <-flDone
			delErr := <-delDone
			disarmOneShotHold(t, ctx, s.pool, hold)

			if delErr != nil && stderrors.Is(delErr, iamerr.ErrAborted) {
				deletionAborted++
			}
			after := remnantsOf(t, ctx, s, target)
			records := forceLogoutRecords(t, ctx, s.pool, target)
			ended, failed := endedSessionsOfRecords(t, records)
			opDone, opCode := forceLogoutOperationOf(t, ctx, s, target)
			t.Logf("%s, прогон %d: живых до %d · удаление: %v · выход: %s %q · записей %d (снято %d, «не снято» %d) · "+
				"операция done=%v код=%d · осталось: личность %d, сессий %d, отсечек %d, отсечек выданного %d",
				sc.name, round, live, delErr, status.Code(flErr), status.Convert(flErr).Message(),
				len(records), ended, failed, opDone, opCode,
				after.user, after.sessions, after.userCutoffs, after.mintedCutoffs)

			// Личности нет вместе со всем, что держится её внешним ключом.
			assert.NoError(t, delErr, "%s, прогон %d: удаление личности", sc.name, round)
			assert.Zero(t, after.user, "%s, прогон %d: строка личности", sc.name, round)
			assert.Zero(t, after.sessions, "%s, прогон %d: записи сессии удалённой личности", sc.name, round)
			assert.Zero(t, after.userCutoffs, "%s, прогон %d: отсечка удалённой личности", sc.name, round)
			assert.True(t, opDone, "%s, прогон %d: операция выхода обязана быть завершена", sc.name, round)

			// Выход — целиком либо ничего.
			if flErr == nil {
				logoutCommitted++
				if assert.Len(t, records, 1, "%s, прогон %d: зафиксированный выход — одна запись", sc.name, round) {
					assert.Equal(t, "ended", records[0]["session_teardown"], "%s, прогон %d", sc.name, round)
				}
				assert.Equal(t, live, ended, "%s, прогон %d: число снятых в записи", sc.name, round)
				assert.Equal(t, int(codes.OK), opCode, "%s, прогон %d: код операции", sc.name, round)
			} else {
				logoutNothing++
				assert.Empty(t, records, "%s, прогон %d: отказавший выход не оставляет записи события", sc.name, round)
				assert.Equal(t, absentAnswer, status.Code(flErr),
					"%s, прогон %d: поздний выход обязан отвечать так же, как выход над отсутствующей "+
						"личностью; ответ %s %q", sc.name, round, status.Code(flErr), status.Convert(flErr).Message())
				assert.Equal(t, int(status.Code(flErr)), opCode, "%s, прогон %d: код операции — код ответа", sc.name, round)
			}
		}
	}

	aborted := s.refusals.aborted()
	deadlocksAfter := deadlocksAfterPoolClose(t, ctx, s.dsn, s.pool)
	t.Logf("прогонов %d · живых записей до сцен %d · выход зафиксирован %d · выход не зафиксировал ничего %d · "+
		"ответ над отсутствующей личностью %s · ABORTED выхода %d · ABORTED удаления %d · pg_stat_database.deadlocks +%d",
		rounds, denominator, logoutCommitted, logoutNothing, absentAnswer,
		aborted, deletionAborted, deadlocksAfter-deadlocksBefore)

	require.Positive(t, denominator, "знаменатель пуст — сцены судили бы личность без сессий")
	assert.Zero(t, aborted+deletionAborted, "ABORTED (40P01): выход против удаления личности")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
}
