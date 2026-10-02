// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_identity_deletion_race_integration_test.go — ПРИНУДИТЕЛЬНЫЙ
// ВЫХОД И УДАЛЕНИЕ ЛИЧНОСТИ, ИДУЩИЕ ОДНОВРЕМЕННО, НЕ БЛОКИРУЮТ ДРУГ ДРУГА
// (задача kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ПОРЯДОК ЗАХВАТА СТРОК
//
// Удаление личности идёт по внешним ключам сверху вниз: строка `users`
// (`FOR UPDATE` самим удалением), затем каскадом её записи сессии. Транзакция
// принудительного выхода на посадке `own` снимает записи сессии, а строку
// личности берёт позже — `FOR KEY SHARE` проверкой внешнего ключа отсечки.
// Порядки встречные: выход держит сессию и ждёт личность, удаление держит
// личность и ждёт сессию.
//
// Утверждается: при таком чередовании ни одна из двух транзакций не падает
// взаимной блокировкой (`40P01`), обе фиксируются, выход записывает «снято»,
// а личности после удаления нет. Прогонов — шесть, каждый со своей личностью.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ВЫЗВАНО ЧЕРЕДОВАНИЕ
//
// Окно между снятием сессии и отсечкой у выхода короткое, поэтому оно
// расширено триггером, засыпающим ПОСЛЕ отметки окончания записи сессии:
// замок на строке сессии к этому моменту взят. Удаление запускается, когда
// обслуживающий процесс выхода виден спящим (`pg_stat_activity`), — то есть
// ровно внутри окна, а не наугад по времени. Удаление — настоящим писателем
// (`UsersW().Delete`), тем, которым его исполняет полоса удаления личности.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedAccountMember — ещё одна активная личность в аккаунте владельца. Владелец
// аккаунта не удаляется вовсе (`accounts_owner_fk`), поэтому удаляемой в сцене
// обязана быть не она.
func seedAccountMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner domain.UserID) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		SELECT $1, account_id, $2, $3, 'Deletion Race Target', 'ACTIVE'
		  FROM kaname.users WHERE id = $4`,
		string(uid), "ext-"+string(uid), fmt.Sprintf("m-%s@example.com", uid), string(owner))
	require.NoError(t, err, "личность в аккаунте владельца")
	return uid
}

// awaitSleepingBackend — ждёт, пока обслуживающий процесс выхода не окажется
// внутри окна: спящим в триггере после отметки окончания записи сессии.
func awaitSleepingBackend(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var sleeping int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event = 'PgSleep'`).Scan(&sleeping))
		if sleeping > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("выход не вошёл в окно за 10 с — сцена чередования не построена")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIntegration_ForceLogoutAndIdentityDeletionDoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	owner := seedForceLogoutUser(t, ctx, pool)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	users := kanamepg.New(pool, nil)

	_, err := pool.Exec(ctx, `
		CREATE FUNCTION kaname.probe_hold_after_session_end() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(0.5);
			RETURN NULL;
		END $$`)
	require.NoError(t, err, "функция окна")
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER probe_hold_after_session_end
		AFTER UPDATE OF ended_at ON kaname.human_sessions
		FOR EACH ROW EXECUTE FUNCTION kaname.probe_hold_after_session_end()`)
	require.NoError(t, err, "триггер окна")

	const rounds = 6
	var deadlocks, deletionFailures, logoutFailures int
	for round := 0; round < rounds; round++ {
		target := seedAccountMember(t, ctx, pool, owner)
		digest := freshBearerDigest(t)
		seedOwnLoginSession(t, ctx, pool, target, digest)
		requireLiveBefore(t, ctx, sessions, digest)

		logoutDone := make(chan error, 1)
		go func() {
			_, lerr := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{
				UserId: string(target),
				Reason: "admin-force-logout",
			})
			logoutDone <- lerr
		}()
		awaitSleepingBackend(t, ctx, pool)

		deleteErr := func() error {
			w, werr := users.Writer(ctx)
			if werr != nil {
				return werr
			}
			defer func() { _ = w.Rollback(ctx) }()
			if derr := w.UsersW().Delete(ctx, target); derr != nil {
				return derr
			}
			return w.Commit(ctx)
		}()
		logoutErr := <-logoutDone

		if deleteErr != nil {
			deletionFailures++
			if stderrors.Is(deleteErr, iamerr.ErrAborted) {
				deadlocks++
			}
			t.Logf("прогон %d: удаление отказало: %v", round, deleteErr)
		}
		if logoutErr != nil {
			logoutFailures++
			t.Logf("прогон %d: выход отказал: %v", round, logoutErr)
			continue
		}
		record := requireOneForceLogoutRecord(t, ctx, pool, target)
		assert.Equal(t, "ended", record["session_teardown"], "прогон %d: %v", round, record)
	}
	t.Logf("прогонов %d · взаимных блокировок %d · отказов удаления %d · отказов выхода %d",
		rounds, deadlocks, deletionFailures, logoutFailures)

	assert.Zero(t, deadlocks,
		"выход и удаление личности берут строки в ВСТРЕЧНОМ порядке: выход держит сессию "+
			"и ждёт личность, удаление держит личность и ждёт сессию")
	assert.Zero(t, deletionFailures, "удаление личности обязано фиксироваться в каждом прогоне")
	assert.Zero(t, logoutFailures, "принудительный выход обязан фиксироваться в каждом прогоне")
}
