// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// force_logout_writer_lock_wait_integration_test.go — ТРАНЗАКЦИЯ ПРИНУДИТЕЛЬНОГО
// ВЫХОДА ЖДЁТ ОДНОГО ЗАМКА НЕ ДОЛЬШЕ СВОЕГО ПРЕДЕЛА (задача kaname#340).
//
// Предел — `lock_timeout` самой транзакции, и ограничивает он КАЖДОЕ ожидание
// замка отдельно, а не их сумму: здесь строку держит ОДНА чужая транзакция, и
// утверждение — о ней. Утверждается наблюдаемое: снятие сессии, строку которой
// держит чужая транзакция, отказывает недоступностью ВСКОРЕ после предела, а не
// по сроку вызова и не по потолку оператора пула. Сумму ожиданий при
// нескольких держателях по очереди предел не ограничивает, и проба этого не
// утверждает.
// И отдельно — что предел, который `lock_timeout` выразил бы нулём, то есть
// «без предела», транзакцию не открывает: иначе ограничение снималось бы молча.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestIntegration_ForceLogoutWriterWaitsForARowLockNoLongerThanItsOwnLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	scene := ceremonyScene(t, ctx, pool, "fxwat")

	blocker, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback(ctx) }()
	var held int
	require.NoError(t, blocker.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.human_sessions WHERE id = $1 FOR SHARE) s`,
		scene.SessionID).Scan(&held))
	require.Equal(t, 1, held, "замок на строке сессии не взят — сцена не построена")

	const limit = 300 * time.Millisecond
	w, err := kanamepg.NewHumanSessionRepo(pool).ForceLogoutWriter(ctx, domain.UserID(scene.UserID), limit)
	require.NoError(t, err, "транзакция выхода")
	defer func() { _ = w.Rollback(ctx) }()

	started := time.Now()
	_, err = w.EndOtherSessions(ctx, domain.UserID(scene.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
	elapsed := time.Since(started)
	require.Error(t, err, "снятие прошло сквозь чужой замок — сцена не построена")
	assert.True(t, stderrors.Is(err, iamerr.ErrUnavailable),
		"отказ замка в своём пределе обязан читаться недоступностью: %v", err)
	assert.GreaterOrEqual(t, elapsed, limit, "отказ пришёл раньше предела — это не отказ по пределу")
	assert.Less(t, elapsed, 5*time.Second,
		"снятие ждало %s: предел транзакции не действует, ожидание ограничено чем-то иным", elapsed)
}

func TestIntegration_ForceLogoutWriterRefusesALimitThatWouldMeanNoLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	scene := ceremonyScene(t, ctx, pool, "fxzer")
	repo := kanamepg.NewHumanSessionRepo(pool)

	for _, wait := range []time.Duration{0, -time.Second, 500 * time.Microsecond} {
		w, err := repo.ForceLogoutWriter(ctx, domain.UserID(scene.UserID), wait)
		if w != nil {
			_ = w.Rollback(ctx)
		}
		assert.Error(t, err,
			"предел %s записался бы в `lock_timeout` нулём — то есть «ждать без предела»", wait)
	}

	// Положительный близнец: законный предел транзакцию открывает.
	w, err := repo.ForceLogoutWriter(ctx, domain.UserID(scene.UserID), time.Millisecond)
	require.NoError(t, err, "предел в одну миллисекунду законен")
	require.NoError(t, w.Rollback(ctx))
}
