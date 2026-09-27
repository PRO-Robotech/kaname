// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_request_deadline_integration_test.go — транзакция запроса
// обмена открывается ПОД СРОКОМ вызова порта (задача PRO-Robotech/kaname#423,
// возврат ревью сборки 425).
//
// Погашение кода открывает транзакцию запроса, и её начало — взятие связи из
// пула и BEGIN — исполняется на контексте вызова порта. Пул, который связи не
// отдаёт, обязан вернуть отказ по сроку в пределах срока вызова, а не держать
// обмен без предела.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// narrowPool — пул службы (`coredb.NewPool`) шириной width: тот же
// конструктор, что у корня, и одно изменённое значение — ширина.
func narrowPool(t *testing.T, width int) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pool, err := coredb.NewPool(ctx, dsn+sep+"pool_max_conns="+strconv.Itoa(width))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	require.EqualValues(t, width, pool.Config().MaxConns, "ширина пула пробы не применилась")
	return ctx, pool
}

// consumeWithin — погашение в единице запроса под сроком вызова; ответ — исход и
// признак «вызов вернулся раньше, чем пробе надоело ждать».
func consumeWithin(v *kanamepg.CeremonyVaults, reqCtx context.Context, sig string, callLimit, patience time.Duration,
	release func(),
) (took time.Duration, returned bool, err error) {
	callCtx, cancel := context.WithTimeout(reqCtx, callLimit)
	defer cancel()
	type outcome struct {
		err  error
		took time.Duration
	}
	done := make(chan outcome, 1)
	start := time.Now()
	go func() {
		_, cerr := v.ConsumeAuthorizationCode(callCtx, sig)
		done <- outcome{cerr, time.Since(start)}
	}()
	select {
	case o := <-done:
		return o.took, true, o.err
	case <-time.After(patience):
		// Отпустить держателя, чтобы вызов вернулся и проба не оставила горутину.
		release()
		o := <-done
		return o.took, false, o.err
	}
}

// Пул в одну связь, и эта связь занята: погашение обязано вернуть отказ по
// сроку в пределах срока своего вызова. Близнец — тот же вызов с тем же сроком
// при свободном пуле гасит код.
func TestCeremonyVaults_ConsumptionHonoursItsCallDeadlineOnASaturatedPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := narrowPool(t, 1)
	sc := ceremonyScene(t, ctx, pool, "vdd1")
	v := kanamepg.NewCeremonyVaults(pool)
	sig := ceremonyDigest(0x7d0001)
	storeVaultCode(t, ctx, v, sc, sig)

	held, err := pool.Acquire(ctx)
	require.NoError(t, err, "держатель единственной связи пула")
	heldOut := true
	release := func() {
		if heldOut {
			held.Release()
			heldOut = false
		}
	}
	defer release()

	const callLimit = 300 * time.Millisecond
	reqCtx, settle := v.OpenRequest(ctx)
	took, returned, err := consumeWithin(v, reqCtx, sig, callLimit, 3*time.Second, release)
	require.NoError(t, settle(ctx), "урегулирование запроса")
	require.True(t, returned,
		"погашение при занятом пуле не вернулось за 3s при сроке вызова %s: начало транзакции запроса не несёт срока "+
			"вызова (вернулось через %s, исход %v)", callLimit, took, err)
	require.ErrorIs(t, err, context.DeadlineExceeded, "отказ погашения при занятом пуле — не отказ по сроку")
	require.Less(t, took, callLimit+time.Second, "отказ по сроку пришёл позже срока вызова")

	// Близнец: связь свободна — тот же вызов с тем же сроком гасит код.
	release()
	reqCtx2, settle2 := v.OpenRequest(ctx)
	_, returned2, err2 := consumeWithin(v, reqCtx2, sig, callLimit, 3*time.Second, func() {})
	require.True(t, returned2)
	require.NoError(t, err2, "близнец: погашение при свободном пуле")
	require.NoError(t, settle2(ctx), "близнец: урегулирование закрепляет погашение")
}
