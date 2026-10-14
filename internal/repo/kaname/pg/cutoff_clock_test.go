// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cutoff_clock_test.go — общий источник моментов, сравниваемых с отсечкой
// отзыва-всех, — часы первичной базы (задача kaname#589), и запись момента
// выдачи без момента — отказ, а не подстановка часов базы.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// TestSharedClock_AnswersThePrimaryDatabaseMoment — источник отвечает часами
// той базы, в которую пишутся отсечки: между двумя чтениями `now()` той же
// базы, в UTC и в её разрешении.
func TestSharedClock_AnswersThePrimaryDatabaseMoment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	var before, after time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before))
	at, err := kanamepg.NewSharedClock(pool).Now(ctx)
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after))
	require.Equal(t, time.UTC, at.Location(), "момент — в UTC")
	require.Falsef(t, at.Before(before) || at.After(after), "момент %s вне окна часов базы [%s, %s]", at, before, after)
	require.True(t, at.Equal(at.Truncate(time.Microsecond)), "момент — в разрешении хранилища")
}

// TestSharedClock_UnansweredIsAnErrorNotAMoment — база не ответила в пределе:
// ошибка, нулевого момента нет, класс для журнала — «deadline».
func TestSharedClock_UnansweredIsAnErrorNotAMoment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	clock, err := revocationpolicy.ClockWithDeadline(kanamepg.NewSharedClock(pool), time.Nanosecond)
	require.NoError(t, err)
	at, err := revocationpolicy.Moment(ctx, clock)
	require.ErrorIs(t, err, revocationpolicy.ErrClockUnavailable)
	require.True(t, at.IsZero())
	require.Equal(t, "deadline", revocationpolicy.MomentFailureClass(err))
}

// TestUserOAuthClientInsert_WithoutIssuanceMomentIsRefused — kaname#589,
// предикат 2: запасного пути к часам базы у записи момента выдачи нет —
// строка без момента отвергается до оператора, строки нет. Законный близнец —
// та же строка с моментом — ложится с ним же.
func TestUserOAuthClientInsert_WithoutIssuanceMomentIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()

	uid := mustSeedUser(t, ctx, pool, "clk589")
	repo := kanamepg.NewUserOAuthClientRepo(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)

	bare := newUOC(uid, "no-moment")
	bare.CreatedAt = time.Time{}
	tx, err := txb.Begin(ctx)
	require.NoError(t, err)
	_, err = repo.Insert(ctx, tx, bare)
	require.ErrorIs(t, err, kanamepg.ErrIssuanceMomentRequired)
	require.NoError(t, tx.Rollback(ctx))
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.user_oauth_clients WHERE id = $1`, string(bare.ID)).Scan(&n))
	require.Zero(t, n, "строки без момента нет")

	at := time.Date(2026, 10, 7, 9, 37, 0, 123456000, time.UTC)
	twin := newUOC(uid, "with-moment")
	twin.CreatedAt = at
	got := insertUOC(t, ctx, txb, repo, twin)
	require.Truef(t, got.CreatedAt.Equal(at), "момент выдачи %s, подан %s", got.CreatedAt, at)
}
