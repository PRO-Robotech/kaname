// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// bearer_letter_sweep_integration_test.go — условие аудита поверхности к
// приёмке `access-beyond-login-needs-a-verified-address.md` (kaname#456):
// открытое значение кода в строке очереди писем снимается уборкой, когда код
// истёк, — и у недоставленного письма; строка с живым кодом остаётся. Уборка
// окон источника снимает только вышедшие окна.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

func TestExpiredBearerLettersAreSweptEvenUndelivered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.NewHumanSessionRepo(pool)

	emit := func(user string, validFor time.Duration, age time.Duration) int64 {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.NoError(t, invite_mail_outbox.EmitVerificationTx(ctx, tx, user, "acc-x", user+"@example.invalid", "ABCDE-FGH12", validFor))
		var id int64
		require.NoError(t, tx.QueryRow(ctx, `SELECT max(id) FROM invite_mail_outbox`).Scan(&id))
		_, err = tx.Exec(ctx, `UPDATE invite_mail_outbox SET created_at = now() - $2::interval WHERE id = $1`, id, age)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id
	}
	expired := emit("usr-sweep-expired", 30*time.Minute, 31*time.Minute)
	live := emit("usr-sweep-live", 30*time.Minute, time.Minute)

	removed, _, err := repo.SweepExpiredBearerLetters(ctx, 0, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята ровно строка с истёкшим кодом")
	var left []int64
	rows, err := pool.Query(ctx, `SELECT id FROM invite_mail_outbox WHERE id IN ($1, $2)`, expired, live)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		left = append(left, id)
	}
	rows.Close()
	require.Equal(t, []int64{live}, left, "письмо с живым кодом остаётся; письмо с истёкшим снято и недоставленным")

	// Окна источника: вышедшее снимается, живое остаётся.
	_, err = pool.Exec(ctx, `INSERT INTO source_request_windows (lane, source, window_started_at, requests)
		VALUES ('registration', '198.51.100.1', now() - interval '2 hours', 3),
		       ('registration', '198.51.100.2', now(), 1)`)
	require.NoError(t, err)
	removed, _, err = repo.SweepAgedSourceWindows(ctx, time.Hour, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снято вышедшее окно")
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM source_request_windows WHERE source = '198.51.100.2'`).Scan(&n))
	require.Equal(t, 1, n, "живое окно остаётся")
}
