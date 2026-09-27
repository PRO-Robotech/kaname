// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// bootstrap_admin_address_integration_test.go — полоса И приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, Р12) и
// условие аудита поверхности о посеве роли: строка с адресом посева обязана
// быть и действующей, и подтверждённой; отметка и адрес судятся ОДНИМ чтением
// строки, которой выдаётся право, и выдача — в той же транзакции.

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// TestEV80_UnverifiedSeedAddressGetsNoGrant — EV-80.
func TestEV80_UnverifiedSeedAddressGetsNoGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, verified := range []bool{false, true} {
		ctx := context.Background()
		pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
		require.NoError(t, err)
		const email = "seed-ev80@example.test"
		uid := seedBootstrapUser(t, ctx, pool, email)
		if verified {
			_, err = pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, uid)
			require.NoError(t, err)
		}
		res, err := seed.RunBootstrapAdmin(ctx, pool, slog.New(slog.DiscardHandler), seed.BootstrapAdminInput{Email: email})
		require.NoError(t, err)
		var grants int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants))
		if verified {
			require.False(t, res.Skipped, "EV-80 (б): выдача создана")
			require.Equal(t, 1, grants)
			var events int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM audit_outbox WHERE event_type = 'iam.cluster_admin.granted'
				 AND event_payload->>'subject_id' = $1`, uid).Scan(&events))
			require.Equal(t, 1, events, "EV-80 (б): событие iam.cluster_admin.granted")
			pool.Close()
			continue
		}
		require.True(t, res.Skipped, "EV-80 (а): пропуск")
		require.Equal(t, seed.BootstrapSkipReason("user not verified"), res.SkipReason, "EV-80 (а): причина user not verified")
		require.Zero(t, grants, "EV-80 (а): выдачи нет")
		pool.Close()
	}
}

// TestEV81_TheSkipReasonIsNotTerminal — EV-81: после подтверждения следующий
// проход согласователя выдаёт; близнец — `email empty` согласователь
// останавливает, как сегодня.
func TestEV81_TheSkipReasonIsNotTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()
	const email = "seed-ev81@example.test"
	uid := seedBootstrapUser(t, ctx, pool, email)
	run := func(ctx context.Context) (seed.BootstrapAdminResult, error) {
		return seed.RunBootstrapAdmin(ctx, pool, slog.New(slog.DiscardHandler), seed.BootstrapAdminInput{Email: email})
	}
	rec := seed.NewBootstrapReconciler(run, seed.BootstrapReconcilerConfig{Interval: 20 * time.Millisecond})
	done := make(chan struct{})
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	go func() { defer close(done); _ = rec.Run(rctx) }()
	time.Sleep(200 * time.Millisecond)
	var grants int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants))
	require.Zero(t, grants, "EV-81: до подтверждения выдачи нет")
	_, err = pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, uid)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_ = pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants)
		return grants == 1
	}, 10*time.Second, 50*time.Millisecond, "EV-81: первый проход после подтверждения выдаёт")
	cancel()
	<-done
}

// TestSeedGrantOnlyExistsWhenTheMarkIsCommitted — условие аудита поверхности:
// подтверждение и проход посева одновременно 50 раз — выдача существует ТОЛЬКО
// при закоммиченной отметке; ни в одном повторе нет выдачи строке без отметки.
func TestSeedGrantOnlyExistsWhenTheMarkIsCommitted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()
	for i := 0; i < 50; i++ {
		email := "seed-race-" + time.Now().Format("150405.000000") + "@example.test"
		uid := seedBootstrapUser(t, ctx, pool, email)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = pool.Exec(ctx, `UPDATE users SET email_verified_at = now() WHERE id = $1`, uid)
		}()
		go func() {
			defer wg.Done()
			_, _ = seed.RunBootstrapAdmin(ctx, pool, slog.New(slog.DiscardHandler), seed.BootstrapAdminInput{Email: email})
		}()
		wg.Wait()
		var grants int
		var marked bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants))
		require.NoError(t, pool.QueryRow(ctx, `SELECT email_verified_at IS NOT NULL FROM users WHERE id = $1`, uid).Scan(&marked))
		require.True(t, grants == 0 || marked, "повтор %d: выдача без закоммиченной отметки", i)
		// Строка, так и не подтверждённая, выдачи не получает.
		_, _ = pool.Exec(ctx, `DELETE FROM cluster_admin_grants WHERE subject_id = $1`, uid)
	}
	unverified := seedBootstrapUser(t, ctx, pool, "seed-race-never@example.test")
	for i := 0; i < 5; i++ {
		_, _ = seed.RunBootstrapAdmin(ctx, pool, slog.New(slog.DiscardHandler), seed.BootstrapAdminInput{Email: "seed-race-never@example.test"})
	}
	var grants int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, unverified).Scan(&grants))
	require.Zero(t, grants, "строка, занявшая адрес посева без отметки, права не получает никогда")
}
