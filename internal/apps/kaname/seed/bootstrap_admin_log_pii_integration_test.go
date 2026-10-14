// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// bootstrap_admin_log_pii_integration_test.go — kaname#631: журнал шага
// посева первого администратора не несёт его адреса ни на одном уровне.
//
// Адрес — персональные данные. Журнал называет администратора непрозрачным
// id строки там, где строка найдена, а до этого — только признаком «адрес
// задан», без значения.
//
// Проба проходит КАЖДУЮ ветку посева, пишущую в журнал, на уровне Debug
// (ниже любого уровня, который ставит посадка), и утверждает две вещи сразу:
// ветка действительно исполнилась и записала своё сообщение (иначе «адреса
// нет» неотличимо от «журнала нет»), и ни адреса, ни его частей в записанном
// нет. Знаменатель — число исполненных веток — печатается и сверяется.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// piiMarkerAddress — адрес, части которого не встречаются нигде, кроме него
// самого: совпадение в журнале может прийти только от него.
func piiMarkerAddress(t *testing.T) (addr, local, domainPart string) {
	t.Helper()
	b := make([]byte, 6)
	_, err := rand.Read(b)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): случайный маркер")
	tag := hex.EncodeToString(b)
	local = "piilocal" + tag
	domainPart = "piidomain" + tag + ".test"
	return local + "@" + domainPart, local, domainPart
}

// requireNoAddress — ни адреса, ни его локальной части, ни домена; регистр не
// спасает (сравнение по адресу в продукте регистронезависимо).
func requireNoAddress(t *testing.T, branch, logged, addr, local, domainPart string) {
	t.Helper()
	low := strings.ToLower(logged)
	for _, part := range []string{addr, local, domainPart} {
		require.NotContainsf(t, low, strings.ToLower(part),
			"ветка %q: журнал посева несёт адрес администратора (или его часть)\n--- журнал ---\n%s", branch, logged)
	}
}

type piiBranch struct {
	name       string
	wantReason seed.BootstrapSkipReason
	wantMsg    string
	prepare    func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string)
	// runs — сколько раз прогнать посев; ветка гонки достигается вторым проходом.
	runs int
}

func TestBootstrapAdminLog_NoAddressOnAnyBranchAtAnyLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	branches := []piiBranch{
		{
			name: "not_registered", wantReason: seed.BootstrapSkipNotRegistered,
			wantMsg: "bootstrap admin user not registered yet",
			prepare: func(*testing.T, context.Context, *pgxpool.Pool, string) {},
			runs:    1,
		},
		{
			name: "row_not_active", wantReason: seed.BootstrapSkipNotActive,
			wantMsg: "bootstrap admin row exists but may not authenticate",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) {
				seedUserRow(t, ctx, pool, email, "BLOCKED")
			},
			runs: 1,
		},
		{
			name: "not_verified", wantReason: seed.BootstrapSkipNotVerified,
			wantMsg: "bootstrap admin address not verified yet",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) {
				seedUnverifiedBootstrapUser(t, ctx, pool, email)
			},
			runs: 1,
		},
		{
			name: "granted", wantReason: "",
			wantMsg: "bootstrap admin: cluster admin grant + outbox enqueue committed",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) {
				seedBootstrapUser(t, ctx, pool, email)
			},
			runs: 1,
		},
		{
			name: "concurrent_race", wantReason: seed.BootstrapSkipConcurrentRace,
			wantMsg: "concurrent bootstrap detected",
			prepare: func(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) {
				seedBootstrapUser(t, ctx, pool, email)
			},
			runs: 2,
		},
	}

	executed := 0
	for _, br := range branches {
		t.Run(br.name, func(t *testing.T) {
			ctx := context.Background()
			pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
			require.NoError(t, err)
			defer pool.Close()

			addr, local, domainPart := piiMarkerAddress(t)
			br.prepare(t, ctx, pool, addr)

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			var res seed.BootstrapAdminResult
			for i := 0; i < br.runs; i++ {
				res, err = seed.RunBootstrapAdmin(ctx, pool, logger, seed.BootstrapAdminInput{Email: addr})
				require.NoError(t, err)
			}
			require.Equalf(t, br.wantReason, res.SkipReason,
				"НЕ-ВЫПОЛНИЛОСЬ(ветка %q не достигнута): причина исхода не та", br.name)
			require.Containsf(t, buf.String(), br.wantMsg,
				"НЕ-ВЫПОЛНИЛОСЬ(ветка %q): сообщение ветки не записано — «адреса нет» было бы «журнала нет»", br.name)
			requireNoAddress(t, br.name, buf.String(), addr, local, domainPart)
			executed++
		})
	}
	t.Logf("веток посева исполнено: %d из %d", executed, len(branches))
	require.Equal(t, len(branches), executed, "знаменатель: исполнены не все ветки посева")
}

// TestBootstrapAdminLog_ReconcilerPassesCarryNoAddress — петля согласователя
// повторяет проход каждые несколько секунд до схождения: журнал КАЖДОГО прохода,
// включая собственные записи петли, без адреса. Проходов ровно два — остановка
// по счётчику, не по времени.
func TestBootstrapAdminLog_ReconcilerPassesCarryNoAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	addr, local, domainPart := piiMarkerAddress(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	passes := 0
	run := func(ctx context.Context) (seed.BootstrapAdminResult, error) {
		passes++
		if passes == 2 {
			defer cancel()
		}
		return seed.RunBootstrapAdmin(ctx, pool, logger, seed.BootstrapAdminInput{Email: addr})
	}
	rec := seed.NewBootstrapReconciler(run, seed.BootstrapReconcilerConfig{Interval: 1, Logger: logger})
	require.NoError(t, rec.Run(ctx))

	require.GreaterOrEqual(t, passes, 2, "НЕ-ВЫПОЛНИЛОСЬ: петля не сделала двух проходов")
	require.Equal(t, 2, strings.Count(buf.String(), "bootstrap admin user not registered yet"),
		"НЕ-ВЫПОЛНИЛОСЬ: каждый проход обязан записать сообщение ветки")
	require.Contains(t, buf.String(), "bootstrap admin not yet reconciled, will retry")
	requireNoAddress(t, "reconciler", buf.String(), addr, local, domainPart)
}
