// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// bootstrap_admin_row_choice_integration_test.go — какую именно строку посев
// администратора выбирает по адресу почты.
//
// Один человек = N строк с одним адресом (по одной на аккаунт): глобальная
// уникальность почты снята намеренно (миграция 0011), поэтому «взять первую
// попавшуюся» — не редкий случай, а обычный. Выбор без упорядочивания отдан
// физическому порядку строк: тот же стенд, тот же адрес, а права уровня
// кластера получает то одна строка, то другая. Плюс выбор не смотрел на
// состояние — под него подходила и заблокированная строка, и неподтверждённое
// приглашение.
//
// Здесь фиксируется наблюдаемый исход: посев выбирает каноническую строку
// личности (старейшую действующую), делает это одинаково от прогона к прогону
// и не сеет прав ни на заблокированную строку, ни на приглашение.

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// seedUserRow вставляет строку пользователя с заданными состоянием и моментом
// создания (+ её аккаунт) и возвращает id.
func seedUserRow(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	email, inviteStatus string, createdAt time.Time,
) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	accID := ids.NewID(domain.PrefixAccount)

	// DB-CHECK users_invite_status_consistency: PENDING ⇔ external_id='',
	// ACTIVE/BLOCKED ⇔ external_id<>''.
	externalID := "ext-" + uid
	if inviteStatus == "PENDING" {
		externalID = ""
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		uid, accID, externalID, email, "Bootstrap Admin", inviteStatus, createdAt)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, "boot-acc-"+strings.ToLower(accID[len(accID)-6:]), uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid
}

// TestRunBootstrapAdmin_PicksOldestActiveRow_NotArbitrary — у личности три
// строки с одним адресом. Права обязаны достаться канонической — старейшей
// действующей, той же, которую по этому адресу резолвят остальные пути.
func TestRunBootstrapAdmin_PicksOldestActiveRow_NotArbitrary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "multi@prorobotech.ru"
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Порядок вставки намеренно обратен возрасту: физический порядок строк
	// (то, чем прежде решался выбор) противоречит канону.
	newest := seedUserRow(t, ctx, pool, email, "ACTIVE", base.Add(48*time.Hour))
	oldest := seedUserRow(t, ctx, pool, email, "ACTIVE", base)
	middle := seedUserRow(t, ctx, pool, email, "ACTIVE", base.Add(24*time.Hour))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, oldest, res.UserID,
		"выбор обязан быть каноническим (старейшая действующая строка), а не физическим порядком")
	assert.NotEqual(t, newest, res.UserID)
	assert.NotEqual(t, middle, res.UserID)

	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, oldest).Scan(&grants))
	assert.Equal(t, 1, grants)
}

// TestRunBootstrapAdmin_SkipsBlockedRow — заблокированная строка существует,
// поэтому проверка на наличие её пропускала. Права уровня кластера на
// заблокированную личность не сеются.
func TestRunBootstrapAdmin_SkipsBlockedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "blocked@prorobotech.ru"
	blocked := seedUserRow(t, ctx, pool, email, "BLOCKED", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.True(t, res.Skipped, "заблокированной личности права не сеются")
	assert.Equal(t, "user not active", res.SkipReason,
		"причина пропуска обязана отличать «строки нет» от «строка есть, но не действует» — иначе оператор ищет опечатку в адресе")

	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, blocked).Scan(&grants))
	assert.Zero(t, grants)
	// Миграции сеют собственные строки очереди, поэтому считаются только те,
	// что называют эту личность.
	var outbox int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM fga_outbox WHERE payload->>'user' = $1`, "user:"+blocked).Scan(&outbox))
	assert.Zero(t, outbox, "ни одной записи в очередь на выдачу для заблокированной личности")
}

// TestRunBootstrapAdmin_PrefersActiveOverOlderBlocked — заблокированная строка
// старше действующей. Возраст не отменяет состояния.
func TestRunBootstrapAdmin_PrefersActiveOverOlderBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "mixed@prorobotech.ru"
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	blocked := seedUserRow(t, ctx, pool, email, "BLOCKED", base)
	active := seedUserRow(t, ctx, pool, email, "ACTIVE", base.Add(24*time.Hour))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, active, res.UserID)
	assert.NotEqual(t, blocked, res.UserID)
}

// TestRunBootstrapAdmin_EmailMatchIsCaseInsensitive — уникальность почты в этой
// схеме определена по lower(email); посев обязан спрашивать так же, иначе
// объявленный адрес администратора «не находится» из-за регистра.
func TestRunBootstrapAdmin_EmailMatchIsCaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	uid := seedUserRow(t, ctx, pool, "Mixed.Case@ProRobotech.RU", "ACTIVE",
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(),
		seed.BootstrapAdminInput{Email: "mixed.case@prorobotech.ru"})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, uid, res.UserID)
}
