// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// recovery_keeps_block_integration_test.go — самостоятельное восстановление
// пароля возвращает УЧЁТНЫЕ ДАННЫЕ, но не право пользоваться ими.
//
// Продуктовое решение: блокировка — административный акт, и снимается она
// административным актом. Самостоятельное восстановление доказывает владение
// почтовым ящиком — ровно то, что администратор, ставя запрет, под сомнение и
// не ставил. Прежняя редакция считала «строка есть в {действующая,
// заблокированная}» достаточным основанием снять запрет, то есть решала по
// наличию строки там, где предметом было её состояние: обе половины одного
// пути компрометации смотрели в противоположные стороны — выдача токена
// отказывала заблокированному, а восстановление возвращало его в строй.
//
// Отсечка сессий (revoke-all) остаётся на КАЖДОЙ затронутой строке, в том
// числе заблокированной: обрубить живые сессии личности, чьи учётные данные
// только что сменили, полезно независимо от того, разрешено ли ей входить.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestOnRecoveryCompleted_BlockedStaysBlocked — наблюдаемый исход: запрет
// переживает самостоятельное восстановление.
func TestOnRecoveryCompleted_BlockedStaysBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")

	uid, accID := seedAccountAndUser(t, ctx, pool, "krt_blocked_keep", "keep@example.com", "BLOCKED")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_blocked_keep", RecoveryJTI: "rec_keep_001", Email: "keep@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "восстановление проходит: смена учётных данных состоялась")

	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "BLOCKED", statusDB,
		"самостоятельное восстановление не снимает административную блокировку")

	// Отсечка всё равно поставлена — это и есть предмет восстановления.
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	// Событие записано, аккаунт назван.
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_keep_001"))
	var tenant string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT tenant_account_id FROM kaname.audit_outbox
		 WHERE event_payload->>'recovery_jti' = $1`, "rec_keep_001").Scan(&tenant))
	assert.Equal(t, string(accID), tenant)
}

// TestOnRecoveryCompleted_ActiveStaysActive — контрольный случай той же формы:
// действующая личность восстановлением не портится, отсечка ставится.
func TestOnRecoveryCompleted_ActiveStaysActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_active_keep", "active-keep@example.com", "ACTIVE")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_active_keep", RecoveryJTI: "rec_keep_002", Email: "active-keep@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error)

	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB)

	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)
}
