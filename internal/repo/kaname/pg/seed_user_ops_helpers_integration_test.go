// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// seed_user_ops_helpers_integration_test.go — общие подпорки интеграционных
// проб пакета: посев пары (аккаунт, пользователь) и ожидание операции.
//
// Жили в файле проб снятого глагола обратного вызова прежнего поставщика
// восстановления (kaname#564); их зовут пробы заведения личности и блокировки,
// поэтому файл проб снят, а подпорки перенесены сюда без изменений.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// seedAccountAndUser inserts (account, user) with the given external_id / email /
// invite_status in one tx (DEFERRABLE FK chicken-and-egg). Returns the ids.
func seedAccountAndUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, externalID, email, status string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		string(uid), string(accID), externalID, email, "Recovery User", status)
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), fmt.Sprintf("rec-acc-%s", accID[len(accID)-6:]), string(uid))
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// awaitOp polls the ops repo until done (or timeout).
func awaitOp(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operation %s not done within deadline", id)
	return nil
}
