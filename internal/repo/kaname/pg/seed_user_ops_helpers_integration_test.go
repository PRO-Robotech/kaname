// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// seed_user_ops_helpers_integration_test.go — общая подпорка интеграционных
// проб пакета: посев пары (аккаунт, пользователь).
//
// Жила в файле проб снятого глагола обратного вызова прежнего поставщика
// восстановления (kaname#564). Ожидание операции снято вместе с последним
// вызывающим — пробами, гонявшими глагол заведения личности по внешнему
// удостоверению (снят kaname#929): они идут теперь телом заведения напрямую.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
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

	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}
