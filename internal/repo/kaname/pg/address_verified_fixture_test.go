// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// markAddressVerified — Дано сцен активации приглашения: приглашённый
// подтвердил свой адрес. Активация приглашения идёт только после подтверждения
// (kaname#456, Р11), и сцена, судящая иной факт (срок, членство, повтор),
// ставит его, чтобы отказ оставался отказом по своему факту.
func markAddressVerified[ID ~string](t *testing.T, ctx context.Context, pool *pgxpool.Pool, id ID) {
	t.Helper()
	_, err := pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(id))
	require.NoError(t, err)
}
