// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

const tokenKeyReserve = `SELECT kaname._authority_user_token_unique_reserve_v1($1,$2,$3)`
const tokenKeyInsert = `INSERT INTO kaname.user_oauth_clients(id,user_id,created_by_user_id,credential_kind,secret_hash,expires_at)
VALUES($1,$2,$2,$3,coalesce($4::bytea,''::bytea),clock_timestamp()+interval '1 day')`

func TestUserTokenIssueUniqueReservationOrdinaryWriters(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	pool, parent := newCredQuotaDB(t)
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	owner, _, _ := credQuotaFixture(t, ctx, pool, "key-reserve")
	id := ids.NewID(domain.PrefixUserOAuthClient)
	otherID := ids.NewID(domain.PrefixUserOAuthClient)
	rowID := ids.NewID(domain.PrefixUserOAuthClient)
	digest := bytes.Repeat([]byte{37}, 32)
	_, err := pool.Exec(ctx, tokenKeyInsert, rowID, owner, "KEYPAIR", nil)
	require.NoError(t, err)
	held := tokenStorageTx(t, ctx, pool)
	_, err = held.Exec(ctx, tokenKeyReserve, id, "SECRET", digest)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, sql string
		args      []any
	}{
		{"PK insert", tokenKeyInsert, []any{id, owner, "KEYPAIR", nil}},
		{"digest insert", tokenKeyInsert, []any{otherID, owner, "SECRET", digest}},
		{"move PK", `UPDATE kaname.user_oauth_clients SET id=$2 WHERE id=$1`, []any{rowID, id}},
		{"enter partial index", `UPDATE kaname.user_oauth_clients SET credential_kind='SECRET',secret_hash=$2 WHERE id=$1`, []any{rowID, digest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := tokenStorageTx(t, ctx, pool)
			_, err := other.Exec(ctx, `SET LOCAL lock_timeout='200ms'`)
			require.NoError(t, err)
			_, err = other.Exec(ctx, tc.sql, tc.args...)
			tokenStorageState(t, err, "55P03")
		})
	}
	separate := tokenStorageTx(t, ctx, pool)
	_, err = separate.Exec(ctx, `SET LOCAL lock_timeout='200ms'`)
	require.NoError(t, err)
	_, err = separate.Exec(ctx, tokenKeyInsert, otherID, owner, "KEYPAIR", nil)
	require.NoError(t, err)
	require.NoError(t, separate.Rollback(ctx))
	require.NoError(t, held.Rollback(ctx))

	_, err = pool.Exec(ctx, tokenKeyInsert, otherID, owner, "SECRET", digest)
	require.NoError(t, err)
	for _, tc := range []struct {
		id, kind   string
		hash       []byte
		constraint string
	}{
		{otherID, "KEYPAIR", nil, "user_oauth_clients_pkey"},
		{id, "SECRET", digest, "user_oauth_clients_secret_hash_unique"},
	} {
		_, err = pool.Exec(ctx, tokenKeyReserve, tc.id, tc.kind, tc.hash)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23505", pgErr.Code)
		require.Equal(t, tc.constraint, pgErr.ConstraintName)
	}
}

func TestUserTokenIssueUniqueReservationRestartsForEarlierWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	pool, parent := newCredQuotaDB(t)
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	owner, _, _ := credQuotaFixture(t, ctx, pool, "key-before-reserve")
	id := ids.NewID(domain.PrefixUserOAuthClient)
	digest := bytes.Repeat([]byte{61}, 32)
	writer := tokenStorageTx(t, ctx, pool)
	_, err := writer.Exec(ctx, tokenKeyInsert, id, owner, "SECRET", digest)
	require.NoError(t, err)
	for _, tc := range []struct {
		id, kind string
		hash     []byte
	}{
		{id, "KEYPAIR", nil},
		{ids.NewID(domain.PrefixUserOAuthClient), "SECRET", digest},
	} {
		_, err := pool.Exec(ctx, tokenKeyReserve, tc.id, tc.kind, tc.hash)
		tokenStorageState(t, err, "40001")
	}
	require.NoError(t, writer.Commit(ctx))
	removal := tokenStorageTx(t, ctx, pool)
	_, err = removal.Exec(ctx, `DELETE FROM kaname.user_oauth_clients WHERE id=$1`, id)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, tokenKeyReserve, id, "SECRET", digest)
	tokenStorageState(t, err, "40001")
	require.NoError(t, removal.Commit(ctx))
	_, err = pool.Exec(ctx, tokenKeyReserve, id, "SECRET", digest)
	require.NoError(t, err)
}
