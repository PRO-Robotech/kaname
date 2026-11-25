// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

const tokenStorageWait = `SELECT kaname._authority_user_token_issue_storage_wait_v1($1,$2,$3,$4)`
const tokenStorageAuditID = "evt_0000000000000000000001"
const tokenStorageAuditInsert = `INSERT INTO kaname.audit_outbox(id,event_type,event_payload,status) VALUES($1,'iam.user_token.issued','{}','pending')`

func tokenStorageTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	return tx
}

func tokenStorageState(t *testing.T, err error, state string) {
	t.Helper()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, state, pgErr.Code)
}

// Обычные SQL writers проходят через их настоящие quota/audit triggers. NOWAIT
// или lock_timeout проверяют конфликт, успешный повтор после rollback — снятие.
func TestUserTokenIssueStorageWaitHoldsWriteDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	pool, parent := newCredQuotaDB(t)
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	owner, machine, _, other := credQuotaFixtureWithVictim(t, ctx, pool, "storage-wait")
	for _, tc := range []struct{ name, typ, id string }{
		{"self", "user", owner}, {"human", "user", other}, {"machine", "service_account", machine},
	} {
		t.Run(tc.name, func(t *testing.T) {
			held := tokenStorageTx(t, ctx, pool)
			_, err := held.Exec(ctx, tokenStorageWait, tc.typ, tc.id, owner, tokenStorageAuditID)
			require.NoError(t, err)
			type query struct {
				sql  string
				args []any
			}
			checks := []query{
				{`SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE NOWAIT`, []any{owner}},
				{`SELECT kind FROM kaname.own_ceilings WHERE kind='iam.user.credential' FOR UPDATE NOWAIT`, nil},
				{`SELECT kind FROM kaname.project_resource_quotas WHERE carrier_type='iam.user' AND carrier_id=$1 AND kind='iam.user.credential' FOR UPDATE NOWAIT`, []any{owner}},
				{`LOCK TABLE ONLY kaname.user_oauth_clients IN SHARE MODE NOWAIT`, nil},
				{tokenStorageAuditInsert, []any{tokenStorageAuditID}},
			}
			if tc.typ == "service_account" {
				checks = append(checks, query{`SELECT id FROM kaname.service_accounts WHERE id=$1 FOR UPDATE NOWAIT`, []any{tc.id}})
			} else if tc.id != owner {
				checks = append(checks, query{`SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE NOWAIT`, []any{tc.id}})
			}
			// Другая квота и другой audit ID не делят эксклюзивную блокировку.
			separate := tokenStorageTx(t, ctx, pool)
			_, err = separate.Exec(ctx, `SET LOCAL lock_timeout='250ms'`)
			require.NoError(t, err)
			_, err = separate.Exec(ctx, tokenStorageWait, "user", other, other, "evt_0000000000000000000002")
			require.NoError(t, err)
			require.NoError(t, separate.Rollback(ctx))
			for _, q := range checks {
				contender := tokenStorageTx(t, ctx, pool)
				_, err = contender.Exec(ctx, `SET LOCAL lock_timeout='250ms'`)
				require.NoError(t, err)
				_, err = contender.Exec(ctx, q.sql, q.args...)
				tokenStorageState(t, err, "55P03")
				require.NoError(t, contender.Rollback(ctx))
			}
			require.NoError(t, held.Rollback(ctx))
			released := tokenStorageTx(t, ctx, pool)
			for _, q := range checks {
				_, err = released.Exec(ctx, q.sql, q.args...)
				require.NoError(t, err)
			}
			require.NoError(t, released.Rollback(ctx))
		})
	}
}

func TestUserTokenIssueStorageWaitHandlesAbsentQuotaAndExistingAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	pool, parent := newCredQuotaDB(t)
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	owner, _, _ := credQuotaFixture(t, ctx, pool, "absent-quota")
	tag, err := pool.Exec(ctx, `DELETE FROM kaname.project_resource_quotas WHERE carrier_type='iam.user' AND carrier_id=$1 AND kind='iam.user.credential'`, owner)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	held := tokenStorageTx(t, ctx, pool)
	_, err = held.Exec(ctx, tokenStorageWait, "user", owner, owner, tokenStorageAuditID)
	require.NoError(t, err)

	const insertQuota = `INSERT INTO kaname.project_resource_quotas(carrier_type,carrier_id,kind,limit_value,source_scope)
VALUES('iam.user',$1,'iam.user.credential',12,'DEFAULT')`
	other := tokenStorageTx(t, ctx, pool)
	_, err = other.Exec(ctx, `SET LOCAL lock_timeout='250ms'`)
	require.NoError(t, err)
	_, err = other.Exec(ctx, insertQuota, owner)
	tokenStorageState(t, err, "55P03")
	require.NoError(t, other.Rollback(ctx))
	require.NoError(t, held.Rollback(ctx))
	_, err = pool.Exec(ctx, insertQuota, owner)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, tokenStorageAuditInsert, tokenStorageAuditID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, tokenStorageWait, "user", owner, owner, tokenStorageAuditID)
	tokenStorageState(t, err, "23505")
}

func TestUserTokenIssueStorageWaitPrecedesDecisionAndIsPrivate(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	pool, parent := newCredQuotaDB(t)
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	defer cancel()
	owner, _, _ := credQuotaFixture(t, ctx, pool, "blocked-quota")
	var private bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT NOT p.prosecdef AND NOT EXISTS (
SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner AND a.privilege_type='EXECUTE')
FROM pg_proc p WHERE p.oid='kaname._authority_user_token_issue_storage_wait_v1(text,text,text,text)'::regprocedure`).Scan(&private))
	require.True(t, private)
	blocker := tokenStorageTx(t, ctx, pool)
	_, err := blocker.Exec(ctx, `SELECT kind FROM kaname.project_resource_quotas WHERE carrier_type='iam.user' AND carrier_id=$1 AND kind='iam.user.credential' FOR UPDATE`, owner)
	require.NoError(t, err)
	candidate := tokenStorageTx(t, ctx, pool)
	_, err = candidate.Exec(ctx, `SET LOCAL lock_timeout='250ms'`)
	require.NoError(t, err)
	_, err = candidate.Exec(ctx, tokenStorageWait, "user", owner, owner, tokenStorageAuditID)
	tokenStorageState(t, err, "55P03")
	require.NoError(t, candidate.Rollback(ctx))
	require.NoError(t, blocker.Rollback(ctx))
	_, err = pool.Exec(ctx, tokenStorageWait, "user", owner, owner, tokenStorageAuditID)
	require.NoError(t, err)
	var audits int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE id=$1`, tokenStorageAuditID).Scan(&audits))
	require.Zero(t, audits)
}
