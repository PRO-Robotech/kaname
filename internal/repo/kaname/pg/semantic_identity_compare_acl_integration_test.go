// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestSemanticIdentityComparePreservesInvokerReadACL(t *testing.T) {
	r := writerProtocolRig(t)
	r.strict(t)
	var readable, mutable bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_semantic_identity','SELECT'),has_table_privilege(current_user,'kaname.authority_semantic_identity','UPDATE')`).Scan(&readable, &mutable))
	require.True(t, readable)
	require.False(t, mutable, "row lock не требует раздавать UPDATE на private identity")
	probe, err := kanamepg.OpenSemanticIdentityCompareProbe(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, probe.Rollback(r.ctx))
	// EXECUTE остаётся: отказ должен происходить именно на исходном SELECT ACL,
	// в том числе при верно угаданной identity и уже взятом coordinator lock.
	_, err = r.admin.Exec(r.ctx, "REVOKE SELECT ON kaname.authority_semantic_identity FROM "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_semantic_identity','SELECT')`).Scan(&readable))
	require.False(t, readable)
	identity := r.bundle.Identity()
	for _, model := range []string{identity.ModelID, "wrong-identity"} {
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0)`)
		require.NoError(t, err)
		var at time.Time
		err = tx.QueryRow(r.ctx, `SELECT kaname.authority_compare_identity_v2($1,$2,$3)`, model, identity.CatalogID, identity.ProjectorVersion).Scan(&at)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
		rollbackErr := tx.Rollback(cleanup)
		cancel()
		require.NoError(t, rollbackErr)
		var pgerr *pgconn.PgError
		require.ErrorAs(t, err, &pgerr)
		require.Equal(t, "42501", pgerr.Code)
		require.Zero(t, at)
	}
	_, err = r.admin.Exec(r.ctx, "GRANT SELECT ON kaname.authority_semantic_identity TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	probe, err = kanamepg.OpenSemanticIdentityCompareProbe(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, probe.Rollback(r.ctx))
}
