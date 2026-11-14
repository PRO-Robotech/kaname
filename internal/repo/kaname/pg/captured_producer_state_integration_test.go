// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Фикстура проверяет только хранилище: из этих строк не выводится право.
// Отдельная ordinary-LOGIN проба получает положительный D1 через настоящие
// Register и installer. Здесь exact SQL incarnation guard проверяется отдельно
// от более раннего epoch rejection, чтобы выполнить именно его ветку отказа.
func TestCapturedProducerActualSQLIncarnationAndExactKeys(t *testing.T) {
	pool := cvPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	bundle := nativeBoundaryBundle(t)
	actor := nativeBoundaryActor()
	const insert = `INSERT INTO kaname.producer_source_receipt(kind,module,catalog_type,object_type,object_id,relation,subject_type,subject_id,scopes,source_version,versionless,active)
 VALUES('registration_owner','iam','iam.account','account',$1,'owner','user',$2,'[{"registered":true,"account_id":"acc_capture"}]',clock_timestamp(),false,true)`
	_, err = conn.Exec(ctx, insert, "captured-original", string(actor.ID))
	require.NoError(t, err)
	capture := func() *producerPopulationCapture {
		tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, e)
		c, e := captureProducerPopulation(ctx, tx, bundle, actor, &relverdict.AdministrativeReadBudget{})
		require.NoError(t, tx.Rollback(ctx))
		require.NoError(t, e)
		return c
	}
	reread := func(c *producerPopulationCapture) error {
		tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		require.NoError(t, e)
		defer tx.Rollback(ctx)
		w := &semanticAuthorityWriteTx{authorityWriteTx: &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}}, bundle: bundle}
		keys := make([]producerReceiptKey, len(c.receipts))
		for i, r := range c.receipts {
			keys[i] = r.key
		}
		raw, e := json.Marshal(keys)
		require.NoError(t, e)
		_, e = w.rereadCapturedProducerState(ctx, c.receipts, raw)
		return e
	}
	original := capture()
	require.Len(t, original.receipts, 1)
	require.NoError(t, reread(original))
	_, err = conn.Exec(ctx, insert, "new-foreign-unlocked", string(actor.ID))
	require.NoError(t, err)
	require.NoError(t, reread(original), "new receipt is not admitted or compared as captured authority")
	require.Len(t, original.receipts, 1)
	// JSON одинаков, но heap incarnation другой: xmin/ctid обязаны заметить ABA.
	var before, after string
	require.NoError(t, conn.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM kaname.producer_source_receipt r WHERE object_id='captured-original'`).Scan(&before))
	_, err = conn.Exec(ctx, `UPDATE kaname.producer_source_receipt SET active=active WHERE object_id='captured-original'`)
	require.NoError(t, err)
	require.NoError(t, conn.QueryRow(ctx, `SELECT to_jsonb(r)::text FROM kaname.producer_source_receipt r WHERE object_id='captured-original'`).Scan(&after))
	require.Equal(t, before, after, "only physical incarnation changed")
	require.ErrorIs(t, reread(original), kaname.ErrAuthorityClassificationChanged)
	fresh := capture()
	require.Len(t, fresh.receipts, 2)
	require.NoError(t, reread(fresh))
	_, err = conn.Exec(ctx, `UPDATE kaname.producer_source_receipt SET active=false WHERE object_id='captured-original'`)
	require.NoError(t, err)
	require.ErrorIs(t, reread(fresh), kaname.ErrAuthorityClassificationChanged, "revocation is detected before active-row filtering")
}
