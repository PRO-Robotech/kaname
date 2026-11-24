// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const receiptMigration = "20261112220000_registration_producers_keep_current_receipts.sql"

// Минимальная строка схемы: Down не должен уничтожать даже неподтверждённую
// provenance. Доменные admission-предпосылки проверяются отдельными пробами.
const receiptInsert = `INSERT INTO kaname.producer_source_receipt(kind,module,catalog_type,object_type,object_id,relation,subject_type,subject_id,scopes,source_version,versionless,active)
 VALUES('registration_owner','registry','registry.registries','registry_registry','down','owner','user','same','[{}]',now(),false,true)`

func TestProducerReceiptDownEmptyAndNonempty(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		name := "empty"
		if nonempty {
			name = "nonempty"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool, _ := authorityTestDB(t)
			if nonempty {
				_, err := pool.Exec(ctx, receiptInsert)
				require.NoError(t, err)
			}
			tx, err := pool.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(ctx)
			_, err = tx.Exec(ctx, reversePathOf(t, receiptMigration))
			if nonempty {
				require.ErrorContains(t, err, "producer receipts are not empty")
				require.NoError(t, tx.Rollback(ctx))
				var n int
				require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt`).Scan(&n))
				require.Equal(t, 1, n)
			} else {
				require.NoError(t, err)
				require.NoError(t, tx.Commit(ctx))
				var absent bool
				require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass('kaname.producer_source_receipt') IS NULL`).Scan(&absent))
				require.True(t, absent)
			}
		})
	}
}

func TestProducerReceiptDownSerializesConcurrentInsert(t *testing.T) {
	t.Run("writer_before_down", func(t *testing.T) {
		ctx, pool, _ := authorityTestDB(t)
		writer, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer writer.Rollback(ctx)
		_, err = writer.Exec(ctx, receiptInsert)
		require.NoError(t, err)
		down, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer down.Rollback(ctx)
		sql := reversePathOf(t, receiptMigration)
		done := make(chan error, 1)
		go func() { _, e := down.Exec(ctx, sql); done <- e }()
		receiptWaitForBlocker(t, ctx, pool, int(writer.Conn().PgConn().PID()))
		require.NoError(t, writer.Commit(ctx))
		select {
		case err = <-done:
			require.ErrorContains(t, err, "producer receipts are not empty")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.NoError(t, down.Rollback(ctx))
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt`).Scan(&n))
		require.Equal(t, 1, n, "зафиксированная provenance не потеряна")
	})
	t.Run("down_before_writer", func(t *testing.T) {
		ctx, pool, _ := authorityTestDB(t)
		down, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer down.Rollback(ctx)
		_, err = down.Exec(ctx, reversePathOf(t, receiptMigration))
		require.NoError(t, err)
		writer, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer writer.Rollback(ctx)
		done := make(chan error, 1)
		go func() { _, e := writer.Exec(ctx, receiptInsert); done <- e }()
		receiptWaitForBlocker(t, ctx, pool, int(down.Conn().PgConn().PID()))
		require.NoError(t, down.Commit(ctx))
		select {
		case err = <-done:
			require.Error(t, err, "после удаления таблицы вставка обязана явно отказать")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		require.Error(t, writer.Commit(ctx), "не должно быть успешного commit потерянной provenance")
	})
}
