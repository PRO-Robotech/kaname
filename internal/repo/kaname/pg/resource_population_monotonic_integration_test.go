// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Это owner storage-component probe, не доказательство native authority:
// любые успешные metadata изменения остаются внутри откатываемой TX.
func TestResourcePopulationTokenMonotonicStorage(t *testing.T) {
	r := writerProtocolRig(t)
	t.Run("increments and insert change exact token", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		defer policyFixtureRollback(tx)
		var beforeCount, afterCount int
		var beforeSum, afterSum string
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT row_count,revision_sum FROM kaname.authority_policy_population_read(100000)`).Scan(&beforeCount, &beforeSum))
		for i := 0; i < 2; i++ {
			_, err = tx.Exec(r.ctx, `UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='*'`)
			require.NoError(t, err)
		}
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT row_count,revision_sum FROM kaname.authority_policy_population_read(100000)`).Scan(&afterCount, &afterSum))
		require.Equal(t, beforeCount, afterCount)
		number, ok := new(big.Int).SetString(beforeSum, 10)
		require.True(t, ok)
		require.Equal(t, new(big.Int).Add(number, big.NewInt(2)).String(), afterSum)
		_, err = tx.Exec(r.ctx, `INSERT INTO kaname.authority_policy_epoch(key) VALUES($1)`, "scope:account:"+r.a+":population-component")
		require.NoError(t, err)
		var insertedCount int
		var insertedSum string
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT row_count,revision_sum FROM kaname.authority_policy_population_read(100000)`).Scan(&insertedCount, &insertedSum))
		require.Equal(t, afterCount+1, insertedCount)
		require.Equal(t, afterSum, insertedSum, "новая zero-revision identity обнаруживается через COUNT")
	})
	for name, statement := range map[string]string{
		"revision reset":   `UPDATE kaname.authority_policy_epoch SET revision=revision-1 WHERE key='*'`,
		"generation reset": `UPDATE kaname.authority_policy_epoch SET generation=generation||'-reset' WHERE key='*'`,
		"key move":         `UPDATE kaname.authority_policy_epoch SET key='moved-root' WHERE key='*'`,
		"delete ABA":       `DELETE FROM kaname.authority_policy_epoch WHERE key='*'`,
		"truncate":         `TRUNCATE kaname.authority_policy_epoch`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(tx)
			_, err = tx.Exec(r.ctx, statement)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, "42501", denied.Code)
		})
	}
}
