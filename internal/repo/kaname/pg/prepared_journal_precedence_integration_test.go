// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Публичный allocator заново проверяет физический proof на каждом входе.
// Compatibility NULL не читает sequence storage, а signed proof предшествует
// custody refusal. Настоящие prepared INSERT/claim проверяет соседний sequence
// integrity suite; здесь два одновременных отказа фиксируют их первый locus.
func TestPreparedJournalPreservesProofCustodyOrderAndFreshInvocation(t *testing.T) {
	r := writerProtocolRig(t)
	attestationLocksetInjector(t, r)
	var granted bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
  'kaname.authority_prepared_journal_value_v3(jsonb,jsonb)','EXECUTE')`).Scan(&granted))
	require.True(t, granted, "проверяется production allocator настоящего LOGIN")
	snapshot := func() string {
		var value string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
  'sequence',(SELECT jsonb_build_object('last_value',s.last_value,'is_called',s.is_called)
   FROM kaname.resource_journal_sequence_no_seq s),
  'journal',(SELECT count(*) FROM kaname.resource_journal),
  'fga',(SELECT count(*) FROM kaname.fga_outbox))::text`).Scan(&value))
		return value
	}
	before := snapshot()
	t.Run("compatibility-null-ignores-caller-storage", func(t *testing.T) {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		defer attestationLocksetRollback(tx)
		_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_sequence_program(junk integer) ON COMMIT DROP;
 CREATE TEMP TABLE kaname_authority_sequence_effects(junk integer) ON COMMIT DROP`)
		require.NoError(t, err)
		var absent bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_prepared_journal_value_v3('{}'::jsonb,'{}'::jsonb) IS NULL`).Scan(&absent))
		require.True(t, absent)
		require.NoError(t, tx.Rollback(r.ctx))
		require.Equal(t, before, snapshot())
	})
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	before = snapshot()
	for _, tc := range []struct {
		name, message  string
		enter, invalid bool
	}{
		{"missing-proof-before-custody", "authority transaction attestation required", false, false},
		{"invalid-proof-before-custody-after-positive", "authority account barrier missing", true, true},
		{"custody-after-valid-proof", "untrusted sequence program storage", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			if tc.enter {
				r.enter(t, tx, r.intent(r.a), "decision")
				var absent bool
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_prepared_journal_value_v3('{}'::jsonb,'{}'::jsonb) IS NULL`).Scan(&absent))
				require.True(t, absent, "полный signed entry без private program не выделяет ID")
			}
			_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_sequence_program(junk integer) ON COMMIT DROP`)
			require.NoError(t, err)
			if tc.invalid {
				_, err = tx.Exec(r.ctx, `SELECT kaname.test_attestation_accounts(ARRAY[$1,$2]::text[],'accounts')`, r.a, "prepared_journal_missing_account")
				require.NoError(t, err)
			}
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_prepared_journal_value_v3('{}'::jsonb,'{}'::jsonb)`)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			require.Equal(t, tc.message, pe.Message)
			require.NoError(t, tx.Rollback(r.ctx))
			require.Equal(t, before, snapshot(), "отказ не вызывает nextval и не создаёт события")
		})
	}
	authorityWaitReleased(t, r.runtime)
}
