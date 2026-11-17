// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Два одновременных отказа характеризуют прежний порядок DEFAULT:
// Свежая аттестация предшествует исходным правам и проверке закрытого хранилища.
// Тестовый вход владельца сохраняет права приложения и не принимает аттестацию или заголовок.
func TestSequenceDefaultPreservesPrivilegeAndCustodyFailureOrder(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		revoke, enter, invalid bool
		message                string
	}{
		{"privilege-before-corrupt-storage", true, true, false, "sequence default lacks original privileges"},
		{"corrupt-storage-after-privilege", false, true, false, "untrusted sequence program storage"},
		{"invalid-proof-before-privilege", true, true, true, "authority account barrier missing"},
		{"missing-proof-before-privilege", true, false, false, "authority transaction attestation required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := writerProtocolRig(t)
			_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_default_failure_order_v3() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $door$
BEGIN RETURN kaname._authority_sequence_default_v3('fga_outbox');END $door$;
REVOKE ALL ON FUNCTION kaname.test_default_failure_order_v3() FROM PUBLIC`)
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, e := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_default_failure_order_v3()`)
				require.NoError(t, e)
			})
			_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.test_default_failure_order_v3() TO "+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			attestationLocksetInjector(t, r)
			require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			if tc.revoke {
				_, err = r.admin.Exec(r.ctx, "REVOKE USAGE,UPDATE ON SEQUENCE kaname.fga_outbox_id_seq FROM "+pgx.Identifier{r.role}.Sanitize())
				require.NoError(t, err)
			}
			var privilege bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_sequence_privilege(current_user,'kaname.fga_outbox_id_seq','USAGE,UPDATE')`).Scan(&privilege))
			require.Equal(t, !tc.revoke, privilege, "GIVEN: проверяются фактические права исходного LOGIN")
			snapshot := func() string {
				var value string
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
    'sequence',(SELECT jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called) FROM kaname.fga_outbox_id_seq s),
    'fga',(SELECT count(*) FROM kaname.fga_outbox),
    'journal',(SELECT count(*) FROM kaname.resource_journal))::text`).Scan(&value))
				return value
			}
			before := snapshot()
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			if tc.enter {
				r.enter(t, tx, r.intent(r.a), "decision")
			}
			// Поддельное хранилище создаёт обычный LOGIN без подстановки корректного заголовка владельцем.
			_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_sequence_program(junk integer) ON COMMIT DROP`)
			require.NoError(t, err)
			if tc.invalid {
				_, err = tx.Exec(r.ctx, `SELECT kaname.test_attestation_accounts(ARRAY[$1,$2]::text[],'accounts')`, r.a, "default_precedence_missing_account")
				require.NoError(t, err)
			}
			_, err = tx.Exec(r.ctx, `SELECT kaname.test_default_failure_order_v3()`)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			require.Equal(t, tc.message, pe.Message)
			require.NoError(t, tx.Rollback(r.ctx))
			require.Equal(t, before, snapshot(), "отказ не вызывает nextval и не создаёт события")
			authorityWaitReleased(t, r.runtime)
		})
	}
}
