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

// Owner-only GIVEN повреждает metadata уже настоящего signed entry в его TX.
// Production helper не экспортирует flags/proof и не получает caller arguments.
func TestAttestationSingleSnapshotPreservesFirstFailureOrder(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_snapshot_fault_v3(p_mode text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$
BEGIN
 CASE p_mode
 WHEN 'root-before-consumer' THEN
  UPDATE pg_temp.kaname_authority_attestation SET mode='global';
  UPDATE pg_temp.kaname_authority_consumer SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'accounts-before-consumer' THEN
  UPDATE pg_temp.kaname_authority_attestation SET accounts=accounts||ARRAY['snapshot_missing_account'];
  UPDATE pg_temp.kaname_authority_consumer SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'consumer-before-missing-relation' THEN
  ALTER TABLE kaname.authority_producer_population_latch RENAME TO authority_producer_population_latch_snapshot_test;
  UPDATE pg_temp.kaname_authority_consumer SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'compat-before-missing-relation' THEN
  ALTER TABLE kaname.authority_producer_population_latch RENAME TO authority_producer_population_latch_snapshot_test;
  PERFORM pg_advisory_xact_lock(1262569283,0);
  UPDATE pg_temp.kaname_authority_attestation SET mode='global';
 WHEN 'missing-relation' THEN
  ALTER TABLE kaname.authority_producer_population_latch RENAME TO authority_producer_population_latch_snapshot_test;
 WHEN 'extra-mode' THEN LOCK TABLE kaname.authority_producer_population_latch IN EXCLUSIVE MODE;
 WHEN 'legal-access-share' THEN LOCK TABLE kaname.authority_producer_population_latch IN ACCESS SHARE MODE;
 ELSE RAISE EXCEPTION 'unknown snapshot test fault';END CASE;
END $fault$;
REVOKE ALL ON FUNCTION kaname.test_snapshot_fault_v3(text) FROM PUBLIC;
CREATE FUNCTION kaname.test_snapshot_v1_v3() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observe$
BEGIN RETURN kaname._authority_protocol_attestation_v1_body() IS NOT NULL;END $observe$;
REVOKE ALL ON FUNCTION kaname.test_snapshot_v1_v3() FROM PUBLIC;
CREATE FUNCTION kaname.test_snapshot_full_v3() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observe_full$
BEGIN RETURN kaname.authority_protocol_attestation() IS NOT NULL;END $observe_full$;
REVOKE ALL ON FUNCTION kaname.test_snapshot_full_v3() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_snapshot_fault_v3(text);DROP FUNCTION kaname.test_snapshot_v1_v3();DROP FUNCTION kaname.test_snapshot_full_v3()`)
		require.NoError(t, e)
	})
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.test_snapshot_fault_v3(text),kaname.test_snapshot_v1_v3(),kaname.test_snapshot_full_v3() TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	_, err = r.runtime.Exec(r.ctx, `SELECT * FROM kaname._authority_protocol_snapshot_v3()`)
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	// Production attestation остаётся закрытой для прямого runtime EXECUTE.
	// Test-only owner door вызывает её в той же сессии/TX; invoker не подменяется.
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_protocol_attestation()`)
	denied = nil
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	for _, tc := range []struct{ mode, code, message string }{
		{"root-before-consumer", "42501", "authority cluster barrier missing"},
		{"accounts-before-consumer", "42501", "authority account barrier missing"},
		{"consumer-before-missing-relation", "42501", "authority consumer v2 witness mismatch"},
		{"compat-before-missing-relation", "42501", "authority compatibility admission missing"},
		{"missing-relation", "42P01", ""},
		{"extra-mode", "42501", "authority population latch mode mismatch"},
		{"legal-access-share", "", ""},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			tx, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			defer attestationLocksetRollback(tx)
			r.enter(t, tx, r.intent(r.a), "decision")
			// Обе проверки до повреждения обязаны принять настоящий entry.
			var allowed bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_snapshot_full_v3()`).Scan(&allowed))
			require.True(t, allowed)
			_, e = tx.Exec(r.ctx, `SELECT kaname.test_snapshot_fault_v3($1)`, tc.mode)
			require.NoError(t, e)
			// Свежий plan нужен именно для проверки позднего regclass name resolution;
			// не полагаемся на историческую регистровую константу cached PL expression.
			_, e = tx.Exec(r.ctx, `DISCARD PLANS`)
			require.NoError(t, e)
			if tc.mode != "root-before-consumer" && tc.mode != "accounts-before-consumer" {
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_snapshot_v1_v3()`).Scan(&allowed))
				require.True(t, allowed, "старый private v1 ABI не добавляет consumer/latch отказы")
			}
			e = tx.QueryRow(r.ctx, `SELECT kaname.test_snapshot_full_v3()`).Scan(&allowed)
			if tc.code == "" {
				require.NoError(t, e)
				require.True(t, allowed)
			} else {
				var pe *pgconn.PgError
				require.ErrorAs(t, e, &pe)
				require.Equal(t, tc.code, pe.Code)
				if tc.message != "" {
					require.Equal(t, tc.message, pe.Message)
				}
			}
			require.NoError(t, tx.Rollback(r.ctx))
			var restored bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_regclass('kaname.authority_producer_population_latch') IS NOT NULL
   AND to_regclass('kaname.authority_producer_population_latch_snapshot_test') IS NULL`).Scan(&restored))
			require.True(t, restored, "rollback восстанавливает original latch и private fault state")
		})
	}
	authorityWaitReleased(t, r.runtime)
}
