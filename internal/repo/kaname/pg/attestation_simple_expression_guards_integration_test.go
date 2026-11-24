// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Проверяем живую canonical функцию, а не её текст/скорость. Изменения helper
// и TEMP proof — adversarial входы внутри откатываемых subtransactions.
func TestAttestationCompatibilitySimpleExpressionGuards(t *testing.T) {
	r := writerProtocolRig(t)
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	type functionState struct{ definition, body, metadata string }
	readState := func(q interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	}, signature string) functionState {
		t.Helper()
		var state functionState
		require.NoError(t, q.QueryRow(r.ctx, `SELECT pg_get_functiondef(p.oid),p.prosrc,
   jsonb_build_object('oid',p.oid,'owner',p.proowner,'acl',p.proacl,'settings',p.proconfig,
   'language',p.prolang,'definer',p.prosecdef,'volatility',p.provolatile)::text
   FROM pg_catalog.pg_proc p WHERE p.oid=$1::regprocedure`, signature).Scan(&state.definition, &state.body, &state.metadata))
		return state
	}
	const publicSignature = "kaname.authority_protocol_attestation()"
	const helperSignature = "kaname._authority_compare_legacy_write_allowed_v2()"
	publicBefore := readState(tx, publicSignature)
	helperBefore := readState(tx, helperSignature)
	var compatible, attestationAbsent, compareAbsent, ownsHelper bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT
  (SELECT enforcement='compatibility' FROM kaname.authority_writer_protocol WHERE singleton),
  to_regclass('pg_temp.kaname_authority_attestation') IS NULL,
  to_regclass('pg_temp.kaname_authority_compare') IS NULL,
  (SELECT proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
   FROM pg_catalog.pg_proc WHERE oid='kaname._authority_compare_legacy_write_allowed_v2()'::regprocedure)`,
	).Scan(&compatible, &attestationAbsent, &compareAbsent, &ownsHelper))
	require.True(t, compatible)
	require.True(t, attestationAbsent)
	require.True(t, compareAbsent)
	require.True(t, ownsHelper)
	cases := []struct{ name, code, message string }{
		{name: "absent"},
		{name: "empty"},
		{name: "valid"},
		{name: "invalid", code: "42501", message: "compare source reader cannot become a local writer"},
		{name: "spoofed", code: "42501", message: "untrusted compare storage"},
		{name: "strict", code: "42501", message: "authority transaction attestation required"},
		{name: "helper_raise", code: "42501", message: "simple expression helper mutation reached"},
		{name: "helper_drop", code: "42883", message: "function kaname._authority_compare_legacy_write_allowed_v2() does not exist"},
		{name: "same_command_temp_mutation", code: "42501", message: "compare source reader cannot become a local writer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel запрещён: один backend и последовательная проверка invalidation.
			sub, beginErr := tx.Begin(r.ctx)
			require.NoError(t, beginErr)
			defer attestationLocksetRollback(sub)
			var isNull bool
			require.NoError(t, sub.QueryRow(r.ctx, `SELECT kaname.authority_protocol_attestation() IS NULL`).Scan(&isNull))
			require.True(t, isNull, "прогрев canonical callable до изменения helper/proof")
			var heldExclusive bool
			require.NoError(t, sub.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
    WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
    AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
    AND mode='ExclusiveLock' AND granted)`).Scan(&heldExclusive))
			require.True(t, heldExclusive, "unsigned вызов должен реально взять compatibility admission")
			switch tc.name {
			case "empty", "valid", "invalid", "same_command_temp_mutation":
				_, err = sub.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_compare(backend integer,transaction_id xid8,invoker_oid oid,nonce text,mode text) ON COMMIT DROP`)
			case "spoofed":
				_, err = sub.Exec(r.ctx, `CREATE TEMP VIEW kaname_authority_compare AS SELECT 1 AS backend`)
			case "strict":
				_, err = sub.Exec(r.ctx, `UPDATE kaname.authority_writer_protocol SET enforcement='strict' WHERE singleton`)
			case "helper_raise":
				require.Equal(t, 1, strings.Count(helperBefore.definition, helperBefore.body))
				rejected := strings.Replace(helperBefore.definition, helperBefore.body, `BEGIN RAISE EXCEPTION 'simple expression helper mutation reached' USING ERRCODE='42501'; END`, 1)
				_, err = sub.Exec(r.ctx, rejected)
			case "helper_drop":
				_, err = sub.Exec(r.ctx, `DROP FUNCTION kaname._authority_compare_legacy_write_allowed_v2()`)
			default:
				err = nil
			}
			require.NoError(t, err)
			if tc.name == "valid" {
				_, err = sub.Exec(r.ctx, `LOCK TABLE kaname.authority_producer_population_latch IN SHARE MODE`)
				require.NoError(t, err)
				_, err = sub.Exec(r.ctx, `INSERT INTO pg_temp.kaname_authority_compare SELECT pg_backend_pid(),pg_current_xact_id(),oid,'simple-expression-valid','global' FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user)`)
				require.NoError(t, err)
			}
			if tc.name == "invalid" {
				_, err = sub.Exec(r.ctx, `INSERT INTO pg_temp.kaname_authority_compare VALUES(0,pg_current_xact_id(),0,'invalid','accounts')`)
				require.NoError(t, err)
			}
			var callErr error
			if tc.name == "same_command_temp_mutation" {
				_, callErr = sub.Exec(r.ctx, `DO $mutation$ BEGIN
     PERFORM kaname.authority_protocol_attestation();
     INSERT INTO pg_temp.kaname_authority_compare VALUES(0,pg_current_xact_id(),0,'invalid','accounts');
     PERFORM kaname.authority_protocol_attestation();
    END $mutation$`)
			} else {
				callErr = sub.QueryRow(r.ctx, `SELECT kaname.authority_protocol_attestation() IS NULL`).Scan(&isNull)
			}
			if tc.code == "" {
				require.NoError(t, callErr)
				require.True(t, isNull)
			} else {
				var pgerr *pgconn.PgError
				require.ErrorAs(t, callErr, &pgerr)
				require.Equal(t, tc.code, pgerr.Code)
				require.Equal(t, tc.message, pgerr.Message)
				// Where вправе называть assignment либо PERFORM; отказ и его причина точны.
			}
			require.NoError(t, sub.Rollback(r.ctx))
		})
		// Проверка после каждого case: следующему не достаются его DDL/TEMP изменения.
		require.Equal(t, publicBefore, readState(tx, publicSignature))
		require.Equal(t, helperBefore, readState(tx, helperSignature))
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT to_regclass('pg_temp.kaname_authority_compare') IS NULL`).Scan(&compareAbsent))
		require.True(t, compareAbsent)
	}
	require.NoError(t, tx.Rollback(r.ctx))
	// Внешний observer подтверждает откат и определения, и security metadata.
	require.Equal(t, publicBefore, readState(r.admin, publicSignature))
	require.Equal(t, helperBefore, readState(r.admin, helperSignature))
}
