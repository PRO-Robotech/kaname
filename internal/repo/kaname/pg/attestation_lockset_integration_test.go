// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Только test owner может создать этот fault injector. Он меняет account set
// настоящего entry на той же connection; runtime не получает DML на proof.
// Это проверка verifier, не утверждение о доступной runtime подделке proof.
func attestationLocksetInjector(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_attestation_accounts(p_accounts text[],p_mode text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 BEGIN
  UPDATE pg_temp.kaname_authority_attestation SET accounts=p_accounts,mode=p_mode;
  IF NOT FOUND THEN RAISE EXCEPTION 'test requires actual entry'; END IF;
 END $$;
 REVOKE ALL ON FUNCTION kaname.test_attestation_accounts(text[],text) FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.test_attestation_accounts(text[],text) TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.admin.Exec(ctx, `DROP FUNCTION IF EXISTS kaname.test_attestation_accounts(text[],text)`)
	})
}

func attestationLocksetRollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func TestAttestationLocksetActualLoginAndFreshInvocation(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	attestationLocksetInjector(t, r)
	attestationNonceObserver(t, r)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	r.enter(t, tx, r.intent(r.a, r.b), "decision")
	// Нет injector перед positive: настоящий complete entry и BEFORE STATEMENT.
	_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='lockset-positive' WHERE false`)
	require.NoError(t, err)
	var nonce string
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_attestation_nonce()`).Scan(&nonce))
	require.NotEmpty(t, nonce)
	// Прежняя положительная проверка не кэшируется: следующий guard заново
	// проверяет весь изменённый test-only proof и находит последний missing key.
	_, err = tx.Exec(r.ctx, `SELECT kaname.test_attestation_accounts(ARRAY[$1,$2,$3]::text[],'accounts')`, r.a, r.b, "lockset_missing_after_positive")
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='must-deny' WHERE false`)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Equal(t, "authority account barrier missing", pe.Message)
	require.NoError(t, tx.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}

func TestAttestationLocksetLastKeyAndForeignLocks(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	attestationLocksetInjector(t, r)
	for _, mode := range []string{"complete", "collision", "missing-last", "shared-last", "namespace-last", "foreign-pid-last", "bigint-last", "wrong-root-mode"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			r.enter(t, tx, r.intent(r.a), "decision")
			keys := make([]string, 255)
			keys[0] = r.a
			for i := 1; i < len(keys); i++ {
				keys[i] = fmt.Sprintf("lockset_%s_%03d", mode, i)
			}
			// Последний key выбирается без hash collision с prefix; иначе отрицательная
			// проба могла бы законно удовлетвориться тем же физическим advisory lock.
			var unique bool
			for attempt := 0; attempt < 8; attempt++ {
				keys[len(keys)-1] = fmt.Sprintf("lockset_%s_last_%d", mode, attempt)
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT NOT (hashtext($1)=ANY(SELECT hashtext(v) FROM unnest($2::text[]) v))`, keys[len(keys)-1], keys[:len(keys)-1]).Scan(&unique))
				if unique {
					break
				}
			}
			require.True(t, unique)
			if mode == "collision" {
				keys[len(keys)-2], keys[len(keys)-1] = "acc-collision-716556", "acc-collision-916815"
				var collisionKey int32
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT hashtext($1) FROM (SELECT 1) v WHERE hashtext($1)=hashtext($2)`, keys[len(keys)-2], keys[len(keys)-1]).Scan(&collisionKey))
				require.Equal(t, int32(-2116289360), collisionKey)
			}
			_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569281,hashtext(v)) FROM unnest($1::text[]) v`, keys[:len(keys)-1])
			require.NoError(t, err)
			last := keys[len(keys)-1]
			var other pgx.Tx
			switch mode {
			case "complete":
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569281,hashtext($1))`, last)
			case "shared-last":
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock_shared(1262569281,hashtext($1))`, last)
			case "namespace-last":
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569282,hashtext($1))`, last)
			case "bigint-last":
				// Тот же classid/objid, но bigint API имеет objsubid=1 вместо 2.
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock((1262569281::bigint<<32) | (hashtext($1)::bigint & 4294967295))`, last)
			case "foreign-pid-last":
				other, err = r.runtime.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(other)
				_, err = other.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569281,hashtext($1))`, last)
			}
			require.NoError(t, err)
			proofMode := "accounts"
			if mode == "wrong-root-mode" {
				proofMode = "global"
			}
			_, err = tx.Exec(r.ctx, `SELECT kaname.test_attestation_accounts($1::text[],$2)`, keys, proofMode)
			require.NoError(t, err)
			// Реальный statement guard, не копия verifier в тесте.
			_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='lockset-probe' WHERE false`)
			if mode == "complete" || mode == "collision" {
				require.NoError(t, err)
				require.NoError(t, tx.Commit(r.ctx))
			} else {
				var pe *pgconn.PgError
				require.ErrorAs(t, err, &pe)
				require.Equal(t, "42501", pe.Code)
				expected := "authority account barrier missing"
				if mode == "wrong-root-mode" {
					expected = "authority cluster barrier missing"
				}
				require.Equal(t, expected, pe.Message, "не чужая ранняя ошибка вместо lockset refusal")
				require.NoError(t, tx.Rollback(r.ctx))
			}
			if other != nil {
				require.NoError(t, other.Rollback(r.ctx))
			}
		})
	}
	authorityWaitReleased(t, r.runtime)
}

// Выполняет реальные Up/Down SQL sections в отдельных owner TX. Goose journal
// не переписывается: здесь проверяется замена тела/ACL/drain, не runner goose.
func TestAttestationLocksetMigrationSQLRoundTrip(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	raw, err := migrations.FS.ReadFile("20261114080000_attestation_reads_lockset_once.sql")
	require.NoError(t, err)
	parts := strings.Split(string(raw), "-- +goose Down")
	require.Len(t, parts, 2)
	var original, acl string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prosrc,coalesce(proacl::text,'') FROM pg_catalog.pg_proc WHERE oid='kaname.authority_protocol_attestation()'::regprocedure`).Scan(&original, &acl))
	for _, restoreUp := range []bool{false, true} {
		sql := parts[1]
		if restoreUp {
			sql = parts[0]
		}
		tx, e := r.admin.Begin(r.ctx)
		require.NoError(t, e)
		defer attestationLocksetRollback(tx)
		_, e = tx.Exec(r.ctx, sql)
		require.NoError(t, e)
		require.NoError(t, tx.Commit(r.ctx))
		var body, actualACL, config string
		var definer bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prosrc,coalesce(proacl::text,''),prosecdef,array_to_string(proconfig,';') FROM pg_catalog.pg_proc WHERE oid='kaname.authority_protocol_attestation()'::regprocedure`).Scan(&body, &actualACL, &definer, &config))
		require.Equal(t, acl, actualACL)
		require.True(t, definer)
		require.Equal(t, "search_path=pg_catalog,pg_temp", strings.ReplaceAll(config, " ", ""))
		if restoreUp {
			require.Equal(t, original, body)
		} else {
			require.Contains(t, body, "FOR k IN SELECT DISTINCT hashtext(value)")
		}
		runtimeTX, e := r.runtime.Begin(r.ctx)
		require.NoError(t, e)
		defer attestationLocksetRollback(runtimeTX)
		r.enter(t, runtimeTX, r.intent(r.a, r.b), "decision")
		_, e = runtimeTX.Exec(r.ctx, `UPDATE kaname.groups SET description='roundtrip' WHERE false`)
		require.NoError(t, e)
		require.NoError(t, runtimeTX.Commit(r.ctx))
	}
	authorityWaitReleased(t, r.runtime)
}
