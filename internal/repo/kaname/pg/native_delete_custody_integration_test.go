// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Дверь существует только в тестовой БД. Имена storage и виды порчи ограничены
// конечными списками; обычный runtime не получает прав владельца таблиц.
func nativeDeleteCustodyFaultDoor(t *testing.T, r protocolRig) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_native_delete_custody_trigger_v4() RETURNS trigger
LANGUAGE plpgsql AS $trigger$ BEGIN RETURN NEW; END $trigger$;
CREATE FUNCTION kaname.test_native_delete_custody_fault_v4(p_table text,p_fault text,p_role text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$
DECLARE target text;
BEGIN
 IF p_table NOT IN ('kaname_forward_program_v4','kaname_forward_effects_v4','kaname_forward_receipts_v4')
 THEN RAISE EXCEPTION 'unknown test table';END IF;
 target:=format('pg_temp.%I',p_table);
 CASE p_fault
 WHEN 'table-acl' THEN EXECUTE format('GRANT SELECT ON %s TO PUBLIC',target);
 WHEN 'column-acl' THEN EXECUTE format('GRANT SELECT(nonce) ON %s TO PUBLIC',target);
 WHEN 'owner' THEN EXECUTE format('ALTER TABLE %s OWNER TO %I',target,p_role);
 WHEN 'rls' THEN EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY',target);
 WHEN 'force-rls' THEN EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY',target);
 WHEN 'trigger' THEN EXECUTE format('CREATE TRIGGER test_custody BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION kaname.test_native_delete_custody_trigger_v4()',target);
 WHEN 'rule' THEN EXECUTE format('CREATE RULE test_custody AS ON INSERT TO %s DO INSTEAD NOTHING',target);
 WHEN 'inherits-parent' THEN EXECUTE format('CREATE TEMP TABLE test_custody_child () INHERITS (%s)',target);
 WHEN 'inherits-child' THEN
  CREATE TEMP TABLE test_custody_parent(nonce uuid NOT NULL);
  EXECUTE format('ALTER TABLE %s INHERIT pg_temp.test_custody_parent',target);
 WHEN 'missing' THEN EXECUTE format('DROP TABLE %s',target);
 ELSE RAISE EXCEPTION 'unknown test fault';
 END CASE;
END $fault$;
REVOKE ALL ON FUNCTION kaname.test_native_delete_custody_trigger_v4() FROM PUBLIC;
REVOKE ALL ON FUNCTION kaname.test_native_delete_custody_fault_v4(text,text,text) FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_native_delete_custody_fault_v4(text,text,text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION kaname.test_native_delete_custody_fault_v4(text,text,text); DROP FUNCTION kaname.test_native_delete_custody_trigger_v4()`)
		require.NoError(t, err)
	})
}

// Настоящий claim и INSERT со stamp проверяют SQL42501, затем полный откат
// родительской TX убирает и прежний успешный INSERT, и постоянный anchor.
func TestNativeDeleteCustodyEveryPrivateRelationRejectsTamper(t *testing.T) {
	r := writerProtocolRig(t)
	nativeDeleteCustodyFaultDoor(t, r)
	for _, table := range []string{"kaname_forward_program_v4", "kaname_forward_effects_v4", "kaname_forward_receipts_v4"} {
		for _, fault := range []string{"table-acl", "column-acl", "owner", "rls", "force-rls", "trigger", "rule", "inherits-parent", "inherits-child", "missing"} {
			t.Run(table+"/"+fault, func(t *testing.T) {
				var baseline int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&baseline))
				tx, err := r.runtime.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				// Положительная команда в той же TX становится свидетелем полного отката.
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
				require.NoError(t, err)
				nonce, id, payload := nativeDeleteReceiptClaim(t, r, tx)
				_, err = tx.Exec(r.ctx, `SELECT kaname.test_native_delete_custody_fault_v4($1,$2,$3)`, table, fault, r.role)
				require.NoError(t, err)
				_, err = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) SELECT $2,'fga.tuple.delete',$3::jsonb,kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
				forwardReceiptDenied(t, err)
				require.NoError(t, tx.Rollback(r.ctx))
				var after, anchors int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&after))
				require.Equal(t, baseline, after, "весь caller откатился вместе с прежним успешным INSERT")
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_forward_emit_anchor_v4`).Scan(&anchors))
				require.Zero(t, anchors)
				// Следующая здоровая команда доказывает восстановление после порчи storage.
				recovery, err := r.runtime.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(recovery)
				_, err = recovery.Exec(r.ctx, `SELECT kaname.authority_native_delete_emit_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a)
				require.NoError(t, err)
				require.NoError(t, recovery.Rollback(r.ctx))
			})
		}
	}
}
