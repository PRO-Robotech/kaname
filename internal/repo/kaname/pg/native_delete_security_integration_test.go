// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

var nativeDeleteSecuritySignatures = []string{
	"authority_native_delete_emit_v4(jsonb[])",
	"authority_native_delete_prepare_v4(jsonb[])",
	"authority_native_delete_stamp_v4(uuid,bigint,jsonb)",
}

func nativeDeleteSecurityReady(t *testing.T, r protocolRig) {
	t.Helper()
	var ready bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_crud_storage_v3()`).Scan(&ready))
	require.True(t, ready, "kaname#1034: положительный baseline и восстановление readiness")
}

// kaname#1034: реальный LOGIN получает все три новые двери, PUBLIC не получает
// ни одну. Private ABI проверяется отдельно от наличия легитимного runtime ACL.
func TestNativeDeleteSecurityExportsAndPrivateACL(t *testing.T) {
	r := writerProtocolRig(t)
	nativeDeleteSecurityReady(t, r)
	for _, signature := range nativeDeleteSecuritySignatures {
		var allowed, public bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE'),EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid=to_regprocedure('kaname.'||$1) AND a.grantee=0 AND a.privilege_type='EXECUTE')`, signature).Scan(&allowed, &public))
		require.True(t, allowed, signature)
		require.False(t, public, signature)
	}
	for _, signature := range forwardReceiptSignatures {
		if !strings.HasPrefix(signature, "_") {
			continue
		}
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE')`, signature).Scan(&allowed))
		require.False(t, allowed, signature)
	}
	for _, statement := range []string{
		`UPDATE pg_temp.kaname_forward_program_v4 SET phase='finished'`,
		`UPDATE pg_temp.kaname_forward_receipts_v4 SET guarded=true,consumed=true`,
		`DELETE FROM pg_temp.kaname_forward_effects_v4`,
		`DELETE FROM kaname.authority_forward_emit_anchor_v4`,
		`SELECT kaname._authority_forward_row_v4(1,'{}'::jsonb,false)`,
	} {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		_, _, _ = nativeDeleteReceiptClaim(t, r, tx)
		_, err = tx.Exec(r.ctx, statement)
		forwardReceiptDenied(t, err)
		require.NoError(t, tx.Rollback(r.ctx))
	}
}

// kaname#1034: каждая дверь входит в transitive readiness по телу, ABI,
// SECURITY и search_path. Административная порча всегда откатывается целиком.
func TestNativeDeleteSecurityReadinessMutationAndRecovery(t *testing.T) {
	r := writerProtocolRig(t)
	nativeDeleteSecurityReady(t, r)
	for _, signature := range nativeDeleteSecuritySignatures {
		t.Run(signature, func(t *testing.T) {
			for _, fault := range []string{"body", "strict", "security", "search-path", "public-acl"} {
				t.Run(fault, func(t *testing.T) {
					tx, err := r.admin.Begin(r.ctx)
					require.NoError(t, err)
					defer attestationLocksetRollback(tx)
					statement := "ALTER FUNCTION kaname." + signature
					switch fault {
					case "body":
						var definition string
						require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_get_functiondef(to_regprocedure('kaname.'||$1))`, signature).Scan(&definition))
						statement = strings.Replace(definition, "AS $function$", "AS $function$\n-- kaname#1034: изменено actual prosrc\n", 1)
						require.NotEqual(t, definition, statement, "мутация обязана менять тело")
					case "strict":
						statement += " STRICT"
					case "security":
						if strings.HasPrefix(signature, "authority_native_delete_emit_") {
							statement += " SECURITY DEFINER"
						} else {
							statement += " SECURITY INVOKER"
						}
					case "search-path":
						statement += " SET search_path=pg_catalog,kaname,pg_temp"
					case "public-acl":
						statement = "GRANT EXECUTE ON FUNCTION kaname." + signature + " TO PUBLIC"
					}
					_, err = tx.Exec(r.ctx, statement)
					require.NoError(t, err)
					var ready bool
					require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&ready))
					require.False(t, ready, statement)
					require.NoError(t, tx.Rollback(r.ctx))
					nativeDeleteSecurityReady(t, r)
				})
			}
		})
	}
}

// kaname#1034: readiness запрещает лишние права, но не обещает обнаружить
// отсутствие runtime grant. Проверяем сам ACL и actual permission error LOGIN.
func TestNativeDeleteSecurityRevokedRuntimeExecute(t *testing.T) {
	r := writerProtocolRig(t)
	for _, signature := range nativeDeleteSecuritySignatures {
		t.Run(signature, func(t *testing.T) {
			grant := "GRANT EXECUTE ON FUNCTION kaname." + signature + " TO " + pgx.Identifier{r.role}.Sanitize()
			_, err := r.admin.Exec(r.ctx, "REVOKE EXECUTE ON FUNCTION kaname."+signature+" FROM "+pgx.Identifier{r.role}.Sanitize())
			require.NoError(t, err)
			// DDL должен быть видим отдельному LOGIN, поэтому восстановление ACL
			// выполняется явно после rollback его отказавшей транзакции.
			defer func() {
				_, restoreErr := r.admin.Exec(r.ctx, grant)
				require.NoError(t, restoreErr)
			}()
			var allowed bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE')`, signature).Scan(&allowed))
			require.False(t, allowed, signature)
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			if strings.HasPrefix(signature, "authority_native_delete_stamp_") {
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_stamp_v4('00000000-0000-0000-0000-000000000001',1,'{}'::jsonb)`)
			} else {
				name, _, _ := strings.Cut(signature, "(")
				_, err = tx.Exec(r.ctx, `SELECT kaname.`+name+`(ARRAY[`+forwardReceiptPayload+`])`, r.a)
			}
			forwardReceiptDenied(t, err)
			var permission *pgconn.PgError
			require.ErrorAs(t, err, &permission)
			require.Contains(t, permission.Message, "permission denied for function", "отказ ACL должен предшествовать телу функции")
			require.NoError(t, tx.Rollback(r.ctx))
			_, err = r.admin.Exec(r.ctx, grant)
			require.NoError(t, err)
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,to_regprocedure('kaname.'||$1),'EXECUTE')`, signature).Scan(&allowed))
			require.True(t, allowed, signature)
			nativeDeleteSecurityReady(t, r)
		})
	}
}

func nativeDeleteSecurityBusinessState(t *testing.T, r protocolRig) string {
	t.Helper()
	var state string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'accounts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.accounts x),
 'groups',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.groups x),
 'memberships',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.memberships x),
 'bindings',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.access_bindings x),
 'emitted',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.access_binding_emitted_tuples x),
 'outbox',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.fga_outbox x))::text`).Scan(&state))
	return state
}

// kaname#1034: отказ проверяется именно на COMMIT без последующего INSERT или
// finish. Постоянный anchor обязан пережить уничтожение private temp storage.
func TestNativeDeleteSecurityIncompleteCommandsCannotCommit(t *testing.T) {
	for _, stage := range []string{"prepared", "claimed", "stamped-without-insert", "inserted-without-finish", "temp-drop-before-commit", "discard-temp-before-commit", "finish-before-insert"} {
		t.Run(stage, func(t *testing.T) {
			r := writerProtocolRig(t)
			if stage == "temp-drop-before-commit" {
				forwardReceiptFaultDoor(t, r)
			}
			before := nativeDeleteSecurityBusinessState(t, r)
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			var nonce, payload string
			var id int64
			if stage == "prepared" {
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_native_delete_prepare_v4(ARRAY[`+forwardReceiptPayload+`])`, r.a).Scan(&nonce))
			} else {
				nonce, id, payload = nativeDeleteReceiptClaim(t, r, tx)
			}
			switch stage {
			case "stamped-without-insert":
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
				require.NoError(t, err)
			case "inserted-without-finish", "temp-drop-before-commit", "discard-temp-before-commit":
				_, err = tx.Exec(r.ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) SELECT $2,'fga.tuple.delete',$3::jsonb,kaname.authority_native_delete_stamp_v4($1::uuid,$2,$3::jsonb)`, nonce, id, payload)
				require.NoError(t, err)
				if stage == "temp-drop-before-commit" {
					_, err = tx.Exec(r.ctx, `SELECT kaname.test_forward_receipt_fault_v4('temp-drop',$1::uuid)`, nonce)
					require.NoError(t, err)
				}
				if stage == "discard-temp-before-commit" {
					_, err = tx.Exec(r.ctx, `DISCARD TEMP`)
					require.NoError(t, err)
				}
			case "finish-before-insert":
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
				forwardReceiptDenied(t, err)
				require.NoError(t, tx.Rollback(r.ctx))
			}
			if stage != "finish-before-insert" {
				forwardReceiptDenied(t, tx.Commit(r.ctx))
			}
			require.Equal(t, before, nativeDeleteSecurityBusinessState(t, r), "отказ не меняет бизнес-строки и outbox")
			var anchors int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_forward_emit_anchor_v4`).Scan(&anchors))
			require.Zero(t, anchors)
		})
	}
}

// kaname#1034: обе двери, способные резервировать sequence, сохраняют исходные
// privilege/signed guards. Двойные faults проверяют отказ до nextval без
// зависимости от текста ошибки или выбранной реализации precedence.
func TestNativeDeleteSecurityOriginalPrivilegesBeforeReservation(t *testing.T) {
	for _, name := range []string{"authority_native_delete_prepare_v4", "authority_native_delete_emit_v4"} {
		for _, scenario := range []string{"sequence-privilege", "table-privilege", "foreign-temp", "sequence-and-foreign-temp", "table-and-foreign-temp", "signed", "strict-unsigned"} {
			t.Run(name+"/"+scenario, func(t *testing.T) {
				r := writerProtocolRig(t)
				if strings.HasPrefix(scenario, "sequence-") {
					_, err := r.admin.Exec(r.ctx, `REVOKE USAGE,UPDATE ON SEQUENCE kaname.fga_outbox_id_seq FROM `+pgx.Identifier{r.role}.Sanitize())
					require.NoError(t, err)
				}
				if strings.HasPrefix(scenario, "table-") {
					_, err := r.admin.Exec(r.ctx, `REVOKE INSERT ON kaname.fga_outbox FROM `+pgx.Identifier{r.role}.Sanitize())
					require.NoError(t, err)
				}
				if scenario == "signed" || scenario == "strict-unsigned" {
					r.strict(t)
				}
				tx, err := r.runtime.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				if scenario == "signed" {
					r.enter(t, tx, r.intent(r.a), "decision")
				}
				if strings.Contains(scenario, "foreign-temp") {
					_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_forward_program_v4(junk integer)`)
					require.NoError(t, err)
				}
				var before, after string
				const sequence = `SELECT jsonb_build_object('last_value',s.last_value,'log_cnt',s.log_cnt,'is_called',s.is_called)::text FROM kaname.fga_outbox_id_seq s`
				require.NoError(t, r.admin.QueryRow(r.ctx, sequence).Scan(&before))
				_, err = tx.Exec(r.ctx, `SELECT kaname.`+name+`(ARRAY[`+forwardReceiptPayload+`])`, r.a)
				forwardReceiptDenied(t, err)
				require.NoError(t, tx.Rollback(r.ctx))
				require.NoError(t, r.admin.QueryRow(r.ctx, sequence).Scan(&after))
				require.Equal(t, before, after, "отказ до nextval, включая совместные privilege и foreign-temp faults")
			})
		}
	}
}
