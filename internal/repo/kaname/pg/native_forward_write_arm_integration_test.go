// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Два настоящих mirror объекта; остальные fixtures и public producer исходные.
func nativeWriteArmFixture(t *testing.T) (protocolRig, []string) {
	t.Helper()
	r := writerProtocolRig(t)
	nativeFallbackReader(t, r)
	payloads := make([]string, 2)
	for i, id := range []string{"native-arm-01", "native-arm-02"} {
		_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,labels) VALUES('compute.instance',$1,$2,'{}'::jsonb)`, id, r.a)
		require.NoError(t, err)
		raw, err := json.Marshal(map[string]any{"object": "compute_instance:" + id, "user": "user:usr_" + id, "relations": []string{"v_update", "editor", "v_get", "v_delete"}})
		require.NoError(t, err)
		payloads[i] = string(raw)
	}
	_, err := r.admin.Exec(r.ctx, `GRANT SET ON PARAMETER track_functions TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	return r, payloads
}

func nativeWriteArmState(t *testing.T, ctx context.Context, tx pgx.Tx, nonce string) bool {
	t.Helper()
	_, raw := nativeFallbackImage(t, ctx, tx)
	var image struct {
		Anchors []struct {
			Nonce    string         `json:"nonce"`
			Required bool           `json:"write_required"`
			Batch    map[string]any `json:"write_batch"`
		} `json:"anchors"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &image))
	for _, a := range image.Anchors {
		if a.Nonce == nonce {
			if a.Required {
				require.Equal(t, "armed", a.Batch["phase"])
			}
			return a.Required
		}
	}
	t.Fatalf("prepared nonce отсутствует в actual anchor: %s", nonce)
	return false
}

func nativeWriteArmPrepare(t *testing.T, r protocolRig, ctx context.Context, tx pgx.Tx, payloads []string) string {
	t.Helper()
	var nonce string
	require.NoError(t, tx.QueryRow(ctx, `SELECT kaname.authority_forward_prepare_v4($1::jsonb[])`, payloads).Scan(&nonce))
	_, err := tx.Exec(ctx, `SELECT kaname.authority_native_write_arm_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	return nonce
}

// Отсутствие новой capability и column-only прежние права не изменяют public API.
// Whole-command fallback измеряется actual callbacks, но semantic/rollback checks идут первыми.
func TestNativeForwardWriteArmPreservesGenericFallbacks(t *testing.T) {
	r, payloads := nativeWriteArmFixture(t)
	for _, name := range []string{"missing_arm_execute", "column_select_only", "existing_fact", "duplicate_key", "explicit_version"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
			defer cancel()
			role := pgx.Identifier{r.role}.Sanitize()
			if name == "missing_arm_execute" {
				_, err := r.admin.Exec(ctx, `REVOKE EXECUTE ON FUNCTION kaname.authority_native_write_arm_v4(uuid) FROM `+role)
				require.NoError(t, err)
				defer func() {
					_, e := r.admin.Exec(context.WithoutCancel(ctx), `GRANT EXECUTE ON FUNCTION kaname.authority_native_write_arm_v4(uuid) TO `+role)
					require.NoError(t, e)
				}()
			}
			if name == "column_select_only" {
				_, err := r.admin.Exec(ctx, `REVOKE SELECT ON kaname.relation_fact FROM `+role+`; GRANT SELECT(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params) ON kaname.relation_fact TO `+role)
				require.NoError(t, err)
				defer func() {
					_, e := r.admin.Exec(context.WithoutCancel(ctx), `REVOKE SELECT(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params) ON kaname.relation_fact FROM `+role+`; GRANT SELECT ON kaname.relation_fact TO `+role)
					require.NoError(t, e)
				}()
			}
			tx, err := r.runtime.Begin(ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			nativeFallbackLimits(t, ctx, tx)
			_, err = tx.Exec(ctx, `SET LOCAL track_functions='all'`)
			require.NoError(t, err)
			if name == "missing_arm_execute" {
				var granted bool
				require.NoError(t, tx.QueryRow(ctx, `SELECT has_function_privilege(current_user,'kaname.authority_native_write_arm_v4(uuid)','EXECUTE')`).Scan(&granted))
				require.False(t, granted)
			}
			if name == "column_select_only" {
				var table, column bool
				require.NoError(t, tx.QueryRow(ctx, `SELECT has_table_privilege(current_user,'kaname.relation_fact','SELECT'),has_column_privilege(current_user,'kaname.relation_fact','source_version','SELECT')`).Scan(&table, &column))
				require.False(t, table)
				require.True(t, column)
			}
			_, baseline := nativeFallbackImage(t, ctx, tx)
			input := append([]string(nil), payloads...)
			if name == "existing_fact" {
				_, err = tx.Exec(ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('compute_instance','native-arm-01','editor','user:usr_native-arm-01')`)
				require.NoError(t, err)
			}
			if name == "duplicate_key" {
				input[1] = input[0]
			}
			if name == "explicit_version" {
				var v map[string]any
				require.NoError(t, json.Unmarshal([]byte(input[0]), &v))
				v["source_version"] = "2026-11-01T00:00:00Z"
				b, e := json.Marshal(v)
				require.NoError(t, e)
				input[0] = string(b)
			}
			start := nativeBatchPolicyCalls(t, ctx, tx)
			_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4($1::jsonb[])`, input)
			require.NoError(t, err)
			calls := nativeBatchPolicyCalls(t, ctx, tx) - start
			var events, facts int
			require.NoError(t, tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user' LIKE 'user:usr_native-arm-%'),(SELECT count(*) FROM kaname.relation_fact WHERE object_type='compute_instance' AND object_id IN('native-arm-01','native-arm-02'))`).Scan(&events, &facts))
			require.Equal(t, 2, events)
			wantFacts := 2
			if name == "duplicate_key" {
				wantFacts = 1
			}
			if name == "explicit_version" {
				wantFacts = 5
			}
			require.Equal(t, wantFacts, facts)
			_, image := nativeFallbackImage(t, ctx, tx)
			var state struct {
				Anchors []struct {
					Required bool `json:"write_required"`
				} `json:"anchors"`
			}
			require.NoError(t, json.Unmarshal([]byte(image), &state))
			require.Len(t, state.Anchors, 1)
			require.False(t, state.Anchors[0].Required)
			_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback(ctx))
			outside, e := r.admin.Begin(ctx)
			require.NoError(t, e)
			defer attestationLocksetRollback(outside)
			_, after := nativeFallbackImage(t, ctx, outside)
			require.JSONEq(t, baseline, after)
			require.NoError(t, outside.Rollback(ctx))
			// Owner-versioned input сохраняет три native verbs: historical filter применяется только без source_version.
			wantCalls := int64(5)
			if name == "explicit_version" {
				wantCalls = 11
			}
			require.Equal(t, wantCalls, calls, "whole generic fallback сохраняет исходное effective relation множество")
		})
	}
}

// Metadata corruption вводится owner-ом явно между командами, без guard disable,
// replacement canonical bodies или EXECUTE grants к private helpers.
func TestNativeForwardWriteArmRejectsPartialReplayAndInterference(t *testing.T) {
	r, payloads := nativeWriteArmFixture(t)
	for _, name := range []string{"foreign_nonce", "replay", "partial", "overlap", "same_backend_fact", "corrupt_digest", "lost_required"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
			defer cancel()
			tx, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			nativeFallbackLimits(t, ctx, tx)
			_, baseline := nativeFallbackImage(t, ctx, tx)
			role := pgx.Identifier{r.role}.Sanitize()
			_, err = tx.Exec(ctx, `SET LOCAL ROLE `+role+`; SET LOCAL search_path=pg_catalog,pg_temp; SAVEPOINT arm_fault`)
			require.NoError(t, err)
			var principal string
			require.NoError(t, tx.QueryRow(ctx, `SELECT current_user`).Scan(&principal))
			require.Equal(t, r.role, principal)
			nonce := nativeWriteArmPrepare(t, r, ctx, tx, payloads)
			require.True(t, nativeWriteArmState(t, ctx, tx, nonce), "fault должен затронуть реально armed command")
			switch name {
			case "foreign_nonce":
				_, err = tx.Exec(ctx, `SELECT kaname.authority_native_write_arm_v4('00000000-0000-0000-0000-000000000001'::uuid)`)
			case "replay":
				_, err = tx.Exec(ctx, `SELECT kaname.authority_native_write_arm_v4($1::uuid)`, nonce)
			case "overlap":
				var second string
				require.NoError(t, tx.QueryRow(ctx, `SELECT kaname.authority_forward_prepare_v4($1::jsonb[])`, payloads).Scan(&second))
				_, err = tx.Exec(ctx, `SELECT kaname.authority_native_write_arm_v4($1::uuid)`, second)
			case "same_backend_fact":
				_, err = tx.Exec(ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('compute_instance','native-arm-01','editor','user:usr_native-arm-01')`)
			case "corrupt_digest", "lost_required":
				_, e := tx.Exec(ctx, `RESET ROLE`)
				require.NoError(t, e)
				if name == "corrupt_digest" {
					_, e = tx.Exec(ctx, `UPDATE kaname.authority_forward_emit_anchor_v4 SET write_batch=jsonb_set(write_batch,'{digest}','"bad"'::jsonb) WHERE nonce=$1::uuid`, nonce)
				} else {
					_, e = tx.Exec(ctx, `UPDATE kaname.authority_forward_emit_anchor_v4 SET write_required=false WHERE nonce=$1::uuid`, nonce)
				}
				require.NoError(t, e)
				_, e = tx.Exec(ctx, `SET LOCAL ROLE `+role)
				require.NoError(t, e)
				_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) SELECT * FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce)
			case "partial":
				rows, e := tx.Query(ctx, `SELECT id,payload::text,created_at FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce)
				require.NoError(t, e)
				var id int64
				var payload string
				var at time.Time
				count := 0
				for rows.Next() {
					var nextID int64
					var nextPayload string
					var nextAt time.Time
					require.NoError(t, rows.Scan(&nextID, &nextPayload, &nextAt))
					if count == 0 {
						id = nextID
						payload = nextPayload
						at = nextAt
					}
					count++
				}
				require.NoError(t, rows.Err())
				rows.Close()
				require.Equal(t, 2, count)
				_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) VALUES($1,'fga.tuple.write',$2::jsonb,$3)`, id, payload, at)
			}
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			if name == "partial" {
				require.Equal(t, "native write whole journal transition differs", pe.Message)
			}
			if name == "same_backend_fact" {
				require.Equal(t, "native write policy invocation changed", pe.Message)
			}
			if name == "corrupt_digest" || name == "lost_required" {
				require.Equal(t, "native write immutable obligations changed", pe.Message)
			}
			_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT arm_fault`)
			require.NoError(t, err)
			_, after := nativeFallbackImage(t, ctx, tx)
			require.JSONEq(t, baseline, after)
			require.NoError(t, tx.Rollback(ctx))
			outside, e := r.admin.Begin(ctx)
			require.NoError(t, e)
			defer attestationLocksetRollback(outside)
			_, after = nativeFallbackImage(t, ctx, outside)
			require.JSONEq(t, baseline, after)
			require.NoError(t, outside.Rollback(ctx))
		})
	}
}

// Busy epoch не создаёт новую early wait/error lane. NOWAIT fallback откатывает
// также уже взятый root SHARE; actual generic statement выполняется после release.
func TestNativeForwardWriteArmBusyEpochFallsBackWithoutLeakingLocks(t *testing.T) {
	r, payloads := nativeWriteArmFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	holder, err := r.admin.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(holder)
	var key string
	require.NoError(t, holder.QueryRow(ctx, `SELECT key FROM kaname.authority_policy_epoch WHERE key=$1 FOR UPDATE`, "scope:"+r.a).Scan(&key))
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nativeFallbackLimits(t, ctx, tx)
	_, err = tx.Exec(ctx, `SET LOCAL track_functions='all'`)
	require.NoError(t, err)
	_, baseline := nativeFallbackImage(t, ctx, tx)
	nonce := nativeWriteArmPrepare(t, r, ctx, tx, payloads)
	require.False(t, nativeWriteArmState(t, ctx, tx, nonce))
	require.NoError(t, holder.QueryRow(ctx, `SELECT key FROM kaname.authority_policy_epoch WHERE key='*' FOR UPDATE NOWAIT`).Scan(&key), "root SHARE из speculative subtransaction не должен утечь")
	require.NoError(t, holder.Rollback(ctx))
	start := nativeBatchPolicyCalls(t, ctx, tx)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) SELECT * FROM kaname.authority_forward_claim_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	calls := nativeBatchPolicyCalls(t, ctx, tx) - start
	_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	require.NoError(t, err)
	var count int
	require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='compute_instance' AND object_id IN('native-arm-01','native-arm-02')`).Scan(&count))
	require.Equal(t, 2, count)
	require.NoError(t, tx.Rollback(ctx))
	outside, e := r.admin.Begin(ctx)
	require.NoError(t, e)
	defer attestationLocksetRollback(outside)
	_, after := nativeFallbackImage(t, ctx, outside)
	require.JSONEq(t, baseline, after)
	require.NoError(t, outside.Rollback(ctx))
	require.Equal(t, int64(5), calls)
}

// Overflow fallback возникает ПОСЛЕ успешных NOWAIT acquisitions. Отдельная
// fixture повышает existing scope монотонно; старое значение не восстанавливается
// запрещённым decrease. Её штатное уничтожение удаляет эту TEST database.
func TestNativeForwardWriteArmOverflowFallbackReleasesAllLocks(t *testing.T) {
	r, payloads := nativeWriteArmFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
	defer cancel()
	// Положительный контроль исключает ложный успех always-generic/closure отказа.
	positive, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(positive)
	nativeFallbackLimits(t, ctx, positive)
	nonce := nativeWriteArmPrepare(t, r, ctx, positive, payloads)
	require.True(t, nativeWriteArmState(t, ctx, positive, nonce))
	require.NoError(t, positive.Rollback(ctx))
	const maximum int64 = 9223372036854775807
	scope := "scope:" + r.a
	var originalRevision int64
	var originalGeneration string
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT revision,generation FROM kaname.authority_policy_epoch WHERE key=$1`, scope).Scan(&originalRevision, &originalGeneration))
	require.Less(t, originalRevision, maximum)
	tag, err := r.admin.Exec(ctx, `UPDATE kaname.authority_policy_epoch SET revision=$2 WHERE key=$1`, scope, maximum)
	require.NoError(t, err)
	require.Equal(t, int64(1), tag.RowsAffected())
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	nativeFallbackLimits(t, ctx, tx)
	var login, session string
	require.NoError(t, tx.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&login, &session))
	require.Equal(t, r.role, login)
	require.Equal(t, r.role, session)
	epochs, baseline := nativeFallbackImage(t, ctx, tx)
	require.Equal(t, maximum, epochs[scope].Revision)
	require.Equal(t, originalGeneration, epochs[scope].Generation)
	nonce = nativeWriteArmPrepare(t, r, ctx, tx, payloads)
	require.False(t, nativeWriteArmState(t, ctx, tx, nonce), "actual overflow обязан отказаться от arm")
	// Обе строки теперь должны быть доступны ДРУГОМУ backend без ожидания.
	probe, err := r.admin.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(probe)
	nativeFallbackLimits(t, ctx, probe)
	var key string
	require.NoError(t, probe.QueryRow(ctx, `SELECT key FROM kaname.authority_policy_epoch WHERE key='*' FOR UPDATE NOWAIT`).Scan(&key))
	require.Equal(t, "*", key)
	var revision int64
	var generation string
	require.NoError(t, probe.QueryRow(ctx, `SELECT key,revision,generation FROM kaname.authority_policy_epoch WHERE key=$1 FOR UPDATE NOWAIT`, scope).Scan(&key, &revision, &generation))
	require.Equal(t, scope, key)
	require.Equal(t, maximum, revision)
	require.Equal(t, originalGeneration, generation)
	require.NoError(t, probe.Rollback(ctx))
	// Generic business INSERT намеренно не выполняется: его overflow не является
	// предметом этого lock-release свидетеля. Prepared state целиком откатывается.
	require.NoError(t, tx.Rollback(ctx))
	outside, err := r.admin.Begin(ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(outside)
	_, after := nativeFallbackImage(t, ctx, outside)
	require.JSONEq(t, baseline, after)
	require.NoError(t, outside.Rollback(ctx))
}
