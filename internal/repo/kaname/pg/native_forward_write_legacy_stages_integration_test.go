// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Старые prepare/claim не принимают новый whole-command контракт автоматически.
// Проверяем настоящий LOGIN, частичные INSERT и intervening native command.
func TestNativeForwardLegacyStagesPreservePartialAndNestedCommands(t *testing.T) {
	r := writerProtocolRig(t)
	nativeFallbackReader(t, r)
	users := []string{"user:usr_native_write_legacy_01", "user:usr_native_write_legacy_02"}
	payloads := make([]string, len(users))
	for i, user := range users {
		raw, err := json.Marshal(map[string]any{"object": "account:" + r.a, "user": user, "relations": []string{"v_get", "editor"}})
		require.NoError(t, err)
		payloads[i] = string(raw)
	}
	for _, nested := range []bool{false, true} {
		name := "partial_statements"
		if nested {
			name = "savepoint_then_nested_before_parent"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(r.ctx, 120*time.Second)
			defer cancel()
			tx, err := r.runtime.Begin(ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			nativeFallbackLimits(t, ctx, tx)
			privileges := nativeFallbackOriginalPrivileges(t, ctx, tx)
			before, baseline := nativeFallbackImage(t, ctx, tx)
			var nonce string
			require.NoError(t, tx.QueryRow(ctx, `SELECT kaname.authority_forward_prepare_v4($1::jsonb[])`, payloads).Scan(&nonce))
			type row struct {
				id      int64
				payload string
				at      time.Time
			}
			claimed := []row{}
			rows, err := tx.Query(ctx, `SELECT id,payload::text,created_at FROM kaname.authority_forward_claim_v4($1::uuid) ORDER BY id`, nonce)
			require.NoError(t, err)
			defer rows.Close()
			for rows.Next() {
				var item row
				require.NoError(t, rows.Scan(&item.id, &item.payload, &item.at))
				claimed = append(claimed, item)
			}
			require.NoError(t, rows.Err())
			rows.Close()
			require.Len(t, claimed, 2)
			_, staged := nativeFallbackImage(t, ctx, tx)
			var childEpochs map[string]nativeBatchEpoch
			var childFacts string
			if nested {
				_, err = tx.Exec(ctx, `SAVEPOINT legacy_parent_first_attempt`)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(id,event_type,payload,created_at) VALUES
     ($1,'fga.tuple.write',$2::jsonb,$3),($4,'fga.tuple.write',$5::jsonb,$6)`, claimed[0].id, claimed[0].payload, claimed[0].at, claimed[1].id, claimed[1].payload, claimed[1].at)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT legacy_parent_first_attempt`)
				require.NoError(t, err)
				_, restored := nativeFallbackImage(t, ctx, tx)
				require.JSONEq(t, staged, restored)
				_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_emit_v4($1::jsonb[])`, payloads)
				require.NoError(t, err)
				childEpochs, _ = nativeFallbackImage(t, ctx, tx)
				require.NoError(t, tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb)::text FROM kaname.relation_fact f WHERE object_type='account' AND object_id=$1 AND subject=ANY($2::text[])`, r.a, users).Scan(&childFacts))
			}
			for i, item := range claimed {
				// Отдельный actual INSERT для каждой строки ранее claimed команды допустим.
				require.NoError(t, forwardReceiptInsert(r, tx, item.id, item.payload, item.at))
				var count int
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE id=ANY($1::bigint[])`, []int64{claimed[0].id, claimed[1].id}).Scan(&count))
				require.Equal(t, i+1, count)
			}
			after, _ := nativeFallbackImage(t, ctx, tx)
			require.Equal(t, before["*"], after["*"])
			shared := before["scope:"+r.a]
			shared.Revision += 2
			require.Equal(t, shared, after["scope:"+r.a])
			for _, user := range users {
				require.Equal(t, int64(1), after[user].Revision)
			}
			var facts, badFacts, events, badEvents int
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE relation<>'editor' OR source_version<>transaction_timestamp() OR created_at<>transaction_timestamp() OR condition_name<>'' OR condition_params<>'{}'::jsonb) FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND subject=ANY($2::text[])`, r.a, users).Scan(&facts, &badFacts))
			require.Equal(t, 2, facts)
			require.Zero(t, badFacts)
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE event_type<>'fga.tuple.write' OR created_at<>transaction_timestamp()) FROM kaname.fga_outbox WHERE payload->>'user'=ANY($1::text[])`, users).Scan(&events, &badEvents))
			wantEvents := 2
			if nested {
				wantEvents = 4
			}
			require.Equal(t, wantEvents, events)
			require.Zero(t, badEvents)
			if nested {
				require.Equal(t, childEpochs, after, "повторная equal-version parent запись не меняет policy metadata")
				var parentFacts string
				require.NoError(t, tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY to_jsonb(f)::text),'[]'::jsonb)::text FROM kaname.relation_fact f WHERE object_type='account' AND object_id=$1 AND subject=ANY($2::text[])`, r.a, users).Scan(&parentFacts))
				require.JSONEq(t, childFacts, parentFacts)
			}
			_, err = tx.Exec(ctx, `SELECT kaname.authority_forward_finish_v4($1::uuid)`, nonce)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
			require.NoError(t, err)
			_, completedRaw := nativeFallbackImage(t, ctx, tx)
			var completed struct{ Anchors []json.RawMessage }
			require.NoError(t, json.Unmarshal([]byte(completedRaw), &completed))
			require.Empty(t, completed.Anchors)
			require.JSONEq(t, privileges, nativeFallbackOriginalPrivileges(t, ctx, tx))
			require.NoError(t, tx.Rollback(ctx))
			outer, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(outer)
			_, outside := nativeFallbackImage(t, ctx, outer)
			require.JSONEq(t, baseline, outside)
			require.NoError(t, outer.Rollback(ctx))
		})
	}
}
