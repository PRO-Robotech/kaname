// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Исполняется именно выражение установленного owner compiler, а не копия
// его алгоритма в тесте. Oracle отдельно фильтрует исходные строки по двум полям.
func TestBindingCaptureCoordinatePartitionsPreserveExactRows(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	var body string
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT prosrc FROM pg_catalog.pg_proc
 WHERE oid='kaname.authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)'::regprocedure`).Scan(&body))
	const begin = "-- НАЧАЛО разбиения coordinate"
	const end = "-- КОНЕЦ разбиения coordinate"
	require.Equal(t, 1, strings.Count(body, begin))
	require.Equal(t, 1, strings.Count(body, end))
	_, tail, ok := strings.Cut(body, begin)
	require.True(t, ok)
	expression, _, ok := strings.Cut(tail, end)
	require.True(t, ok)
	require.Equal(t, 1, strings.Count(expression, "INTO member_partitions,ledger_partitions;"))
	expression = strings.Replace(expression, "INTO member_partitions,ledger_partitions;", "", 1)
	require.Equal(t, 1, strings.Count(expression, "members->'states'"))
	require.Equal(t, 1, strings.Count(expression, "ledger->'states'"))
	expression = strings.Replace(expression, "members->'states'", "$1::jsonb", 1)
	expression = strings.Replace(expression, "ledger->'states'", "$2::jsonb", 1)
	for _, n := range []int{0, 257, 513} {
		t.Run(fmt.Sprintf("rows_%d", n), func(t *testing.T) {
			request, done := context.WithTimeout(r.ctx, 30*time.Second)
			defer done()
			members := make([]map[string]any, 0, n+8)
			ledger := make([]map[string]any, 0, n+8)
			add := func(typ, id, binding, status string, ordinal int) {
				members = append(members, map[string]any{"object_type": typ, "object_id": id, "binding_id": binding, "rule_fp": fmt.Sprint(ordinal), "verification_status": status})
				ledger = append(ledger, map[string]any{"member_object_type": typ, "member_object_id": id, "binding_id": binding, "fga_user": fmt.Sprint(ordinal), "relation": "viewer", "object": typ + ":" + id})
			}
			for i := 0; i < n; i++ {
				add("iam.group", fmt.Sprintf("g%d", i), "binding1", "ACTIVE", i)
			}
			if n > 0 {
				add("a:b", "c", "binding1", "REJECTED", n)
				add("a", "b:c", "binding2", "PENDING_VERIFICATION", n+1)
				add("iam.group", "g0", "binding2", "REJECTED", n+2)
				add("iam.group", "g0", "binding1", "PENDING_VERIFICATION", n+3)
				add("quote\"", "comma,[]", "binding2", "ACTIVE", n+4)
				add("foreign.type", "outside-census", "binding3", "ACTIVE", n+5)
				// Совпадающие строки нельзя потерять через DISTINCT или map overwrite.
				members = append(members, members[0])
				ledger = append(ledger, ledger[0])
			}
			encode := func(rows []map[string]any) []byte {
				states := make([]any, 0, len(rows))
				for i, row := range rows {
					states = append(states, []any{"1", fmt.Sprintf("(0,%d)", i+1), row})
				}
				raw, err := json.Marshal(states)
				require.NoError(t, err)
				return raw
			}
			var memberMap, ledgerMap json.RawMessage
			require.NoError(t, r.admin.QueryRow(request, expression, encode(members), encode(ledger)).Scan(&memberMap, &ledgerMap))
			compare := func(raw json.RawMessage, rows []map[string]any, typeField, idField string) {
				got := map[string]json.RawMessage{}
				require.NoError(t, json.Unmarshal(raw, &got))
				seen := map[string]bool{}
				total := 0
				for encoded, partition := range got {
					var pair []string
					require.NoError(t, json.Unmarshal([]byte(encoded), &pair))
					require.Len(t, pair, 2)
					key, err := json.Marshal(pair)
					require.NoError(t, err)
					require.False(t, seen[string(key)], "два map key не могут обозначать одну coordinate")
					seen[string(key)] = true
					want := make([]map[string]any, 0)
					for _, row := range rows {
						if row[typeField] == pair[0] && row[idField] == pair[1] {
							want = append(want, row)
						}
					}
					require.NotEmpty(t, want, "partition не создаёт посторонних coordinate")
					expected, err := json.Marshal(want)
					require.NoError(t, err)
					require.JSONEq(t, string(expected), string(partition), "порядок, multiplicity и все поля исходных строк")
					total += len(want)
				}
				require.Equal(t, len(rows), total, "включая чужие binding и строки вне будущего coordinate loop")
				for _, row := range rows {
					key, err := json.Marshal([]any{row[typeField], row[idField]})
					require.NoError(t, err)
					require.True(t, seen[string(key)], "исходная coordinate не потеряна")
				}
				require.NotContains(t, got, `["iam.group", "absent"]`, "отсутствие не заменяется чужим partition")
			}
			compare(memberMap, members, "object_type", "object_id")
			compare(ledgerMap, ledger, "member_object_type", "member_object_id")
			// Те же coalesce lookup возвращают [], но исходные maps остаются полными.
			var emptyMembers, emptyLedger string
			require.NoError(t, r.admin.QueryRow(request, `SELECT coalesce($1::jsonb->jsonb_build_array('iam.group','absent')::text,'[]'::jsonb)::text,
    coalesce($2::jsonb->jsonb_build_array('iam.group','absent')::text,'[]'::jsonb)::text`, memberMap, ledgerMap).Scan(&emptyMembers, &emptyLedger))
			require.JSONEq(t, "[]", emptyMembers)
			require.JSONEq(t, "[]", emptyLedger)
		})
	}
	t.Run("non_array_refuses", func(t *testing.T) {
		request, done := context.WithTimeout(r.ctx, 30*time.Second)
		defer done()
		var a, b json.RawMessage
		err := r.admin.QueryRow(request, expression, []byte(`{}`), []byte(`[]`)).Scan(&a, &b)
		require.Error(t, err, "неверный source не превращается в пустой inventory")
		var pgerr *pgconn.PgError
		require.ErrorAs(t, err, &pgerr)
		require.Equal(t, "22023", pgerr.Code)
	})
}
