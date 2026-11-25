// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestSelectorMoveRulesSQLPreservesUnselectedPaths(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен PostgreSQL")
	}
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	defer conn.Close(ctx)

	old := `[
		{"module":"storage","resources":["bucket"],"verbs":["get"],"match_labels":{"team":"red"},"resource_names":null,"created_by_subject":false,"children":[
			{"resources":["object"],"verbs":["get"],"match_labels":{"class":"public"},"resource_names":[]},
			{"resources":["version"],"verbs":["list"],"match_labels":{"archive":"live"}}
		]},
		{"module":"iam","resources":["project"],"verbs":["get"],"match_access_labels":{"team":"blue"}}
	]`
	want := `[
		{"module":"storage","resources":["bucket"],"verbs":["get"],"match_access_labels":{"team":"red"},"children":[
			{"resources":["object"],"verbs":["get"],"match_access_labels":{"class":"public"}},
			{"resources":["version"],"verbs":["list"],"match_labels":{"archive":"live"}}
		]},
		{"module":"iam","resources":["project"],"verbs":["get"],"match_access_labels":{"team":"blue"}}
	]`
	var proposed json.RawMessage
	var count int
	moves := `[{"rule_index":0,"child_index":0},{"rule_index":0,"child_index":-1}]`
	require.NoError(t, conn.QueryRow(ctx, selectorMoveRulesSQL, old, moves).Scan(&proposed, &count))
	require.Equal(t, 2, count)
	require.JSONEq(t, want, string(proposed))

	invalid := `[
		{"rule_index":0,"child_index":0},{"rule_index":0,"child_index":0},
		{"rule_index":0,"child_index":8},{"rule_index":1,"child_index":-1}
	]`
	require.NoError(t, conn.QueryRow(ctx, selectorMoveRulesSQL, old, invalid).Scan(&proposed, &count))
	require.Equal(t, 1, count, "дубликат, отсутствующий ребёнок и защищённый селектор не засчитываются")
}
