// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveOldProjectMatchUsesWholeChildAndOwner(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const rules = `[{"module":"iam","resources":["account"],"verbs":["get"],"resource_names":["acc-graph"],
		"children":[{"resources":["project"],"verbs":["get"],"match_labels":{"team":"blue","stage":"prod"}}]}]`
	const account = `{"id":"acc-graph","labels":{},"access_labels":{}}`
	const mirror = `{"object_type":"iam.project","object_id":"prj-child","parent_account_id":"acc-graph","parent_project_id":"",
		"labels":{"team":"blue","stage":"prod","excluded":"value"}}`
	for _, test := range []struct {
		name   string
		scope  string
		target string
		mirror string
		match  bool
	}{
		{"контейнер в конечной цели", `["account","acc-graph"]`, `{"resources":[{"type":"iam.account","id":"acc-graph"}]}`, mirror, true},
		{"цель называет ребёнка", `["account","acc-graph"]`, `{"resources":[{"type":"iam.project","id":"prj-child"}]}`, mirror, false},
		{"контейнер вне области", `["account","acc-foreign"]`, `{"allInScope":true}`, mirror, false},
		{"частичное совпадение", `["account","acc-graph"]`, `{"allInScope":true}`,
			`{"object_type":"iam.project","object_id":"prj-child","parent_account_id":"acc-graph","parent_project_id":"","labels":{"team":"blue"}}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pairs []byte
			err := r.admin.QueryRow(r.ctx, `SELECT kaname._authority_role_move_old_project_match_v1(
				$1::jsonb,0,0,$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb,'prj-child','acc-graph')`,
				rules, test.scope, test.target, account, test.mirror).Scan(&pairs)
			require.NoError(t, err)
			if test.match {
				require.JSONEq(t, `{"team":"blue","stage":"prod"}`, string(pairs))
			} else {
				require.Nil(t, pairs)
			}
		})
	}
	var pairs []byte
	err := r.admin.QueryRow(r.ctx, `SELECT kaname._authority_role_move_old_project_match_v1(
		$1::jsonb,0,-1,'["account","acc-graph"]'::jsonb,'{"allInScope":true}'::jsonb,
		$2::jsonb,$3::jsonb,'prj-child','acc-graph')`, rules, account, mirror).Scan(&pairs)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "42501", pgErr.Code)
}

func TestRoleSelectorMoveProjectCopyPairsFollowEligibleBindings(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const source = `{"positions":[
		{"rule_index":0,"child_index":0,"binding_id":"b-first","pairs":{"stage":"prod","tier":"silver"}},
		{"rule_index":0,"child_index":0,"binding_id":"b-second","pairs":{"stage":"prod","tier":"silver"}},
		{"rule_index":0,"child_index":1,"binding_id":"b-third","pairs":{"team":"blue"}}
	]}`
	for _, test := range []struct {
		name    string
		holders string
		pairs   string
	}{
		{"первый источник истёк", `{"b-second":{"class":"PENDING"},"b-third":{"class":"ACTIVE"}}`,
			`{"stage":"prod","tier":"silver","team":"blue"}`},
		{"ни одного источника позиции", `{"b-third":{"class":"ACTIVE"}}`, `{"team":"blue"}`},
		{"все выдачи истекли", `{}`, `{}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var pairs []byte
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_role_move_project_copy_pairs_v1(
				$1::jsonb,$2::jsonb,100)->'pairs'`, source, test.holders).Scan(&pairs))
			require.JSONEq(t, test.pairs, string(pairs))
		})
	}
}

func TestRoleSelectorMoveProjectCopyDerivesAllMatchingHolders(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const graph = `{
		"project_id":"prj-child","native":["1","(0,1)",{"account_id":"acc-a"}],
		"graph":{"present":true,"current_accounts":["acc-a"],"current_project":"",
			"projection":{"object_type":"iam.project","object_id":"prj-child","parent_account_id":"acc-a",
				"parent_project_id":"","labels":{"stage":"mirror","team":"blue"}},
			"ancestors":[
				{"object_type":"iam.account","object_id":"acc-a","present":true,
					"projection":{"id":"acc-a","labels":{},"access_labels":{}}},
				{"object_type":"iam.account","object_id":"acc-b","present":true,
					"projection":{"id":"acc-b","labels":{},"access_labels":{}}}
			]}}`
	const role = `{
		"live":true,"is_system":false,"account_id":"acc-a",
		"rules":[{"module":"iam","resources":["account"],"verbs":["get"],"resource_names":["acc-a"],
			"children":[{"resources":["project"],"verbs":["get"],"match_labels":{"stage":"mirror","team":"blue"}}]}]
	}`
	const holders = `{
		"b-active":{"class":"ACTIVE","scope":["account","acc-a"],"target":{"resources":[{"type":"iam.account","id":"acc-a"}]}},
		"b-backup":{"class":"PENDING","scope":["cluster","cluster_root"],"target":{"allInScope":true}},
		"b-other-owner":{"class":"ACTIVE","scope":["cluster","cluster_root"],"target":{"resources":[{"type":"iam.account","id":"acc-b"}]}},
		"b-other-scope":{"class":"ACTIVE","scope":["account","acc-b"],"target":{"allInScope":true}},
		"b-child-target":{"class":"ACTIVE","scope":["account","acc-a"],"target":{"resources":[{"type":"iam.project","id":"prj-child"}]}}
	}`
	const moves = `[{"rule_index":0,"child_index":0}]`
	const positions = `SELECT kaname._authority_role_move_project_copy_support_v1(
		$1::jsonb,$2::jsonb,$3::jsonb,$4,$5::jsonb,$6)->'positions'`
	var result []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, positions, graph, role, moves, false, holders, 1000).Scan(&result))
	require.JSONEq(t, `[
		{"rule_index":0,"child_index":0,"binding_id":"b-active","pairs":{"stage":"mirror","team":"blue"}},
		{"rule_index":0,"child_index":0,"binding_id":"b-backup","pairs":{"stage":"mirror","team":"blue"}}
	]`, string(result))

	_, err := r.admin.Exec(r.ctx, positions, graph, role, moves, false, "{}", 1000)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "40001", pgErr.Code)

	_, err = r.admin.Exec(r.ctx, positions, graph, role, moves, false, holders, 6)
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "54000", pgErr.Code)
}
