// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelSelectorCanonicalSQLMatchesDomain(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	rows := catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "account", ObjectType: "account"},
			{Module: "iam", Resource: "project", ObjectType: "project", ParentTypes: []string{"account"}, ParentNames: []string{"account"}},
		},
		Verbs: []catalog.VerbRow{
			{Module: "iam", Resource: "account", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "project", Verb: "get", PerObject: true},
		},
	}}
	facts, err := catalog.NewFacts(rows)
	require.NoError(t, err)
	catalogJSON, err := json.Marshal(rows)
	require.NoError(t, err)
	cases := map[string]domain.Rule{
		"legacy-anchor":    {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}},
		"legacy-labels":    {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}},
		"protected":        {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "a", "env": "prod"}},
		"protected-nested": {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"env": "prod"}, Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "a"}}}},
		"mixed-nested":     {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"env": "prod"}, Children: []domain.Rule{{Resources: []string{"project"}, Verbs: []string{"get"}, MatchAccessLabels: map[string]string{"team": "a"}}}},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			rules := domain.Rules{rule}
			stored, err := domain.EncodeRules(rules)
			require.NoError(t, err)
			raw, err := json.Marshal(rules)
			require.NoError(t, err)
			var encoded string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_encode_proposed_rules_v2($1::jsonb,false)::text`, raw).Scan(&encoded))
			require.JSONEq(t, string(stored), encoded)
			var fp string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_fingerprint_v2($1::jsonb->0,false)`, stored).Scan(&fp))
			require.Equal(t, rule.Fingerprint(), fp)
			for i, child := range rule.Children {
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_fingerprint_v2($1::jsonb->0->'children'->$2::integer,true)`, stored, i).Scan(&fp))
				require.Equal(t, child.Fingerprint(), fp)
			}
			expected, err := facts.ProjectGrantRules(rules, domain.TenantPolicy())
			require.NoError(t, err)
			var projected []byte
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_withdrawal_role_projection_v2('{"is_system":false,"owner_module":null}'::jsonb,$1::jsonb,$1::jsonb,$2::jsonb)`, stored, catalogJSON).Scan(&projected))
			var actual struct {
				Selectors []domain.RuleSelector `json:"selectors"`
			}
			require.NoError(t, json.Unmarshal(projected, &actual))
			require.Equal(t, expected.Selectors, actual.Selectors)
		})
	}
}

func TestAccessLabelSelectorCanonicalMigrationRoundTrip(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	restoreSources := accessLabelSuspendMigrations(t, r, accessLabelFreshnessMigration, accessLabelSelectorSourceMigration)
	defer restoreSources()
	up, down := accessLabelMigrationParts(t, accessLabelSelectorCanonicalMigration)
	inspect := func() string {
		var valid bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3() AND kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
		require.True(t, valid)
		var state string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_array(p.oid,p.prosrc,p.proowner,p.proacl,p.prosecdef,p.provolatile,p.proconfig) ORDER BY p.oid)::text FROM pg_proc p WHERE p.oid=ANY(ARRAY[
   'kaname._authority_resource_rule_fingerprint_v2(jsonb,boolean)'::regprocedure,
   'kaname._authority_resource_encode_proposed_rules_v2(jsonb,boolean)'::regprocedure,
   'kaname._authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)'::regprocedure,
   'kaname._authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)'::regprocedure,
   'kaname._authority_crud_storage_v3()'::regprocedure,
   'kaname._authority_full_contract_storage_v3()'::regprocedure])`).Scan(&state))
		return state
	}
	installed := inspect()
	_, err := r.admin.Exec(r.ctx, down)
	require.NoError(t, err)
	require.NotEqual(t, installed, inspect())
	_, err = r.admin.Exec(r.ctx, up)
	require.NoError(t, err)
	require.Equal(t, installed, inspect())
}

func TestAccessLabelSourceMatcherUsesProtectedImage(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const match = `SELECT kaname._authority_resource_selector_matches_v3($1::jsonb,'iam.project','test-id',$2::jsonb,$3::jsonb)`
	const protected = `{"arm":"access_labels","object_types":["iam.project"],"match_access_labels":{"team":"b"}}`
	const ordinary = `{"arm":"labels","object_types":["iam.project"],"match_labels":{"team":"b"}}`
	const teamB = `{"team":"b"}`
	const teamA = `{"team":"a"}`
	for _, tc := range []struct {
		name, selector, labels, accessLabels string
		allowed                              bool
	}{
		{"protected_match", protected, teamA, teamB, true},
		{"protected_rejects_ordinary_collision", protected, teamB, teamA, false},
		{"protected_rejects_missing_key", protected, teamB, `{}`, false},
		{"ordinary_match", ordinary, teamB, teamA, true},
		{"ordinary_rejects_protected_collision", ordinary, teamA, teamB, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var allowed bool
			require.NoError(t, r.admin.QueryRow(r.ctx, match, tc.selector, tc.labels, tc.accessLabels).Scan(&allowed))
			require.Equal(t, tc.allowed, allowed)
		})
	}
	t.Run("rejects_empty_protected_selector", func(t *testing.T) {
		selector := `{"arm":"access_labels","object_types":["iam.project"],"match_access_labels":{}}`
		var allowed bool
		err := r.admin.QueryRow(r.ctx, match, selector, teamB, teamB).Scan(&allowed)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "22023", pgErr.Code)
	})
}
