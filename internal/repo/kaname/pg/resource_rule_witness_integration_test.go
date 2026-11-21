// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Компонентный SQL/Go parity проверяет реальные private SQL функции миграции.
// Owner нужен только потому, что runtime EXECUTE на helper запрещён. Эта проба
// не выдаётся за actor admission или actual-entry certificate verification.
func TestResourceRuleWitness_SQLMatchesCanonicalAuthoredFingerprint(t *testing.T) {
	r := writerProtocolRig(t)
	cases := []struct {
		name string
		rule domain.Rule
	}{
		{"ordinary labels", domain.Rule{Module: "vpc", Resources: []string{"network", "subnet"}, Verbs: []string{"list", "get"}, MatchLabels: map[string]string{"env": "prod", "zone": "one"}}},
		{"creator", domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get", "update"}, CreatedBySubject: true}},
		{"nested", domain.Rule{Module: "vpc", Resources: []string{"box"}, Verbs: []string{"get"}, ResourceNames: []string{"box-one"}, Children: []domain.Rule{{Resources: []string{"item"}, Verbs: []string{"list", "get"}}, {Resources: []string{"tag"}, Verbs: []string{"delete"}}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := domain.EncodeRules(domain.Rules{tc.rule})
			require.NoError(t, err)
			var rows []json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &rows))
			var actual string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_fingerprint_v2($1::jsonb,false)`, string(rows[0])).Scan(&actual))
			require.Equal(t, tc.rule.Fingerprint(), actual)
			var stored []string
			for _, selector := range (domain.Rules{tc.rule}).MaterializingSelectors() {
				stored = append(stored, selector.RuleFP)
			}
			storedJSON, err := json.Marshal(stored)
			require.NoError(t, err)
			for _, selector := range (domain.Rules{tc.rule}).MaterializingSelectors() {
				var witness []byte
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_witness_v2(jsonb_build_object('rules',$1::jsonb),$2,$3::jsonb)`, string(raw), selector.RuleFP, string(storedJSON)).Scan(&witness))
				var result struct {
					Rule   json.RawMessage `json:"rule"`
					Nested bool            `json:"nested"`
				}
				require.NoError(t, json.Unmarshal(witness, &result))
				decoded, err := domain.DecodeRules(append(append([]byte("["), result.Rule...), ']'))
				require.NoError(t, err)
				require.Len(t, decoded, 1)
				require.Equal(t, selector.Verbs, decoded[0].Verbs)
				require.Equal(t, selector.Container != nil, result.Nested)
			}
		})
	}
}

func TestResourceRuleWitness_StoredLayoutKeepsLegacyAndExactOrdinaryResidual(t *testing.T) {
	r := writerProtocolRig(t)
	rule := domain.Rule{Module: "iam", Resources: []string{"role", "group"}, Verbs: []string{"bind", "get"}, ResourceNames: []string{"named-one"}}
	ordinary, _, err := domain.SplitGrantCapabilityRules(domain.Rules{rule})
	require.NoError(t, err)
	require.Len(t, ordinary, 2)
	raw, err := domain.EncodeRules(domain.Rules{rule})
	require.NoError(t, err)
	cases := []struct {
		name   string
		layout domain.Rules
	}{{"legacy", domain.Rules{rule}}, {"split", ordinary}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stored []string
			for _, s := range tc.layout.MaterializingSelectors() {
				stored = append(stored, s.RuleFP)
			}
			storedJSON, err := json.Marshal(stored)
			require.NoError(t, err)
			for _, want := range tc.layout {
				var witness []byte
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_witness_v2(jsonb_build_object('rules',$1::jsonb),$2,$3::jsonb)`, string(raw), want.Fingerprint(), string(storedJSON)).Scan(&witness))
				var result struct {
					Rule json.RawMessage `json:"rule"`
				}
				require.NoError(t, json.Unmarshal(witness, &result))
				decoded, err := domain.DecodeRules(append(append([]byte("["), result.Rule...), ']'))
				require.NoError(t, err)
				require.Equal(t, want.Fingerprint(), decoded[0].Fingerprint())
			}
			var ignored []byte
			err = r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_rule_witness_v2(jsonb_build_object('rules',$1::jsonb),$2,$3::jsonb)`, string(raw), strings.Repeat("0", 64), string(storedJSON)).Scan(&ignored)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
		})
	}
}
