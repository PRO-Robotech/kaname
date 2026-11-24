// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestCatalogWildcardGooseRoundTripKeepsExactBindingProjection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен PostgreSQL")
	}
	db := openP2(t).db
	own, before := versionsOf(t, "20261121160000_catalog_wildcard_uses_live_authority_catalog.sql")
	require.NoError(t, goose.UpTo(db, ".", before))
	const resourceProjection = "kaname._authority_resource_materialized_types_v2(jsonb,integer,jsonb)"
	const censusProjection = "kaname._authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)"
	const stageCapture = "kaname.authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)"
	functionDefinition := func(signature string) string {
		t.Helper()
		var definition string
		require.NoError(t, db.QueryRow(`SELECT pg_catalog.pg_get_functiondef($1::regprocedure)`, signature).Scan(&definition))
		return definition
	}
	priorStage := functionDefinition(stageCapture)
	require.NoError(t, goose.UpTo(db, ".", own))
	upgradedStage := functionDefinition(stageCapture)
	require.NotEqual(t, priorStage, upgradedStage)

	rows := seed.LiteralRows()
	rows.Modules = append(rows.Modules, "warehouse")
	for _, name := range []string{"live", "levelOnly"} {
		rows.Resources = append(rows.Resources, catalog.ResourceRow{
			Module: "warehouse", Resource: name, ObjectType: "warehouse_" + strings.ToLower(name),
		})
	}
	rows.Verbs = append(rows.Verbs,
		catalog.VerbRow{Module: "warehouse", Resource: "live", Verb: "get", PerObject: true},
		catalog.VerbRow{Module: "warehouse", Resource: "levelOnly", Verb: "create"},
	)
	for _, dotted := range domain.RetiredTypes() {
		module, name, ok := strings.Cut(dotted, ".")
		require.True(t, ok)
		rows.Resources = append(rows.Resources, catalog.ResourceRow{
			Module: module, Resource: name, ObjectType: module + "_" + name,
		})
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: module, Resource: name, Verb: "get", PerObject: true})
	}
	halves := catalog.Halves{
		Live: rows,
		Retired: catalog.Rows{Resources: []catalog.ResourceRow{
			{Module: "warehouse", Resource: "retired", ObjectType: "warehouse_retired"},
		}},
	}
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	canonical, err := catalog.CanonicalJSON(halves)
	require.NoError(t, err)
	asJSON := func(value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		return raw
	}

	all := domain.Rule{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}}
	module := domain.Rule{Module: "warehouse", Resources: []string{"*"}, Verbs: []string{"get"}}
	nested := domain.Rule{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get"}}},
	}
	ordinary := domain.Rule{
		Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"},
	}
	require.Contains(t, facts.MaterializedTypeProjection(all, domain.ScopeAccount).ObjectTypes, "warehouse.live")
	require.NotContains(t, facts.MaterializedTypeProjection(all, domain.ScopeAccount).ObjectTypes, "warehouse.levelOnly")
	for _, scope := range []domain.Scope{domain.ScopeCluster, domain.ScopeAccount, domain.ScopeProject} {
		for _, rule := range []domain.Rule{all, module, nested, ordinary} {
			encoded, err := domain.EncodeRules(domain.Rules{rule})
			require.NoError(t, err)
			var raw []byte
			require.NoError(t, db.QueryRow(`SELECT kaname._authority_resource_materialized_types_v2($1::jsonb->0,$2::integer,$3::jsonb)`,
				encoded, int(scope), canonical).Scan(&raw))
			var got []string
			require.NoError(t, json.Unmarshal(raw, &got))
			want := facts.MaterializedTypeProjection(rule, scope).ObjectTypes
			require.True(t, slices.Equal(want, got), "scope %v, rule %v -> Go %v, SQL %v", scope, rule, want, got)
		}
		rules := domain.Rules{all, nested, ordinary}
		encoded, err := domain.EncodeRules(rules)
		require.NoError(t, err)
		for _, fps := range [][]string{{}, {all.Fingerprint(), ordinary.Fingerprint()}} {
			for _, live := range []bool{true, false} {
				var raw []byte
				require.NoError(t, db.QueryRow(`SELECT kaname._authority_binding_census_projection_v3($1::jsonb,$2::jsonb,$3::integer,$4::jsonb)`,
					asJSON(map[string]any{"live": live, "rules": json.RawMessage(encoded)}), asJSON(fps), int(scope), canonical).Scan(&raw))
				var got struct {
					Types        []string
					HasSelectors bool `json:"has_selectors"`
					HasNonanchor bool `json:"has_nonanchor"`
				}
				require.NoError(t, json.Unmarshal(raw, &got))
				var types []string
				var hasNonanchor bool
				var selectors []domain.RuleSelector
				if live {
					selectors = facts.MaterializingSelectorsInScope(domain.RulesForStoredSelectorLayout(rules, fps), scope)
				}
				for _, selector := range selectors {
					types = append(types, selector.ObjectTypes...)
					hasNonanchor = hasNonanchor || selector.Arm != domain.ArmAnchor || selector.Container != nil
				}
				slices.Sort(types)
				require.True(t, slices.Equal(slices.Compact(types), got.Types), "scope %v, FP %v, live %v -> Go %v, SQL %v", scope, fps, live, types, got.Types)
				require.Equal(t, len(selectors) > 0, got.HasSelectors)
				require.Equal(t, hasNonanchor, got.HasNonanchor)
			}
		}
	}

	require.NoError(t, goose.DownTo(db, ".", before))
	require.Equal(t, priorStage, functionDefinition(stageCapture))
	for _, signature := range []string{resourceProjection, censusProjection} {
		var absent bool
		require.NoError(t, db.QueryRow(`SELECT pg_catalog.to_regprocedure($1) IS NULL`, signature).Scan(&absent))
		require.True(t, absent, "%s осталась после отката", signature)
	}
	require.NoError(t, goose.UpTo(db, ".", own))
	require.Equal(t, upgradedStage, functionDefinition(stageCapture))
}
