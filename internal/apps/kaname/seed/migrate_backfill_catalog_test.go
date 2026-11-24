// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Здесь проверяется настоящий путь до SQL-параметров: новый тип должен
// пережить повторный backfill под тем же FP, а снятый тип — исчезнуть.
func TestSystemRoleSelectorBackfillUsesPinnedCatalog(t *testing.T) {
	rules := domain.Rules{
		{Module: "erp", Resources: []string{"*"}, Verbs: []string{"get"}},
		{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, ResourceNames: []string{"one"}},
		{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"team": "one"}},
	}
	for _, invoiceLive := range []bool{false, true, true, false} {
		rows := LiteralRows()
		rows.Modules = append(rows.Modules, "erp")
		rows.Resources = append(rows.Resources, catalog.ResourceRow{Module: "erp", Resource: "contracts", ObjectType: "custom_contract"})
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{Module: "erp", Resource: "contracts", Verb: "get", PerObject: true})
		invoice := catalog.ResourceRow{Module: "erp", Resource: "invoices", ObjectType: "custom_invoice"}
		halves := catalog.Halves{Live: rows}
		if invoiceLive {
			halves.Live.Resources = append(halves.Live.Resources, invoice)
		} else {
			halves.Retired.Resources = append(halves.Retired.Resources, invoice)
		}
		halves.Live.Verbs = append(halves.Live.Verbs, catalog.VerbRow{Module: "erp", Resource: "invoices", Verb: "get", PerObject: true})
		facts, err := catalog.NewFacts(halves)
		require.NoError(t, err)
		tx := newSelectorBackfillCapture(t, rules)
		require.NoError(t, syncAllSystemRoleSelectorsWithFactsTx(context.Background(), tx, facts))
		expectedTypes := []string{"erp.contracts"}
		if invoiceLive {
			expectedTypes = append(expectedTypes, "erp.invoices")
		}
		require.Equal(t, expectedTypes, tx.writes[1].args[3])
		require.Equal(t, rules[0].Fingerprint(), tx.writes[1].args[1])
		require.Equal(t, selectorArmText(domain.ArmAnchor), tx.writes[1].args[2])
		assertSelectorBackfillWrites(t, tx, facts.MaterializingSelectors(rules))
	}
}

func TestSystemRoleSelectorBackfillNilFactsPreservesLegacy(t *testing.T) {
	rules := domain.Rules{
		{Module: "*", Resources: []string{"*"}, Verbs: []string{"get"}},
		{Module: "erp", Resources: []string{"*"}, Verbs: []string{"get"}},
	}
	legacy := newSelectorBackfillCapture(t, rules)
	require.NoError(t, syncAllSystemRoleSelectorsTx(context.Background(), legacy))
	explicitNil := newSelectorBackfillCapture(t, rules)
	require.NoError(t, syncAllSystemRoleSelectorsWithFactsTx(context.Background(), explicitNil, nil))
	require.Equal(t, legacy.writes, explicitNil.writes)
	assertSelectorBackfillWrites(t, legacy, rules.MaterializingSelectors())
}

func assertSelectorBackfillWrites(t *testing.T, tx *selectorBackfillCapture, selectors []domain.RuleSelector) {
	t.Helper()
	require.Equal(t, 1, tx.queries, "каталог не перечитывается внутри backfill")
	var materialized []domain.RuleSelector
	fps := make([]string, 0, len(selectors))
	for _, sel := range selectors {
		if len(sel.ObjectTypes) != 0 {
			materialized = append(materialized, sel)
			fps = append(fps, sel.RuleFP)
		}
	}
	require.Len(t, tx.writes, len(materialized)+1)
	require.Contains(t, tx.writes[0].sql, "DELETE FROM kaname.role_rule_selectors")
	require.Equal(t, []any{"role-live", fps}, tx.writes[0].args)
	for i, sel := range materialized {
		write := tx.writes[i+1]
		require.Contains(t, write.sql, "ON CONFLICT (role_id, rule_fp) DO UPDATE")
		require.Equal(t, "role-live", write.args[0])
		require.Equal(t, sel.RuleFP, write.args[1])
		require.Equal(t, selectorArmText(sel.Arm), write.args[2])
		require.Equal(t, sel.ObjectTypes, write.args[3])
		names := sel.ResourceNames
		if names == nil {
			names = []string{}
		}
		require.Equal(t, names, write.args[4])
		labels := sel.MatchLabels
		if labels == nil {
			labels = map[string]string{}
		}
		raw, err := json.Marshal(labels)
		require.NoError(t, err)
		require.JSONEq(t, string(raw), string(write.args[5].([]byte)))
	}
}

type selectorBackfillWrite struct {
	sql  string
	args []any
}

type selectorBackfillCapture struct {
	t       *testing.T
	rows    *selectorBackfillRows
	queries int
	writes  []selectorBackfillWrite
}

func newSelectorBackfillCapture(t *testing.T, rules domain.Rules) *selectorBackfillCapture {
	t.Helper()
	raw, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	return &selectorBackfillCapture{t: t, rows: &selectorBackfillRows{raw: raw}}
}

func (c *selectorBackfillCapture) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	c.queries++
	require.Contains(c.t, sql, "SELECT id, rules FROM kaname.roles")
	require.Contains(c.t, sql, "AND live")
	return c.rows, nil
}

func (c *selectorBackfillCapture) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	require.True(c.t, c.rows.closed, "Rows закрыты до первой записи на том же соединении")
	c.writes = append(c.writes, selectorBackfillWrite{sql: sql, args: args})
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

type selectorBackfillRows struct {
	pgx.Rows
	raw    []byte
	read   bool
	closed bool
}

func (r *selectorBackfillRows) Next() bool {
	if r.read {
		return false
	}
	r.read = true
	return true
}

func (r *selectorBackfillRows) Scan(dest ...any) error {
	*dest[0].(*string) = "role-live"
	*dest[1].(*[]byte) = r.raw
	return nil
}

func (r *selectorBackfillRows) Close()     { r.closed = true }
func (r *selectorBackfillRows) Err() error { return nil }
