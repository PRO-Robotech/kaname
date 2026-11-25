// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"math"
	"strings"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestRoleSelectorMoveFinalizeOwnsDeferredBudget(t *testing.T) {
	budget := &relverdict.AdministrativeReadBudget{}
	require.NoError(t, budget.Charge(99900, 4056))
	valid := map[string]any{
		"selector_move_transport": pendingNoCopyPrepareTransport, "phase": "selected",
		"source_sha256": strings.Repeat("a3", 32), "content_sha256": strings.Repeat("f4", 32),
		"rows": 79, "reads": 30, "deferred_rows": 21, "deferred_reads": 10,
	}
	// Каждая ось сверяется со своим остатком. Даже формально сходящийся
	// отчёт не может отдать Go часть минимального deferred-резерва.
	for _, tc := range []struct {
		name  string
		edits map[string]any
	}{
		{"transport", map[string]any{"selector_move_transport": "none"}},
		{"phase", map[string]any{"phase": "deferred"}},
		{"short source hash", map[string]any{"source_sha256": "ab"}},
		{"uppercase content hash", map[string]any{"content_sha256": strings.Repeat("AB", 32)}},
		{"hex type", map[string]any{"content_sha256": 9}},
		{"string cost", map[string]any{"reads": "30"}},
		{"null cost", map[string]any{"rows": nil}},
		{"array cost", map[string]any{"deferred_rows": []int{21}}},
		{"overflow addition", map[string]any{"rows": math.MaxInt, "deferred_rows": math.MaxInt}},
		{"unaccounted row", map[string]any{"rows": 78}},
		{"unaccounted read", map[string]any{"reads": 29}},
		{"row reserve exhausted", map[string]any{"rows": 80, "deferred_rows": 20}},
		{"read reserve exhausted", map[string]any{"reads": 31, "deferred_reads": 9}},
		{"empty owner phase", map[string]any{"rows": 8, "deferred_rows": 92}},
		{"unknown field", map[string]any{"decision_at": "later"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := maps.Clone(valid)
			maps.Copy(row, tc.edits)
			raw, err := json.Marshal(row)
			require.NoError(t, err)
			require.ErrorIs(t, chargeSelectorMoveFinalizeReceipt(budget, raw), kaname.ErrSourceUnconfirmed)
			require.Equal(t, 100, budget.RemainingRows())
			require.Equal(t, 40, budget.RemainingReads())
		})
	}
	raw, err := json.Marshal(valid)
	require.NoError(t, err)
	for _, malformed := range []string{
		"[]", "{}", string(raw) + " true",
		strings.Replace(string(raw), `"rows":79`, `"rows":79,"rows":79`, 1),
		strings.Replace(string(raw), `"rows":79`, `"Rows":79`, 1),
		strings.Replace(string(raw), `"reads":30,`, "", 1),
	} {
		require.ErrorIs(t, chargeSelectorMoveFinalizeReceipt(budget, []byte(malformed)), kaname.ErrSourceUnconfirmed)
	}
	require.NoError(t, chargeSelectorMoveFinalizeReceipt(budget, raw))
	require.Zero(t, budget.RemainingRows())
	require.Zero(t, budget.RemainingReads())
	require.ErrorIs(t, chargeSelectorMoveFinalizeReceipt(budget, raw), kaname.ErrSourceUnconfirmed)
}

func TestRoleSelectorMoveFinalizeRequiresLiveAttempt(t *testing.T) {
	var writer *preparedRoleWriteTx
	require.ErrorIs(t, writer.finalizePendingSelectorMove(t.Context(), roleSelectorMoveAuthorizedChanges{}), kaname.ErrSourceUnconfirmed)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, writer.finalizePendingSelectorMove(ctx, roleSelectorMoveAuthorizedChanges{}), context.Canceled)
}
