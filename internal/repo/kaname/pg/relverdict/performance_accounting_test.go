// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"encoding/json"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/stretchr/testify/require"
)

func TestPerformanceAccountingListHasOneInvocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, capture := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	p := scalegrid.StrengthPoint{Axis: scalegrid.AxisPg, N: 100, M: 0, L: 1, S: 7, K: 1, Pg: 10, AllowedShare: 100}
	f.seedPoint(t, ctx, p)
	r := measureStrengthPoint(t, ctx, tx, capture, f, p)
	require.Equal(t, int64(1), r.census.VerdictsAsked, "один List нельзя считать одиннадцатью вопросами")
	require.Zero(t, r.asks[0].p99, "у одного List нет выборки для p99")
}

func TestPerformanceAccountingAskCountsControlAndSamples(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, capture := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	p := scalegrid.StrengthPoint{Axis: scalegrid.AxisV, N: 100, M: 0, L: 1, S: 7, K: 1}
	f.seedPoint(t, ctx, p)
	r := measureStrengthPoint(t, ctx, tx, capture, f, p)
	require.Len(t, r.asks, 3)
	require.Equal(t, int64(3*(strRepeats+1)), r.census.VerdictsAsked, "учтены начальный контроль и повторы каждого Ask; EXPLAIN отдельно")
	require.Positive(t, r.asks[0].p99, "положительный близнец: у повторных Ask есть квантили")
}

func TestPerformanceAccountingCollectorUsesCompiledScenarioPlan(t *testing.T) {
	grid := scalegrid.Strength()
	results := make([][]strPointResult, len(grid))
	for i, axis := range grid {
		for _, p := range axis {
			r := strPointResult{point: p}
			modes := scalegrid.AskModes()
			invocations := int64(strRepeats + 1)
			if p.Axis == scalegrid.AxisPg {
				modes, invocations = modes[:1], 1
			}
			for _, mode := range modes {
				r.asks = append(r.asks, askResult{mode: mode, invocations: invocations})
				r.census.VerdictsAsked += invocations
			}
			results[i] = append(results[i], r)
		}
	}
	text := renderStrengthReport(grid, results, time.Second, true)
	require.Contains(t, text, "points=34 scenarios=78 askScenarios=66 listScenarios=12 apiInvocations=804")
	for _, tc := range []struct {
		name, body, raw, rc string
		valid               bool
	}{
		{"complete", text, "--- PASS: TestStrengthGrid_Report (1s)\nотчёт записан:\n", "0", true},
		{"wrong102", strings.Replace(text, "STRENGTH_CENSUS axes=6 plannedAxes=6 points=34 scenarios=78", "STRENGTH_CENSUS axes=6 plannedAxes=6 points=34 scenarios=102", 1), "--- PASS: TestStrengthGrid_Report (1s)\nотчёт записан:\n", "0", false},
		{"missing", "", "--- PASS: TestStrengthGrid_Report (1s)\nотчёт записан:\n", "0", false},
		{"partial", strings.Replace(text, "STRENGTH_CENSUS axes=6", "STRENGTH_CENSUS axes=5", 1), "--- PASS: TestStrengthGrid_Report (1s)\nотчёт записан:\n", "0", false},
		{"failedGo", text, "--- PASS: TestStrengthGrid_Report (1s)\nотчёт записан:\n", "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			report, raw := filepath.Join(dir, "report"), filepath.Join(dir, "raw")
			require.NoError(t, os.WriteFile(report, []byte(tc.body), 0o600))
			require.NoError(t, os.WriteFile(raw, []byte(tc.raw), 0o600))
			out, err := osexec.Command("bash", "../scalegrid/collect-strength.sh", report, raw, tc.rc).CombinedOutput()
			if tc.valid {
				require.NoError(t, err, "%s", out)
			} else {
				require.Error(t, err, "%s", out)
			}
		})
	}
}

func TestPerformanceAccountingMatrixReportsObservedPlans(t *testing.T) {
	results := make([]matrixResult, 2)
	for i := range results {
		results[i] = matrixResult{point: matrixPoints[i], dbRows: int64(1000 * (i + 1)), tables: make([]tableCount, 10), ops: map[opKind]opResult{}}
		for _, k := range matrixOps() {
			results[i].ops[k] = opResult{kind: k, rows: 1, touched: 1, planTaken: true, plan: []string{"Index Scan", "Seq Scan"}[i], p50: time.Millisecond}
		}
	}
	text := renderMatrixReport(results, time.Second, "PostgreSQL fixture")
	require.Contains(t, text, "Seq Scan", "положительный близнец: реальные формы планов показаны")
	for _, claim := range []string{"НЕ МЕНЯЛСЯ", "перестало помещаться в память", "всего операций исполнено"} {
		require.False(t, strings.Contains(text, claim), "необоснованное утверждение %q", claim)
	}
	require.Contains(t, text, "основных операций цикла")
	require.Contains(t, text, "триггер")
}

func TestPerformanceAccountingMatrixIncludesSubjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	results := runMatrix(t, ctx, matrixPoints[:1])
	require.Contains(t, results[0].ops[opWrite].plan, "access_bindings", "положительный близнец: первая вставка снята")
	require.Contains(t, results[0].ops[opWrite].plan, "access_binding_subjects", "план записи включает обе продуктовые вставки")
	write := results[0].ops[opWrite]
	require.Len(t, write.roots, 2)
	require.True(t, write.constraintsChecked)
	var deferred bool
	for _, n := range write.physicalSQL {
		require.True(t, json.Valid(n.Plan), "вложенное свидетельство — полный JSON")
		require.NotZero(t, n.BackendPID)
		deferred = deferred || strings.Contains(n.Context, "access_binding_carries_a_subject")
	}
	require.True(t, deferred, "снят реальный SQL отложенного ограничения, а не только EXPLAIN-rollback")
	for _, r := range results[0].ops {
		for _, root := range r.roots {
			require.True(t, json.Valid(root.Explain))
			require.NotEmpty(t, root.SQL)
		}
	}
	t.Logf("MATRIX_SQL_EVIDENCE %s", renderMatrixReport(results, time.Second, "PostgreSQL integration"))
}
