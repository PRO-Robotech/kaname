// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
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
