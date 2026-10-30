// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// Given взят из объявленной малой сетки, а не составлен с отсутствующими
// измерениями. Используются настоящий seedPoint, measurePoint и Census.Verify.
// Независимый strengthUnitsTx не сбрасывается вместе с verdictCapture.
func TestR7ScaleGridCallsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, capture := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	p := scalegrid.Small()[0][0]
	f.seedPoint(t, ctx, p)
	observed := &strengthUnitsTx{Tx: tx}
	r := measurePoint(t, ctx, observed, capture, p)
	windows := strengthUnitsProductWindows(t, observed.statements)
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatal(err)
	}
	actualAsks := strengthUnitsOccurrences(observed.statements, relverdict.VerdictQuerySQLForTest(axis))
	t.Run("lawful_initial_SQL_window", func(t *testing.T) {
		if len(windows) != 1 || windows[0] != 2 {
			t.Fatalf("не создано одно реальное окно с двумя SQL продукта: %v", windows)
		}
		if actualAsks != 22 || r.census.VerdictsAsked != actualAsks {
			t.Errorf("вызовов Ask по трассе %d, в census %d; ожидался начальный Ask и цикл из 21", actualAsks, r.census.VerdictsAsked)
		}
		if got := strengthUnitsExplains(observed.statements); got != 1 {
			t.Errorf("исполнено EXPLAIN %d, требуется один вне окна SQL продукта", got)
		}
		if r.p50 <= 0 || r.p95 <= 0 || r.p99 <= 0 {
			t.Error("настоящая выборка времени не получена")
		}
	})
	t.Run("product_SQL_excludes_after_counter", func(t *testing.T) {
		if len(windows) != 1 {
			t.Fatal("реальное окно SQL не создано")
		}
		if r.calls != windows[0] {
			t.Errorf("R71 calls=%d, реально продуктовых SQL между запросами прибора=%d", r.calls, windows[0])
		}
	})
}
