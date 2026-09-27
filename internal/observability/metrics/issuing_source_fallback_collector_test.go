// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// issuing_source_fallback_collector_test.go — клетки
// `kaname_issuing_source_fallbacks_total{point,reason}` выходят на витрину все,
// нулём в том числе, и идут из переписи правила адреса источника (приёмка
// ceremony-pace-is-named-by-number.md, Р7 п.4, KN-PACE-37).

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var fallbackCellsForTest = []IssuingSourceFallbackCell{
	{Point: "authorize", Reason: "forwarded-from-non-edge"},
	{Point: "authorize", Reason: "edge-without-address"},
	{Point: "token", Reason: "forwarded-from-non-edge"},
	{Point: "token", Reason: "edge-without-address"},
}

func fallbackCell(t *testing.T, r *Registry, c IssuingSourceFallbackCell) (float64, bool) {
	t.Helper()
	return labelledCounter(t, r, IssuingSourceFallbacksMetric, map[string]string{"point": c.Point, "reason": c.Reason})
}

func TestIssuingSourceFallbackCollector_PrintsEveryCellFromTheCensus(t *testing.T) {
	census := map[IssuingSourceFallbackCell]uint64{}
	reg := NewRegistry()
	reg.NewIssuingSourceFallbackCollector(fallbackCellsForTest, func() map[IssuingSourceFallbackCell]uint64 {
		out := make(map[IssuingSourceFallbackCell]uint64, len(census))
		for k, v := range census {
			out[k] = v
		}
		return out
	})
	require.Equal(t, "kaname_issuing_source_fallbacks_total", IssuingSourceFallbacksMetric)
	for _, c := range fallbackCellsForTest {
		v, present := fallbackCell(t, reg, c)
		require.Truef(t, present, "клетка %v не вышла на витрину до первого запроса", c)
		require.Zero(t, v)
	}

	census[fallbackCellsForTest[2]] = 3
	v, _ := fallbackCell(t, reg, fallbackCellsForTest[2])
	require.Equal(t, 3.0, v, "ряд идёт из переписи")
	other, _ := fallbackCell(t, reg, fallbackCellsForTest[0])
	require.Zero(t, other)
}

func TestIssuingSourceFallbackCollector_RefusesAnUnwiredCensus(t *testing.T) {
	require.Panics(t, func() { NewRegistry().NewIssuingSourceFallbackCollector(fallbackCellsForTest, nil) })
	require.Panics(t, func() {
		NewRegistry().NewIssuingSourceFallbackCollector(nil, func() map[IssuingSourceFallbackCell]uint64 { return nil })
	})
}
