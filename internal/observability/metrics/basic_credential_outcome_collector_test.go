// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// basic_credential_outcome_collector_test.go — перепись исходов полосы базового
// секрета ЧИТАЕТСЯ, а не только собирается (задача kaname#379).
//
// Утверждается:
//
//	Р1  печатаются ВСЕ объявленные клетки (глагол × исход), включая нулевые;
//	Р2  ряд идёт из ПЕРЕПИСИ, а не из собственного счёта коллектора;
//	Р3  клетка, объявленная и отсутствующая в снимке, печатается НУЛЁМ;
//	Р4  отсутствие читателя либо пустой набор — отказ, а не тихая регистрация.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func basicCredentialSeries(t *testing.T, r *Registry, c BasicCredentialCell) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, BasicCredentialOutcomesMetric,
		map[string]string{"verb": c.Verb, "outcome": c.Outcome})
}

var basicCellsForTest = []BasicCredentialCell{
	{Verb: "resolve", Outcome: "accepted"},
	{Verb: "resolve", Outcome: "owner-revoked"},
	{Verb: "liveness", Outcome: "owner-revoked"},
}

// TestBasicCredentialOutcomeCollector_PrintsEveryDeclaredCell — Р1 и Р3.
func TestBasicCredentialOutcomeCollector_PrintsEveryDeclaredCell(t *testing.T) {
	reg := NewRegistry()
	revoked := basicCellsForTest[1]
	reg.NewBasicCredentialOutcomeCollector(basicCellsForTest, func() map[BasicCredentialCell]uint64 {
		return map[BasicCredentialCell]uint64{revoked: 3}
	})
	for _, c := range basicCellsForTest {
		value, present := basicCredentialSeries(t, reg, c)
		require.Truef(t, present, "клетка %v объявлена и на витрину не вышла", c)
		if c == revoked {
			require.Equal(t, 3.0, value)
			continue
		}
		require.Zerof(t, value, "клетка %v вышла не нулём", c)
	}
}

// TestBasicCredentialOutcomeCollector_ReadsTheCensus — Р2.
func TestBasicCredentialOutcomeCollector_ReadsTheCensus(t *testing.T) {
	census := map[BasicCredentialCell]uint64{}
	reg := NewRegistry()
	reg.NewBasicCredentialOutcomeCollector(basicCellsForTest, func() map[BasicCredentialCell]uint64 {
		out := make(map[BasicCredentialCell]uint64, len(census))
		for k, v := range census {
			out[k] = v
		}
		return out
	})
	live := basicCellsForTest[2]
	before, _ := basicCredentialSeries(t, reg, live)
	require.Zero(t, before)

	census[live] = 5
	after, present := basicCredentialSeries(t, reg, live)
	require.True(t, present)
	require.Equal(t, 5.0, after, "перепись выросла, а ряд остался прежним")

	// Та же причина на ДРУГОМ глаголе — своя клетка.
	other, _ := basicCredentialSeries(t, reg, basicCellsForTest[1])
	require.Zero(t, other, "ряд той же причины на другом глаголе двинулся без своего события")
}

// TestBasicCredentialOutcomeCollector_RefusesAnUnreadableSource — Р4.
func TestBasicCredentialOutcomeCollector_RefusesAnUnreadableSource(t *testing.T) {
	require.Panics(t, func() {
		NewRegistry().NewBasicCredentialOutcomeCollector(basicCellsForTest, nil)
	}, "коллектор без источника принят молча: вечный ноль неотличим от непровязанного читателя")
	require.Panics(t, func() {
		NewRegistry().NewBasicCredentialOutcomeCollector(nil,
			func() map[BasicCredentialCell]uint64 { return nil })
	}, "пустой набор клеток принят молча: на витрину не выйдет ни одного ряда")
}
