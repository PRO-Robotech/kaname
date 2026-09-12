// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// client_token_outcome_collector_test.go — перепись исходов токен-эндпоинта
// ЧИТАЕТСЯ, а не только собирается (задача продукта #2501).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Обработчик нёс карту счётчиков с пред-засевом по КАЖДОМУ объявленному исходу и
// экспортированный аксессор — работа была сделана на девять десятых.
// Композиционный корень его монтировал и не читал: разбивка отказов по исходам
// (склад однократности недоступен · перечень доверия недоступен · издатель не
// доверен · адресат не разрешён …) жила только в памяти процесса.
//
// Это полоса, через которой в отдельной установке выдаётся ВСЯКОЕ арендаторское
// удостоверение. «Ноль отказов за всю жизнь полосы» здесь неотличимо от «полоса
// не исполнялась ни разу».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Р1  печатаются ВСЕ объявленные исходы, включая нулевые;
//	Р2  ряд идёт из ПЕРЕПИСИ, а не из собственного счёта коллектора;
//	Р3  исход, объявленный и отсутствующий в снимке, печатается НУЛЁМ, а не
//	    пропускается: пропуск вернул бы клетку, появляющуюся при первом
//	    попадании;
//	Р4  отсутствие читателя либо пустой набор — отказ, а не тихая регистрация.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func clientTokenCell(t *testing.T, r *Registry, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, ClientTokenOutcomesMetric, map[string]string{"outcome": outcome})
}

var clientTokenOutcomesForTest = []string{"accepted", "client-unknown", "replay-store-unavailable"}

// TestClientTokenOutcomeCollector_PrintsEveryDeclaredOutcome — Р1 и Р3.
func TestClientTokenOutcomeCollector_PrintsEveryDeclaredOutcome(t *testing.T) {
	reg := NewRegistry()
	// Снимок несёт ОДИН исход из трёх: два остальных обязаны выйти нулём, а не
	// пропасть.
	reg.NewClientTokenOutcomeCollector(clientTokenOutcomesForTest, func() map[string]uint64 {
		return map[string]uint64{"client-unknown": 4}
	})

	for _, outcome := range clientTokenOutcomesForTest {
		value, present := clientTokenCell(t, reg, outcome)
		require.Truef(t, present, "исход %q объявлен и на витрину не вышел — клетка, "+
			"появляющаяся при первом попадании, неотличима от «ещё не случалось»", outcome)
		if outcome == "client-unknown" {
			require.Equal(t, 4.0, value)
			continue
		}
		require.Zerof(t, value, "исход %q вышел не нулём", outcome)
	}
}

// TestClientTokenOutcomeCollector_ReadsTheCensus — Р2: величина двигается вместе
// с переписью и не двигается без неё.
func TestClientTokenOutcomeCollector_ReadsTheCensus(t *testing.T) {
	census := map[string]uint64{}
	reg := NewRegistry()
	reg.NewClientTokenOutcomeCollector(clientTokenOutcomesForTest, func() map[string]uint64 {
		out := make(map[string]uint64, len(census))
		for k, v := range census {
			out[k] = v
		}
		return out
	})

	before, _ := clientTokenCell(t, reg, "replay-store-unavailable")
	require.Zero(t, before)

	census["replay-store-unavailable"] = 2
	after, present := clientTokenCell(t, reg, "replay-store-unavailable")
	require.True(t, present)
	require.Equal(t, 2.0, after, "перепись выросла, а ряд остался на прежнем значении")

	other, _ := clientTokenCell(t, reg, "accepted")
	require.Zero(t, other, "ряд соседнего исхода двинулся без своего события")
}

// TestClientTokenOutcomeCollector_RefusesAnUnreadableSource — Р4.
func TestClientTokenOutcomeCollector_RefusesAnUnreadableSource(t *testing.T) {
	require.Panics(t, func() {
		NewRegistry().NewClientTokenOutcomeCollector(clientTokenOutcomesForTest, nil)
	}, "коллектор без источника принят молча: вечный ноль неотличим от непровязанного читателя")
	require.Panics(t, func() {
		NewRegistry().NewClientTokenOutcomeCollector(nil, func() map[string]uint64 { return nil })
	}, "пустой набор исходов принят молча: на витрину не выйдет ни одного ряда")
}
