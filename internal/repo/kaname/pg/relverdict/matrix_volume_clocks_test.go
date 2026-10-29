// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// matrix_volume_clocks_test.go — РАЗДЕЛ О РАСХОЖДЕНИИ ЧАСОВ ПЕЧАТАЕТСЯ ПО
// ИЗМЕРЕННОМУ, А НЕ БЕЗУСЛОВНО (kaname#74).
//
// # Предмет
//
// Отчёт прибора объёма нёс раздел «ЧАСЫ РАСХОДЯТСЯ С НЕСУЩЕЙ ВЕЛИЧИНОЙ» и
// утверждение «план НЕ МЕНЯЛСЯ ни в одной точке» в КАЖДОМ прогоне — текст стоял
// без условия. Отчёт в дереве поэтому утверждал расхождение при несущей ×1.03 и
// часах ×1.01, а неизменность плана — при планах, которые в нём же, разделом
// выше, различаются по точкам. Два ложных утверждения в одном абзаце, и ни одно
// не связано с числами, рядом с которыми напечатано.
//
// # Что держит проба
//
// Три входа, различающихся РОВНО ОДНИМ фактом от соседа:
//
//	часы идут с несущей                раздела о расхождении НЕТ, сказано «не расходятся»;
//	часы ушли, план тот же              раздел есть, «план не менялся» — сказано;
//	часы ушли, план сменился            раздел есть, «план не менялся» — НЕ сказано.
//
// Входы синтетические намеренно: свойство — функция чисел, и снимать ради него
// матрицу на шесть миллионов строк значило бы судить текст по часу замера.

import (
	"strings"
	"testing"
	"time"
)

// syntheticMatrix — две точки объёма; отрицательное чтение задаётся аргументами,
// прочее неподвижно.
func syntheticMatrix(rowsLo, rowsHi int64, p50Lo, p50Hi time.Duration, planLo, planHi string) []matrixResult {
	point := func(name string, n int, rows int64, p50 time.Duration, plan string) matrixResult {
		tables := make([]tableCount, 10)
		for i := range tables {
			tables[i] = tableCount{table: "t", rows: int64(n), bytes: int64(n) * 100}
		}
		ops := map[opKind]opResult{}
		for _, k := range matrixOps() {
			ops[k] = opResult{
				kind: k, rows: 2, touched: 2, planTaken: true, plan: "[Index Scan→t]",
				calls: 2, p50: time.Millisecond, p95: 2 * time.Millisecond,
			}
		}
		ops[opCheck] = opResult{
			kind: opCheck, rows: rows, touched: rows, planTaken: true, plan: plan,
			calls: 2, p50: p50, p95: 2 * p50, verdict: "deny",
		}
		return matrixResult{
			point:  matrixPoint{Name: name, N: n, B: n, R: 9, F: 1},
			tables: tables, dbRows: int64(n) * 10, dbBytes: int64(n) * 1000,
			ops: ops, cycles: 1,
		}
	}
	return []matrixResult{
		point("малая", 1000, rowsLo, p50Lo, planLo),
		point("предельная", 1000000, rowsHi, p50Hi, planHi),
	}
}

// matrixBodyOf — текст отчёта целиком, тем же писателем, что у замера.
func matrixBodyOf(t *testing.T, results []matrixResult) string {
	t.Helper()
	prov := matrixProvenance()
	prov.Postgres = "16.4"
	body, err := renderMatrixReport(prov, results, time.Minute)
	if err != nil {
		t.Fatalf("отчёт не собран: %v", err)
	}
	return body
}

const clocksDivergeTitle = "ЧАСЫ РАСХОДЯТСЯ С НЕСУЩЕЙ ВЕЛИЧИНОЙ"

func TestMatrixReportClaimsClockDivergenceOnlyWhenMeasured(t *testing.T) {
	const plan = "[Index Scan→access_bindings Seq Scan→roles]"

	t.Run("часы идут с несущей — расхождения нет", func(t *testing.T) {
		// Ровно числа отчёта в дереве: несущая ×1.03, часы ×1.01.
		body := matrixBodyOf(t, syntheticMatrix(61, 63, 3200*time.Microsecond, 3232*time.Microsecond, plan, plan))
		if strings.Contains(body, clocksDivergeTitle) {
			t.Errorf("раздел о РАСХОЖДЕНИИ напечатан при несущей ×1.03 и часах ×1.01 — " +
				"отчёт утверждает результат, которого замер не дал")
		}
		if !strings.Contains(body, "НЕ РАСХОДЯТСЯ") {
			t.Errorf("исход «часы с несущей не расходятся» не сказан — молчание неотличимо " +
				"от прибора, который об этом не спрашивал")
		}
	})

	t.Run("часы ушли, план тот же — расхождение и неизменность плана", func(t *testing.T) {
		body := matrixBodyOf(t, syntheticMatrix(61, 63, 3*time.Millisecond, 30*time.Millisecond, plan, plan))
		if !strings.Contains(body, clocksDivergeTitle) {
			t.Errorf("часы ×10 при несущей ×1.03 — раздел о расхождении НЕ напечатан")
		}
		if !strings.Contains(body, "НЕ МЕНЯЛСЯ") {
			t.Errorf("план одинаков во всех точках, а отчёт этого не говорит")
		}
	})

	t.Run("часы ушли, план сменился — неизменность плана не утверждается", func(t *testing.T) {
		body := matrixBodyOf(t, syntheticMatrix(61, 63, 3*time.Millisecond, 30*time.Millisecond,
			plan, "[Index Only Scan→access_bindings Index Scan→roles]"))
		if !strings.Contains(body, clocksDivergeTitle) {
			t.Errorf("часы ×10 при несущей ×1.03 — раздел о расхождении НЕ напечатан")
		}
		if strings.Contains(body, "НЕ МЕНЯЛСЯ") {
			t.Errorf("планы по точкам РАЗНЫЕ, а отчёт утверждает «план НЕ МЕНЯЛСЯ» — " +
				"вывод «разница часов не про алгоритм» опирается на ложную посылку")
		}
	})
}
