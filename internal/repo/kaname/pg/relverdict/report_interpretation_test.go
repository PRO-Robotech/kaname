// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// Малые результаты проходят через настоящий renderer, без посева и повторного
// performance-замера. Каждая пара меняет один факт, влияющий на интерпретацию.
// Пустая матрица, пропущенные планы и вопросы не входят в предмет: runMatrix
// исполняет непустую matrixPoints, measureMatrixPoint снимает все четыре плана,
// а measureStrengthPoint добавляет все AskModes до renderVerdictAxis. Пять таких
// искусственных кейсов первой редакции f38f4c06f сняты после разбора RED; их
// падения не являются основанием расширять контракт renderer.
func interpretationMatrixFixture() []matrixResult {
	results := make([]matrixResult, 3)
	for i := range results {
		results[i] = matrixResult{
			point:   matrixPoint{Name: fmt.Sprintf("fixture-%d", i)},
			dbRows:  []int64{100, 1000, 100000}[i],
			dbBytes: []int64{1024, 10240, 1024000}[i],
			tables:  make([]tableCount, 10),
			ops:     make(map[opKind]opResult),
		}
		for _, op := range matrixOps() {
			results[i].ops[op] = opResult{kind: op, rows: 10, touched: 10,
				planTaken: true, plan: "Index Scan fixture", p50: time.Millisecond, p95: 2 * time.Millisecond}
		}
	}
	return results
}

func interpretationContains(t *testing.T, report, want string) {
	t.Helper()
	if !strings.Contains(report, want) {
		t.Errorf("интерпретация не содержит %q", want)
	}
}

func interpretationExcludes(t *testing.T, report, forbidden string) {
	t.Helper()
	if strings.Contains(report, forbidden) {
		t.Errorf("интерпретация выдаёт неподтверждённый вывод %q", forbidden)
	}
}

func TestR7InterpretationMatrixPlans(t *testing.T) {
	for _, tc := range []struct {
		name, middlePlan string
		want             string
	}{
		{"same", "Index Scan fixture", "планы совпадают во всех точках"},
		{"different_middle", "Seq Scan fixture", "планы различаются"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := interpretationMatrixFixture()
			op := results[1].ops[opCheck]
			op.plan = tc.middlePlan
			results[1].ops[opCheck] = op
			report := renderMatrixReport(results, time.Second, "fixture")
			interpretationContains(t, report, tc.want)
			interpretationContains(t, report, "Index Scan fixture")
			if tc.name != "same" {
				interpretationExcludes(t, report, "План при этом НЕ МЕНЯЛСЯ")
			}
			interpretationExcludes(t, report, "это цена того, что рабочее")
			interpretationContains(t, report, "причина различия времени не установлена")
		})
	}
}

func TestR7InterpretationMatrixTimeDirection(t *testing.T) {
	for _, tc := range []struct {
		name string
		hi   time.Duration
		want string
	}{
		{"decreased", 890 * time.Microsecond, "p50: снизилась (отношение 0.89)"},
		{"same", time.Millisecond, "p50: не изменилась (отношение 1.00)"},
		{"increased", 2 * time.Millisecond, "p50: выросла (отношение 2.00)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := interpretationMatrixFixture()
			op := results[2].ops[opCheck]
			op.p50 = tc.hi
			results[2].ops[opCheck] = op
			report := renderMatrixReport(results, time.Second, "fixture")
			interpretationContains(t, report, tc.want)
			interpretationExcludes(t, report, "это цена того, что рабочее")
		})
	}
}

func TestR7InterpretationMatrixUsesTouched(t *testing.T) {
	for _, tc := range []struct {
		name    string
		touched int64
		want    string
	}{
		{"flat", 10, "НЕ РАСТЁТ (плоско)"},
		{"removed_growth", 1000, "растёт ЛИНЕЙНО или хуже"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := interpretationMatrixFixture()
			for _, op := range matrixOps() {
				hi := results[2].ops[op]
				hi.touched, hi.removed = tc.touched, tc.touched-hi.rows
				results[2].ops[op] = hi
			}
			report := renderMatrixReport(results, time.Second, "fixture")
			// Четыре подробных вывода и четыре строки главной таблицы используют
			// объявленную метрику touched. Rows в обеих половинах остаются равны 10.
			if got := strings.Count(report, tc.want); got != 8 {
				t.Errorf("выводов по touched %q: %d, требуется 8", tc.want, got)
			}
			interpretationContains(t, report, "тронуто")
		})
	}
}

func TestR7InterpretationScaleGridCounters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tuples int64
	}{
		{"equal", 10}, {"different", 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := renderReport([][]pointResult{{{point: scalegrid.Point{Axis: scalegrid.AxisN, N: 1}, rows: 10, touched: 10, tuples: tc.tuples}}}, time.Second)
			interpretationContains(t, report, "pg_stat_xact_all_tables")
			interpretationContains(t, report, "Actual Rows × Actual Loops")
			interpretationContains(t, report, "причина расхождения в этом прогоне не установлена")
			interpretationExcludes(t, report, "РАСХОЖДЕНИЕ ДВУХ ПРИБОРОВ ЗАКОННО И ОЖИДАЕМО")
			interpretationContains(t, report, fmt.Sprintf("1→%.2f", float64(tc.tuples)/10))
		})
	}
}

func TestR7InterpretationStrengthDenyComparison(t *testing.T) {
	for _, tc := range []struct {
		name string
		verb int64
		want string
	}{
		{"cheaper", 4, "deny(глагол) дешевле deny(правило) по touched"},
		{"same", 10, "deny(глагол) равен deny(правило) по touched"},
		{"dearer", 20, "deny(глагол) дороже deny(правило) по touched"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			renderVerdictAxis(&b, []strPointResult{{point: scalegrid.StrengthPoint{Axis: scalegrid.AxisN, N: 1}, asks: []askResult{
				{mode: scalegrid.AskAllow, touched: 2},
				{mode: scalegrid.AskDenyVerb, touched: tc.verb},
				{mode: scalegrid.AskDenyLabel, touched: 10},
			}}})
			interpretationContains(t, b.String(), tc.want)
			interpretationExcludes(t, b.String(), "обязан быть ДЕШЕВЛЕ")
		})
	}
}

func TestR7InterpretationListFirstBatchIsNotTotal(t *testing.T) {
	for _, sweeps := range []int{1, 3} {
		t.Run(fmt.Sprintf("sweeps_%d", sweeps), func(t *testing.T) {
			var b strings.Builder
			renderListAxis(&b, []strPointResult{{point: scalegrid.StrengthPoint{Axis: scalegrid.AxisPg, Pg: 7}, asks: []askResult{
				{mode: scalegrid.AskAllow, sweeps: sweeps, rows: 5, touched: 9, scanned: sweeps * 7, p50: time.Second},
			}}})
			report := b.String()
			// При трёх заходах планы двух последних не захвачены: первый в 5 строк
			// совместим и с суммой 6, и с суммой 105. Произведение 3×5 её не определяет.
			interpretationContains(t, report, "сняты с ПЕРВОГО захода")
			interpretationContains(t, report, "ВЕРХНЯЯ ОЦЕНКА (заходов × страница)")
			interpretationContains(t, report, "суммарные rows/touched вызова не измерены")
			interpretationExcludes(t, report, "Стоимость ВЫЗОВА читается по «заходов» × «строк*»")
		})
	}
}

func TestR7InterpretationMeasurementTwins(t *testing.T) {
	t.Run("matrix_flat_rows_and_touched", func(t *testing.T) {
		report := renderMatrixReport(interpretationMatrixFixture(), time.Second, "fixture")
		if got := strings.Count(report, "НЕ РАСТЁТ (плоско)"); got != 8 {
			t.Errorf("выводов для плоских rows и touched: %d, требуется 8", got)
		}
		interpretationContains(t, report, "строк(несущая) 1.00 · тронуто 1.00 · p50 1.00")
	})
	t.Run("matrix_same_plan_observation", func(t *testing.T) {
		report := renderMatrixReport(interpretationMatrixFixture(), time.Second, "fixture")
		// Законное совпадение планов сохраняет положительный вывод; нельзя
		// убрать всякое сравнение вместе с ложным выводом про разные планы.
		if !strings.Contains(report, "План при этом НЕ МЕНЯЛСЯ") && !strings.Contains(report, "планы совпадают во всех точках") {
			t.Error("совпадающие захваченные планы остались без результата сравнения")
		}
	})
	t.Run("strength_measured_delta", func(t *testing.T) {
		var b strings.Builder
		renderVerdictAxis(&b, []strPointResult{{point: scalegrid.StrengthPoint{Axis: scalegrid.AxisN, N: 1}, asks: []askResult{
			{mode: scalegrid.AskAllow, touched: 2},
			{mode: scalegrid.AskDenyVerb, touched: 4},
			{mode: scalegrid.AskDenyLabel, touched: 10},
		}}})
		interpretationContains(t, b.String(), "+8")
		interpretationContains(t, b.String(), "5.00×")
	})
	t.Run("list_captured_first_batch", func(t *testing.T) {
		var b strings.Builder
		renderListAxis(&b, []strPointResult{{point: scalegrid.StrengthPoint{Axis: scalegrid.AxisPg, Pg: 7}, asks: []askResult{
			{mode: scalegrid.AskAllow, sweeps: 3, rows: 5, touched: 9, scanned: 21, p50: time.Second},
		}}})
		// Читаем напечатанные поля реальной строки, а не повторяем арифметику
		// renderer: семь кандидатов, три захода, первый план 5/9, сумма не снята.
		var measured []string
		for _, line := range strings.Split(b.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 9 && fields[0] == "7" && fields[1] == "0%" {
				measured = fields
			}
		}
		if len(measured) != 9 {
			t.Fatal("нет строки с захваченными измерениями List")
		}
		if measured[2] != "3" || measured[4] != "21" || measured[5] != "5" || measured[6] != "9" {
			t.Errorf("захваченные поля List изменены: %v", measured)
		}
	})
}
