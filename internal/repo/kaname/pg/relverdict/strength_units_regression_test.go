// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// Трасса независима от verdictCapture: его reset не может стереть исходный Ask,
// прогрев, повторы и EXPLAIN. Внешние вызовы проходят через настоящий pgx.Tx.
type strengthUnitsTx struct {
	pgx.Tx
	statements []string
}

func (tx *strengthUnitsTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.statements = append(tx.statements, sql)
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func (tx *strengthUnitsTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx.statements = append(tx.statements, sql)
	return tx.Tx.Query(ctx, sql, args...)
}

// Окно ограничено двумя реально исполненными запросами прибора, а не
// арифметическим вычитанием единицы из проверяемого счётчика calls.
func strengthUnitsProductWindows(t *testing.T, statements []string) []int64 {
	t.Helper()
	var counters []int
	for i, sql := range statements {
		if strings.Contains(sql, "FROM pg_stat_xact_all_tables") {
			counters = append(counters, i)
		}
	}
	if len(counters) == 0 || len(counters)%2 != 0 {
		t.Fatalf("прибор не создал пары границ SQL: %v", counters)
	}
	var windows []int64
	for i := 0; i < len(counters); i += 2 {
		product := statements[counters[i]+1 : counters[i+1]]
		if len(product) == 0 {
			t.Fatal("между запросами прибора нет продуктовых SQL")
		}
		for _, sql := range product {
			if strings.HasPrefix(strings.TrimSpace(sql), "EXPLAIN ") {
				t.Fatal("EXPLAIN попал в окно продуктового вызова")
			}
		}
		windows = append(windows, int64(len(product)))
	}
	return windows
}

func strengthUnitsOccurrences(statements []string, exact string) int64 {
	var count int64
	for _, sql := range statements {
		if sql == exact {
			count++
		}
	}
	return count
}

func strengthUnitsExplains(statements []string) int64 {
	var count int64
	for _, sql := range statements {
		if strings.HasPrefix(strings.TrimSpace(sql), "EXPLAIN ") {
			count++
		}
	}
	return count
}

func strengthUnitsCaption(t *testing.T, report, name string, want int64) {
	t.Helper()
	expected := fmt.Sprintf("%s %d", name, want)
	label := strings.Fields(name)
	for _, line := range strings.Split(report, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+len(label) < len(fields); i++ {
			if strings.Join(fields[i:i+len(label)], " ") == name && fields[i+len(label)] == fmt.Sprint(want) {
				return
			}
		}
	}
	t.Errorf("нет отдельной измерительной единицы %q в отчёте:\n%s", expected, report)
}

// N — размер микропосева, допустимый вход seedPoint/growN (int без минимума
// в 100000). N=100 взят с первой законной точки V; Pg=50 и доли 100/0 взяты с
// реальной оси Pg. Меняется только размер локальной фикстуры; глобальная сетка,
// SQL, роли и путь измерителя остаются теми же. Census.Verify подтверждает Given.
func strengthUnitsPoint(axis scalegrid.Axis, share int) scalegrid.StrengthPoint {
	return scalegrid.StrengthPoint{Axis: axis, N: 100, M: 0, L: 1, S: 7, K: 1, Pg: 50, AllowedShare: share}
}

func TestR7StrengthUnitsLiveAsk(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, capture := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	p := strengthUnitsPoint(scalegrid.AxisV, 100)
	p.Pg = 0
	f.seedPoint(t, ctx, p)
	observed := &strengthUnitsTx{Tx: tx}
	r := measureStrengthPoint(t, ctx, observed, capture, f, p)
	axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
	if err != nil {
		t.Fatal(err)
	}
	actualAsks := strengthUnitsOccurrences(observed.statements, relverdict.VerdictQuerySQLForTest(axis))
	windows := strengthUnitsProductWindows(t, observed.statements)
	t.Run("lawful_producer_population", func(t *testing.T) {
		if len(r.asks) != 3 || len(windows) != 3 || actualAsks != 36 || strengthUnitsExplains(observed.statements) != 3 {
			t.Fatalf("не создан законный Ask producer: сценариев=%d окон=%d Ask=%d EXPLAIN=%d", len(r.asks), len(windows), actualAsks, strengthUnitsExplains(observed.statements))
		}
		for _, n := range windows {
			if n != 2 {
				t.Errorf("продуктовых SQL в начальном Ask: %d, требуется 2", n)
			}
		}
	})
	t.Run("product_SQL_excludes_counter", func(t *testing.T) {
		if len(windows) != len(r.asks) {
			t.Fatal("не совпали реальные окна и вопросы")
		}
		for i, a := range r.asks {
			if a.calls != windows[i] {
				t.Errorf("%s: calls=%d, реально продуктовых SQL между границами прибора=%d", a.mode, a.calls, windows[i])
			}
		}
	})
	t.Run("census_records_actual_Ask", func(t *testing.T) {
		if r.census.VerdictsAsked != actualAsks {
			t.Errorf("census Ask=%d, реально исполнено Ask=%d", r.census.VerdictsAsked, actualAsks)
		}
		report := renderStrengthReport([][]scalegrid.StrengthPoint{{p}}, [][]strPointResult{{r}}, time.Second, true)
		interpretationContains(t, report, "единица переписи: вызовы Ask")
	})
	t.Run("report_names_observation_populations", func(t *testing.T) {
		report := renderStrengthReport([][]scalegrid.StrengthPoint{{p}}, [][]strPointResult{{r}}, time.Second, true)
		for _, want := range []struct {
			name string
			n    int64
		}{
			{"сценариев Ask", 3}, {"вызовов Ask", 36}, {"начальных Ask", 3},
			{"прогревочных Ask", 3}, {"измерений времени Ask", 30}, {"EXPLAIN исполнено", 3},
		} {
			strengthUnitsCaption(t, report, want.name, want.n)
		}
		interpretationExcludes(t, report, "по 11 повторов на вопрос")
	})
}

func TestR7StrengthUnitsLiveList(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	for _, share := range []int{100, 0} {
		t.Run(fmt.Sprintf("share_%d", share), func(t *testing.T) {
			ctx := context.Background()
			tx, capture := openProbeTx(t, ctx)
			f := newStrFixture(t, ctx, tx)
			p := strengthUnitsPoint(scalegrid.AxisPg, share)
			f.seedPoint(t, ctx, p)
			observed := &strengthUnitsTx{Tx: tx}
			r := measureStrengthPoint(t, ctx, observed, capture, f, p)
			if len(r.asks) != 1 {
				t.Fatal("не создан один сценарий List")
			}
			a := r.asks[0]
			windows := strengthUnitsProductWindows(t, observed.statements)
			axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("lawful_producer_population", func(t *testing.T) {
				if len(windows) != 1 || strengthUnitsExplains(observed.statements) != 1 || strengthUnitsOccurrences(observed.statements, relverdict.ListQuerySQLForTest(axis)) != int64(a.sweeps) {
					t.Fatal("не совпали одно окно List, его заходы и один EXPLAIN")
				}
				if windows[0] != int64(a.sweeps+1) {
					t.Errorf("продуктовых SQL %d, заходов %d и одно чтение каталога", windows[0], a.sweeps)
				}
				if share == 100 && a.sweeps != 1 {
					t.Errorf("законный близнец не дал один заход: %d", a.sweeps)
				}
				if share == 0 && a.sweeps <= 1 {
					t.Errorf("не создано несколько заходов List: %d", a.sweeps)
				}
			})
			t.Run("product_SQL_excludes_counter", func(t *testing.T) {
				if len(windows) != 1 {
					t.Fatal("нет окна вызова List")
				}
				if a.calls != windows[0] {
					t.Errorf("List calls=%d, продуктовых SQL между границами прибора=%d", a.calls, windows[0])
				}
			})
			t.Run("census_distinguishes_List_from_Ask", func(t *testing.T) {
				if r.census.VerdictsAsked != 1 {
					t.Errorf("census List=%d, реально исполнен один List", r.census.VerdictsAsked)
				}
				report := renderStrengthReport([][]scalegrid.StrengthPoint{{p}}, [][]strPointResult{{r}}, time.Second, true)
				interpretationContains(t, report, "единица переписи: вызовы List")
			})
			t.Run("report_names_single_elapsed", func(t *testing.T) {
				report := renderStrengthReport([][]scalegrid.StrengthPoint{{p}}, [][]strPointResult{{r}}, time.Second, true)
				for _, want := range []struct {
					name string
					n    int64
				}{
					{"сценариев List", 1}, {"вызовов List", 1}, {"измерений времени List", 1}, {"EXPLAIN исполнено", 1},
				} {
					strengthUnitsCaption(t, report, want.name, want.n)
				}
				interpretationExcludes(t, report, "по 11 повторов на вопрос")
			})
		})
	}
}

// Настоящий писатель пишет в изолированный модуль, распознаваемый тем же
// резолвером пути. Файлы отчётов author copy и captures не открываются на запись.
func TestR7StrengthUnitsHeaderDistinguishesMethods(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/PRO-Robotech/kaname\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifactDir := filepath.Join(dir, "internal", "repo", "kaname", "pg", "scalegrid")
	if err := os.MkdirAll(artifactDir, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	grid := scalegrid.Strength()
	r := strPointResult{point: grid[0][0]}
	for _, mode := range scalegrid.AskModes() {
		r.asks = append(r.asks, askResult{mode: mode, rows: 10, touched: 10, p50: time.Millisecond, p99: 2 * time.Millisecond})
	}
	writeStrengthReport(t, scalegrid.Provenance{RunCommand: "fixture: header only"}, grid, [][]strPointResult{{r}}, time.Second, false)
	body, err := os.ReadFile(filepath.Join(artifactDir, "REPORT-R7-2-strength.txt"))
	if err != nil {
		t.Fatal(err)
	}
	header := strings.SplitN(string(body), "ПРОВЕНАНС", 2)[0]
	interpretationContains(t, header, "шесть осей")
	interpretationContains(t, header, "Ask: три сценария")
	interpretationContains(t, header, "Pg: один List")
	interpretationExcludes(t, header, "КАЖДАЯ точка снята ТРЕМЯ вопросами")
}

func TestR7StrengthUnitsTimingLabels(t *testing.T) {
	for _, axis := range []scalegrid.Axis{scalegrid.AxisV, scalegrid.AxisPg} {
		t.Run(string(axis), func(t *testing.T) {
			p := strengthUnitsPoint(axis, 100)
			r := strPointResult{point: p}
			if axis == scalegrid.AxisPg {
				r.asks = []askResult{{mode: scalegrid.AskAllow, sweeps: 1, p50: 3 * time.Millisecond, p99: 3 * time.Millisecond}}
			} else {
				for _, mode := range scalegrid.AskModes() {
					r.asks = append(r.asks, askResult{mode: mode, p50: 3 * time.Millisecond, p99: 9 * time.Millisecond})
				}
			}
			report := renderStrengthReport([][]scalegrid.StrengthPoint{{p}}, [][]strPointResult{{r}}, time.Second, true)
			interpretationContains(t, report, "Ask: p50/p99 по 10 измерениям времени")
			interpretationContains(t, report, "List: время одного вызова, без отдельного прогрева")
			interpretationExcludes(t, report, "p50/p99    — часы; нулевой повтор прогревочный")
		})
	}
}

func TestR7StrengthUnitsTimingTwins(t *testing.T) {
	t.Run("Ask_quantiles_preserved", func(t *testing.T) {
		var b strings.Builder
		p := strengthUnitsPoint(scalegrid.AxisV, 100)
		r := strPointResult{point: p}
		for _, mode := range scalegrid.AskModes() {
			r.asks = append(r.asks, askResult{mode: mode, p50: 3 * time.Millisecond, p99: 9 * time.Millisecond})
		}
		renderVerdictAxis(&b, []strPointResult{r})
		if strings.Count(b.String(), "3ms") != 3 || strings.Count(b.String(), "9ms") != 3 {
			t.Error("реальные квантили Ask исчезли из таблицы")
		}
	})
	t.Run("List_elapsed_preserved", func(t *testing.T) {
		var b strings.Builder
		renderListAxis(&b, []strPointResult{{point: strengthUnitsPoint(scalegrid.AxisPg, 100), asks: []askResult{{mode: scalegrid.AskAllow, sweeps: 1, p50: 3 * time.Millisecond, p99: 3 * time.Millisecond}}}})
		interpretationContains(t, b.String(), "время вызова")
		interpretationContains(t, b.String(), "3ms")
	})
}

// Дочерний запуск того же тестового бинаря позволяет проверить настоящий
// t.Log runStrengthAxis. Буфер текста не подменяет producer и не перечитывает Go.
func TestR7StrengthUnitsLiveLogUsesSingleElapsed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	const child = "KANAME_STRENGTH_UNITS_LOG_CHILD"
	if os.Getenv(child) == "1" {
		runStrengthAxis(t, context.Background(), []scalegrid.StrengthPoint{strengthUnitsPoint(scalegrid.AxisPg, 100)})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := osexec.CommandContext(ctx, os.Args[0], "-test.run=^TestR7StrengthUnitsLiveLogUsesSingleElapsed$", "-test.v")
	cmd.Env = append(os.Environ(), child+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("живой producer лога не исполнился: %v\n%s", err, output)
	}
	interpretationContains(t, string(output), "точка Pg=50")
	interpretationContains(t, string(output), "время вызова")
	interpretationExcludes(t, string(output), ", p50 ")
}
