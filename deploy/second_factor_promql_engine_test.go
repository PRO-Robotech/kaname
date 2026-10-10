// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_promql_engine_test.go — суждение разбором PromQL сверяется с
// НАСТОЯЩИМ движком (kaname#258, круг 3).
//
// Разбор узнаёт форму выражения; звонит ли тревога, решает движок. Слагаемое
// `sum by (reason)(…)` в цепочке `sum(…) + …`, голый `increase(…)` рядом с
// `sum(…)`, селектор с `@ 0` либо `offset` — всё это ФОРМА слагаемого, но
// движок вычисляет такую цепочку в пустоту, и тревога не звонит никогда. Здесь
// каждая форма, о которой суждение выносит вердикт, вычисляется движком того же
// модуля на данных «растёт одна клетка, прочие стоят», и вердикт суждения
// обязан совпасть с исходом движка: суждение, разошедшееся с движком, — находка
// в самом суждении.
package deploy_test

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/histogram"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunkenc"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/prometheus/prometheus/util/annotations"
	"github.com/stretchr/testify/require"
)

// engineEvalAt — момент вычисления: двадцатая минута ряда; первые десять
// минут стоят все клетки, следующие десять растёт только испытуемая.
const engineEvalAt = 20 * time.Minute

// engineSeries — клетки, которые загружаются в хранилище движка: все клетки
// производителя второго фактора и клетки соседних рядов, которые читают правила
// и формы проб. Метка `job` — метка цели, которую дописывает сбор: она есть у
// каждого живого ряда и делает видимым расхождение наборов меток.
func engineSeries() []cellTerm {
	var out []cellTerm
	for _, v := range secondFactorProducerValues() {
		out = append(out, v.cell)
	}
	for _, o := range []string{"store-failed", "verifier-issue", "capacity-exhausted"} {
		out = append(out, cellTerm{series: "kaname_login_outcomes_total", labels: map[string]string{"outcome": o}})
	}
	out = append(out, cellTerm{series: "kaname_password_verification_outcomes_total",
		labels: map[string]string{"outcome": "capacity-exhausted"}})
	for _, series := range []string{"kaname_registration_outcomes_total", "kaname_recovery_request_outcomes_total",
		"kaname_recovery_completion_outcomes_total"} {
		out = append(out, cellTerm{series: series, labels: map[string]string{"outcome": "store-failed"}})
	}
	return out
}

// floatSample — точка ряда счётчика.
type floatSample struct {
	t int64
	f float64
}

func (s floatSample) T() int64                    { return s.t }
func (floatSample) ST() int64                     { return 0 }
func (s floatSample) F() float64                  { return s.f }
func (floatSample) H() *histogram.Histogram       { return nil }
func (floatSample) FH() *histogram.FloatHistogram { return nil }
func (floatSample) Type() chunkenc.ValueType      { return chunkenc.ValFloat }
func (s floatSample) Copy() chunks.Sample         { return s }

// memSeriesSet — набор рядов, отобранных хранилищем.
type memSeriesSet struct {
	list []storage.Series
	i    int
}

func (m *memSeriesSet) Next() bool                      { m.i++; return m.i < len(m.list) }
func (m *memSeriesSet) At() storage.Series              { return m.list[m.i] }
func (*memSeriesSet) Err() error                        { return nil }
func (*memSeriesSet) Warnings() annotations.Annotations { return nil }

// engineStorage — хранилище в памяти: каждая клетка — ряд с меткой цели `job`,
// точка в минуту с нуля до engineEvalAt. Клетка grow стоит десять минут и
// растёт по единице следующие десять; прочие стоят. Отбор — настоящими
// matcher'ами движка.
func engineStorage(t *testing.T, grow *cellTerm) storage.Queryable {
	t.Helper()
	var all []storage.Series
	growFound := grow == nil
	for _, c := range engineSeries() {
		b := labels.NewScratchBuilder(len(c.labels) + 2)
		b.Add(labels.MetricName, c.series)
		b.Add("job", "kaname")
		for k, v := range c.labels {
			b.Add(k, v)
		}
		b.Sort()
		growing := grow != nil && c.series == grow.series && sameCell(c.labels, grow.labels)
		growFound = growFound || growing
		var samples []chunks.Sample
		for m := int64(0); m <= int64(engineEvalAt/time.Minute); m++ {
			v := 0.0
			if growing && m > 10 {
				v = float64(m - 10)
			}
			samples = append(samples, floatSample{t: m * int64(time.Minute/time.Millisecond), f: v})
		}
		all = append(all, storage.NewListSeries(b.Labels(), samples))
	}
	require.Truef(t, growFound, "клетки %s нет среди загружаемых — движок судил бы не её", grow)
	sort.Slice(all, func(i, j int) bool { return labels.Compare(all[i].Labels(), all[j].Labels()) < 0 })
	return &storage.MockQueryable{MockQuerier: &storage.MockQuerier{
		SelectMockFunction: func(_ bool, _ *storage.SelectHints, ms ...*labels.Matcher) storage.SeriesSet {
			var out []storage.Series
			for _, s := range all {
				lset := s.Labels()
				ok := true
				for _, m := range ms {
					if !m.Matches(lset.Get(m.Name)) {
						ok = false
						break
					}
				}
				if ok {
					out = append(out, s)
				}
			}
			return &memSeriesSet{list: out, i: -1}
		},
	}}
}

// engineFires — вернул ли движок непустой результат выражения, когда растёт
// клетка grow (nil — не растёт ничего). Непустой результат правила тревоги —
// тревога.
func engineFires(t *testing.T, expr string, grow *cellTerm) bool {
	t.Helper()
	engine := promql.NewEngine(promql.EngineOpts{
		MaxSamples:       10000,
		Timeout:          10 * time.Second,
		EnableAtModifier: true,
		LookbackDelta:    5 * time.Minute,
	})
	t.Cleanup(func() { _ = engine.Close() })
	q, err := engine.NewInstantQuery(context.Background(), engineStorage(t, grow), nil, expr, time.Unix(0, 0).Add(engineEvalAt))
	require.NoErrorf(t, err, "движок не принял выражение:\n%s", expr)
	defer q.Close()
	res := q.Exec(context.Background())
	require.NoErrorf(t, res.Err, "движок не вычислил выражение:\n%s", expr)
	vec, err := res.Vector()
	require.NoErrorf(t, err, "выражение правила вычислилось не в вектор:\n%s", expr)
	return len(vec) > 0
}

// engineReadsCell — СЧИТАЕТ ли выражение клетку по исходу движка: звонит,
// когда растёт она, и молчит, когда не растёт ничего.
func engineReadsCell(t *testing.T, expr string, c cellTerm) bool {
	t.Helper()
	return engineFires(t, expr, &c) && !engineFires(t, expr, nil)
}

// Предпосылка: движок различает «растёт клетка» и «не растёт ничего» на
// каноне; без этого совпадение с суждением ничего не значило бы.
func TestPromQLEnginePremise_CanonFiresOnlyWhenItsCellGrows(t *testing.T) {
	canon := expressionFormsBase + "\n  + sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m])) > 0"
	require.True(t, engineFires(t, canon, &refusalUnavailableCell), "канон не звонит на рост своей клетки")
	require.False(t, engineFires(t, canon, nil), "канон звонит, когда не растёт ничего")
	other := cellTerm{series: refusalUnavailableCell.series, labels: map[string]string{"reason": "not-enrolled"}}
	require.False(t, engineFires(t, canon, &other), "канон звонит на рост чужой клетки")
}

// Каждая форма таблицы суждения вычисляется движком: вердикты совпадают.
func TestSecondFactorExpressionFormsAgreeWithTheEngine(t *testing.T) {
	forms := secondFactorExpressionForms()
	require.NotEmpty(t, forms, "таблица форм пуста — сверять нечего")
	agreed := 0
	for name, tc := range forms {
		t.Run(name, func(t *testing.T) {
			require.Equalf(t, tc.reads, engineReadsCell(t, tc.expr, refusalUnavailableCell),
				"ожидание таблицы разошлось с движком:\n%s", tc.expr)
			agreed++
		})
	}
	t.Logf("ПЕРЕПИСЬ: форм %d · совпало с движком %d", len(forms), agreed)
}

// Каждая форма, в которой правило считает клетку стороны вызывающего, звонит
// на её рост по исходу движка: находка суждения — не выдумка.
func TestCallerSideFormsRingByTheEngine(t *testing.T) {
	forms := callerSideCountingForms()
	require.NotEmpty(t, forms, "таблица форм пуста — сверять нечего")
	for name, tc := range forms {
		t.Run(name, func(t *testing.T) {
			require.Truef(t, engineFires(t, tc.expr, &tc.cell),
				"форма не звонит на рост клетки %s — находка о ней была бы ложной:\n%s", tc.cell, tc.expr)
		})
	}
}

// Поставляемые правила вычисляются движком: каждое требование «правило →
// клетка» звонит на рост своей клетки и молчит без него — на каждом профиле.
// Суждение разбором и движок отвечают об одном и том же объекте одинаково.
func TestShippedRulesReadTheirCellsByTheEngine(t *testing.T) {
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			byName := map[string]alertRule{}
			for _, rule := range rules {
				byName[rule.Alert] = rule
			}
			judged := 0
			for alert, cells := range secondFactorCellDemands() {
				rule, ok := byName[alert]
				require.Truef(t, ok, "правила %s нет в объекте", alert)
				for _, c := range cells {
					reads, why := exprReadsCell(rule.Expr, c)
					require.Truef(t, engineReadsCell(t, rule.Expr, c),
						"движок: правило %s не звонит на рост клетки %s:\n%s", alert, c, rule.Expr)
					require.Truef(t, reads, "разбор: правило %s не считает клетку %s: %s", alert, c, why)
					judged++
				}
			}
			t.Logf("ПЕРЕПИСЬ (%s): требований сверено с движком %d", r.name, judged)
			require.NotZero(t, judged, "требований ноль — сверять нечего")
		})
	}
}
