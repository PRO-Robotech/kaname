// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// absence_rules_ring_without_series_test.go — правило «на отсутствие события»
// звонит и тогда, когда РЯДА НЕТ ВОВСЕ (kaname#759).
//
// Выражение `increase(x[…]) == 0` судит ряд, который есть и стоит. Ряда, который
// не собирается, у него нет: `increase` от пустоты — пустота, сравнение пустоты
// с нулём — пустота, и тревога молчит ровно там, где замера нет совсем. Это и
// есть главный случай: цель не собирается (нет объекта сбора, сменился порт,
// под не поднялся), и ни одно правило об этом не говорит.
//
// Суждение выносит не разбор текста, а движок правил того же модуля, что
// исполняет `promtool test rules`: данные грузятся записью рядов `load`,
// правило вычисляется поминутно с учётом выдержки `for`, исход — состояние
// тревоги. Предмет — правила ОПУБЛИКОВАННОЙ страницы: объект чарта обязан с ней
// совпадать, и это держит TestDeliveredAlertRulesMatchThePublishedPage, а эта
// проба исполняется и там, где helm нет.
//
// Каждое отрицательное утверждение — в паре с положительным близнецом: тот же
// набор правил на живой цели МОЛЧИТ, а выключенная оператором возможность не
// звонит. Без близнеца правило «звони всегда» прошло бы эту пробу.
package deploy_test

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb/chunks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// absenceRules — правила, звонящие на отсутствие события. Перепись сверяется с
// выводом из страницы (сравнение с нулём в выражении) в обе стороны: правило,
// добавленное на страницу без записи здесь, и запись без правила — обе красные.
var absenceRules = []string{
	"KanameExpiredCredentialReclaimStalled",
	"KanameIdentityLedgerUnsampled",
	"KanameReadinessUnprobed",
	"KanameSigningKeySweeperSilent",
}

// absenceEvalSpan — сколько минут правило вычисляется: больше самого длинного
// окна (2h) плюс самой длинной выдержки (30m), чтобы исход не зависел от
// разгона окна.
const absenceEvalSpan = 4 * time.Hour

// absenceSeries — ряд с минутным шагом от нуля до конца окна: метки выдачи
// (как у производителя) и наклон. Наклон 0 — ряд стоит на base, 1 — растёт на
// единицу в минуту.
type absenceSeries struct {
	labels map[string]string
	base   float64
	slope  float64
}

func series(name string, base, slope float64, kv ...string) absenceSeries {
	l := map[string]string{labels.MetricName: name}
	for i := 0; i+1 < len(kv); i += 2 {
		l[kv[i]] = kv[i+1]
	}
	return absenceSeries{labels: l, base: base, slope: slope}
}

var (
	// Цель, которую собирают, но которая не kaname: Prometheus живой, kaname в
	// нём нет.
	seriesForeignTarget = series("up", 1, 0, "job", "other")

	seriesBuildInfo        = series("kaname_build_info", 1, 0, "version", "v", "revision", "r")
	seriesLedgerGrows      = series("kaname_identity_ledger_samples_total", 0, 1, "outcome", "ok")
	seriesLedgerFlat       = series("kaname_identity_ledger_samples_total", 0, 0, "outcome", "ok")
	seriesReadinessGrows   = series("kaname_readiness_dependency_checks_total", 0, 1, "dependency", "postgres", "outcome", "ready")
	seriesReadinessFlat    = series("kaname_readiness_dependency_checks_total", 0, 0, "dependency", "postgres", "outcome", "ready")
	seriesReclaimOn        = series("kaname_expired_credential_reclaim_enabled", 1, 0)
	seriesReclaimOff       = series("kaname_expired_credential_reclaim_enabled", 0, 0)
	seriesReclaimPassGrows = series("kaname_expired_credential_reclaim_passes_total", 0, 1, "outcome", "ok")
	seriesReclaimPassFlat  = series("kaname_expired_credential_reclaim_passes_total", 0, 0, "outcome", "ok")
	seriesSweepGrows       = series("kaname_signing_key_events_total", 0, 1, "event", "swept")
	seriesSweepFlat        = series("kaname_signing_key_events_total", 0, 0, "event", "swept")
)

// absenceScenario — состояние Prometheus и ожидаемый исход по каждому правилу.
type absenceScenario struct {
	name   string
	series []absenceSeries
	firing map[string]bool
}

func absenceScenarios() []absenceScenario {
	all := func(v bool) map[string]bool {
		m := map[string]bool{}
		for _, r := range absenceRules {
			m[r] = v
		}
		return m
	}
	return []absenceScenario{
		{
			// ПРЕДМЕТ ЗАДАЧИ: цели kaname в Prometheus нет. Каждое правило о
			// тишине обязано звонить — молчание здесь неотличимо от исправности.
			name:   "цели kaname нет",
			series: []absenceSeries{seriesForeignTarget},
			firing: all(true),
		},
		{
			// Близнец: цель живая, каждый замер идёт — не звонит ни одно.
			name: "цель живая, всё идёт",
			series: []absenceSeries{seriesForeignTarget, seriesBuildInfo, seriesLedgerGrows, seriesReadinessGrows,
				seriesReclaimOn, seriesReclaimPassGrows, seriesSweepGrows},
			firing: all(false),
		},
		{
			// Прежнее обещание сохранено: ряд есть и стоит — звонят все.
			name: "цель живая, всё стоит",
			series: []absenceSeries{seriesForeignTarget, seriesBuildInfo, seriesLedgerFlat, seriesReadinessFlat,
				seriesReclaimOn, seriesReclaimPassFlat, seriesSweepFlat},
			firing: all(true),
		},
		{
			// Выключенное оператором не звонит: своя чеканка выключена — ряда
			// сметателя нет при живой цели; уборка выключена — ряд проходов
			// стоит при выключателе 0.
			name: "цель живая, чеканка и уборка выключены",
			series: []absenceSeries{seriesForeignTarget, seriesBuildInfo, seriesLedgerGrows, seriesReadinessGrows,
				seriesReclaimOff, seriesReclaimPassFlat},
			firing: all(false),
		},
	}
}

// absenceStorage — хранилище в памяти, отбор настоящими matcher'ами движка.
func absenceStorage(in []absenceSeries) storage.Queryable {
	var all []storage.Series
	for _, s := range in {
		b := labels.NewScratchBuilder(len(s.labels))
		for k, v := range s.labels {
			b.Add(k, v)
		}
		b.Sort()
		var samples []chunks.Sample
		for m := int64(0); m <= int64(absenceEvalSpan/time.Minute); m++ {
			samples = append(samples, floatSample{t: m * int64(time.Minute/time.Millisecond), f: s.base + s.slope*float64(m)})
		}
		all = append(all, storage.NewListSeries(b.Labels(), samples))
	}
	sort.Slice(all, func(i, j int) bool { return labels.Compare(all[i].Labels(), all[j].Labels()) < 0 })
	return &storage.MockQueryable{MockQuerier: &storage.MockQuerier{
		SelectMockFunction: func(_ bool, _ *storage.SelectHints, ms ...*labels.Matcher) storage.SeriesSet {
			var out []storage.Series
			for _, s := range all {
				ok := true
				for _, m := range ms {
					if !m.Matches(s.Labels().Get(m.Name)) {
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

// absenceRuleFires — звонит ли правило к концу окна: выражение вычисляется
// движком поминутно, и тревога «горит», когда результат был непуст без
// перерыва не меньше выдержки `for` — то же правило перехода «ожидает →
// горит», что у вычислителя правил Prometheus. Вычислитель правил целиком не
// берётся: его пакет тянет в граф модулей обнаружение целей чужих платформ.
func absenceRuleFires(t *testing.T, rule alertRule, in []absenceSeries) bool {
	t.Helper()
	var hold time.Duration
	if rule.For != "" {
		d, err := time.ParseDuration(rule.For)
		require.NoErrorf(t, err, "выдержка правила %s не разбирается: %q", rule.Alert, rule.For)
		hold = d
	}
	engine := promql.NewEngine(promql.EngineOpts{MaxSamples: 1000000, Timeout: 10 * time.Second, LookbackDelta: 5 * time.Minute})
	t.Cleanup(func() { _ = engine.Close() })
	st := absenceStorage(in)
	start := time.Unix(0, 0).UTC()
	var activeSince *time.Time
	for ts := start; !ts.After(start.Add(absenceEvalSpan)); ts = ts.Add(time.Minute) {
		q, err := engine.NewInstantQuery(context.Background(), st, nil, rule.Expr, ts)
		require.NoErrorf(t, err, "движок не принял выражение правила %s:\n%s", rule.Alert, rule.Expr)
		res := q.Exec(context.Background())
		require.NoErrorf(t, res.Err, "движок не вычислил правило %s в %s", rule.Alert, ts.Sub(start))
		vec, err := res.Vector()
		require.NoErrorf(t, err, "правило %s вычислилось не в вектор", rule.Alert)
		q.Close()
		switch {
		case len(vec) == 0:
			activeSince = nil
		case activeSince == nil:
			at := ts
			activeSince = &at
		}
	}
	end := start.Add(absenceEvalSpan)
	return activeSince != nil && end.Sub(*activeSince) >= hold
}

// pageAbsenceRules — правила тишины со страницы: перепись выводом (сравнение с
// нулём) сверяется со списком absenceRules в обе стороны.
func pageAbsenceRules(t *testing.T) map[string]alertRule {
	t.Helper()
	root, err := surfaceroster.IAMRoot(".")
	require.NoError(t, err, "корень дерева службы")
	page, _ := pageAlertRules(t, root)
	require.NotEmpty(t, page, "на странице не найдено ни одного правила — судить нечего, это не зелёное")

	byName := map[string]alertRule{}
	var derived []string
	for _, r := range page {
		byName[r.Alert] = r
		if strings.Contains(strings.Join(strings.Fields(r.Expr), " "), "== 0") {
			derived = append(derived, r.Alert)
		}
	}
	sort.Strings(derived)
	t.Logf("перепись: правил на странице %d · сравнивающих с нулём %d %v", len(page), len(derived), derived)
	require.Equal(t, absenceRules, derived, "перепись правил тишины разошлась со страницей: "+
		"новое правило на отсутствие события обязано быть судимо этой пробой, снятое — снято из списка")

	out := map[string]alertRule{}
	for _, name := range absenceRules {
		out[name] = byName[name]
	}
	return out
}

// TestAbsenceRulesRingWhenTheSeriesIsNotCollected — kaname#759.
func TestAbsenceRulesRingWhenTheSeriesIsNotCollected(t *testing.T) {
	page := pageAbsenceRules(t)
	for _, sc := range absenceScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			for _, name := range absenceRules {
				got := absenceRuleFires(t, page[name], sc.series)
				want := sc.firing[name]
				if want {
					assert.Truef(t, got, "%s молчит, а должно звонить (%s): правило на отсутствие события, "+
						"молчащее без ряда, молчит именно там, где замера нет совсем\nexpr: %s", name, sc.name, page[name].Expr)
				} else {
					assert.Falsef(t, got, "%s звонит, а должно молчать (%s): правило, звонящее на живой "+
						"цели либо на выключенной оператором возможности, перестанут читать\nexpr: %s", name, sc.name, page[name].Expr)
				}
			}
		})
	}
}

// Предпосылка: движок различает «ряд растёт» и «ряд стоит» на каноне —
// без этого исход сценариев выше ничего не значил бы.
func TestAbsenceEnginePremise_FlatAndGrowingAreTold(t *testing.T) {
	canon := alertRule{Alert: "Canon", Expr: `increase(kaname_build_info[10m]) == 0`, For: "5m"}
	require.True(t, absenceRuleFires(t, canon, []absenceSeries{series("kaname_build_info", 1, 0)}),
		"канон на стоящем ряде обязан звонить")
	require.False(t, absenceRuleFires(t, canon, []absenceSeries{series("kaname_build_info", 0, 1)}),
		"канон на растущем ряде обязан молчать")
	// Выдержка соблюдается: выражение, ставшее непустым за минуту до конца
	// окна, ещё не горит.
	late := alertRule{Alert: "Late", Expr: `kaname_build_info > 239`, For: "5m"}
	require.False(t, absenceRuleFires(t, late, []absenceSeries{series("kaname_build_info", 0, 1)}),
		"правило, непустое меньше выдержки, гореть не обязано")
}
