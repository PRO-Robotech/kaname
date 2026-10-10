// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_alert_cells_test.go — правила собственной полосы входа СЧИТАЮТ
// отказы второго фактора нашей стороны (kaname#258, п.1; перенесённое из #245).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Материал второго фактора, который не открывается ни одним ключом перечня, —
// отказ НАШЕЙ стороны: человек с верным кодом получает 503, и этот исход сам не
// проходит. Производитель пишет его ПАРОЙ клеток (исход предъявления
// `material-unreadable` и отказ `unavailable`) на каждом глаголе и обоих
// способах, а правило `KanameLoginLaneFailing` прежде считало только хранилище и
// проверяющего пароля: оператор узнавал об отказе от людей, а не от тревоги.
//
// Ёмкость проверяющего пароля у `lookup_secret` — та же ёмкость, что у входа
// (один проверяющий), и правило `KanameLoginVerifierCapacityExhausted` обязано
// звонить на её исчерпание и здесь. Тем же проверяющим сверяются пароль при
// повышении уровня и секрет клиента в церемонии; их исчерпание пишет только
// ряд проверяющего (`kaname_password_verification_outcomes_total`), и правило
// ёмкости обязано считать и его.
//
// Выражение судится РАЗБОРОМ PromQL: клетка засчитывается, только если она —
// слагаемое левой части сравнения правила (`sum(increase(…))` либо
// `increase(…)`). Слагаемое в комментарии, `0 * sum(…)` и `… unless sum(…)`
// клетку не считают.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	С1  в рендере каждого поставляемого профиля правило несёт ОТБОР клетки — по
//	    имени ряда и значениям меток, взятым у производителя, а не литералом;
//	С2  отбор стоит В ТОМ правиле, которому принадлежит: слагаемое в соседнем
//	    правиле не засчитывается (окно строк по тексту зачло бы его);
//	С3  клетка, которую читает правило, ПРЕДЗАВЕДЕНА производителем: `A + пусто`
//	    в PromQL — пусто, и правило со слагаемым без клетки оглохло бы целиком.
//
// Совпадение объекта со страницей держит TestDeliveredAlertRulesMatchThePublishedPage;
// здесь судится только, что совпадающее несёт нужное.
package deploy_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// cellTerm — клетка ряда, которую правило обязано читать: имя ряда и точные
// значения меток.
type cellTerm struct {
	series string
	labels map[string]string
}

func (c cellTerm) String() string {
	keys := make([]string, 0, len(c.labels))
	for k := range c.labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, c.labels[k]))
	}
	return c.series + "{" + strings.Join(parts, ",") + "}"
}

// secondFactorCellDemands — какое правило какую клетку читает. Значения — у
// производителя: переименование клетки роняет сборку либо эту пробу, а не
// оставляет правило ждать ряд, которого нет.
func secondFactorCellDemands() map[string][]cellTerm {
	return map[string][]cellTerm{
		"KanameLoginLaneFailing": {{
			series: metrics.SecondFactorRefusalsMetric,
			labels: map[string]string{"reason": string(humansession.RefusalUnavailable)},
		}},
		"KanameLoginVerifierCapacityExhausted": {{
			series: metrics.PasswordVerificationOutcomesMetric,
			labels: map[string]string{"outcome": string(passwordverify.OutcomeCapacityExhausted)},
		}, {
			series: metrics.SecondFactorPresentationsMetric,
			labels: map[string]string{
				"method":  assurance.MethodLookupSecret.String(),
				"outcome": string(humansession.PresentationCapacityExhausted),
			},
		}},
	}
}

// exprMatcherRe — отбор метки в ТЕКСТОВОЙ ВЫДАЧЕ производителя (формат
// экспозиции: значение всегда в двойных кавычках). Выражения правил этим не
// читаются — их читает разбор PromQL ([exprCountedCells]).
var exprMatcherRe = regexp.MustCompile(`([a-z_][a-z0-9_]*)\s*(=~|!~|!=|=)\s*"((?:[^"\\]|\\.)*)"`)

// selectorLabels — точные отборы селектора; ok=false, если среди отборов есть
// неточный (`=~`, `!=`, `!~`): такой селектор клеткой не является.
func selectorLabels(inside string) (map[string]string, bool) {
	got := map[string]string{}
	for _, mm := range exprMatcherRe.FindAllStringSubmatch(inside, -1) {
		if mm[2] != "=" {
			return nil, false
		}
		got[mm[1]] = mm[3]
	}
	return got, true
}

// sameCell — ровно те же метки с теми же значениями: лишний отбор сужает
// клетку, недостающий — расширяет.
func sameCell(got, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			return false
		}
	}
	return true
}

// promqlParser — тот же разборщик, что у сервера правил. Текстовый поиск по
// выражению засчитывал слагаемое, перенесённое в комментарий (`# + sum(…)`), и
// не узнавал законных написаний той же клетки (одинарные кавычки, имя ряда
// отбором `__name__`): судить надо узел разбора, а не слово.
var promqlParser = parser.NewParser(parser.Options{})

// exprCountedCells — клетки, которые выражение СЧИТАЕТ: слагаемые левой части
// сравнения правила. Слагаемое — `sum(increase(ряд{…}[окно]))` либо
// `increase(ряд{…}[окно])`, в любых скобках. Селектор вне такого слагаемого не
// засчитывается: `0 * sum(…)` и `… unless sum(…)` держат клетку в тексте, но
// не дают ей поднять тревогу. Селектор с неточным отбором (`=~`, `!=`, `!~`)
// клеткой не является.
func exprCountedCells(expr string) ([]cellTerm, error) {
	root, err := promqlParser.ParseExpr(expr)
	if err != nil {
		return nil, err
	}
	counted := unparen(root)
	if be, ok := counted.(*parser.BinaryExpr); ok && be.Op.IsComparisonOperator() {
		counted = be.LHS
	}
	var cells []cellTerm
	for _, term := range additiveTerms(counted) {
		vs, ok := increaseSelector(term)
		if !ok {
			continue
		}
		if c, exact := selectorCell(vs); exact {
			cells = append(cells, c)
		}
	}
	return cells, nil
}

func unparen(e parser.Expr) parser.Expr {
	for {
		p, ok := e.(*parser.ParenExpr)
		if !ok {
			return e
		}
		e = p.Expr
	}
}

// additiveTerms — слагаемые цепочки `a + b + …`; прочие операторы слагаемых не
// раскрывают.
func additiveTerms(e parser.Expr) []parser.Expr {
	e = unparen(e)
	if be, ok := e.(*parser.BinaryExpr); ok && be.Op == parser.ADD {
		return append(additiveTerms(be.LHS), additiveTerms(be.RHS)...)
	}
	return []parser.Expr{e}
}

// increaseSelector — селектор слагаемого `sum(increase(…))` либо `increase(…)`.
func increaseSelector(e parser.Expr) (*parser.VectorSelector, bool) {
	e = unparen(e)
	if ag, ok := e.(*parser.AggregateExpr); ok {
		if ag.Op != parser.SUM {
			return nil, false
		}
		e = unparen(ag.Expr)
	}
	call, ok := e.(*parser.Call)
	if !ok || call.Func == nil || call.Func.Name != "increase" || len(call.Args) != 1 {
		return nil, false
	}
	ms, ok := unparen(call.Args[0]).(*parser.MatrixSelector)
	if !ok {
		return nil, false
	}
	vs, ok := ms.VectorSelector.(*parser.VectorSelector)
	return vs, ok
}

// selectorCell — клетка селектора: имя ряда (из имени либо из отбора
// `__name__`) и точные отборы меток; exact=false — среди отборов неточный.
func selectorCell(vs *parser.VectorSelector) (cellTerm, bool) {
	c := cellTerm{series: vs.Name, labels: map[string]string{}}
	for _, m := range vs.LabelMatchers {
		if m.Type != labels.MatchEqual {
			return cellTerm{}, false
		}
		if m.Name == labels.MetricName {
			c.series = m.Value
			continue
		}
		c.labels[m.Name] = m.Value
	}
	return c, c.series != ""
}

// exprReadsCell — считает ли выражение клетку: слагаемое с ровно таким рядом и
// ровно такими точными отборами. Неразборное выражение не считает ничего —
// сервер правил его не примет.
func exprReadsCell(expr string, c cellTerm) bool {
	cells, err := exprCountedCells(expr)
	if err != nil {
		return false
	}
	for _, got := range cells {
		if got.series == c.series && sameCell(got.labels, c.labels) {
			return true
		}
	}
	return false
}

// cellDemandCensus — объём осмотренного одним суждением.
type cellDemandCensus struct {
	rules   int // правил осмотрено
	demands int // требований (правило × клетка)
	matched int // требований, найденных в СВОЁМ правиле
}

// judgeSecondFactorCells — суждение над ПРОИЗВОЛЬНЫМ набором правил: инъекция
// зовёт его же. Находка — правило, не читающее свою клетку, либо правило,
// которого в наборе нет.
func judgeSecondFactorCells(rules []alertRule, demands map[string][]cellTerm) (cellDemandCensus, []string) {
	census := cellDemandCensus{rules: len(rules)}
	byName := map[string]alertRule{}
	for _, r := range rules {
		byName[r.Alert] = r
	}
	var findings []string
	for alert, cells := range demands {
		for _, c := range cells {
			census.demands++
			r, ok := byName[alert]
			if !ok {
				findings = append(findings, alert+": правила нет в наборе — клетку "+c.String()+" не читает никто")
				continue
			}
			if !exprReadsCell(r.Expr, c) {
				findings = append(findings, alert+": выражение не читает клетку "+c.String())
				continue
			}
			census.matched++
		}
	}
	sort.Strings(findings)
	return census, findings
}

// TestOwnLaneAlertsCountTheSecondFactorCells — С1 и С2 на каждом поставляемом
// профиле.
func TestOwnLaneAlertsCountTheSecondFactorCells(t *testing.T) {
	demands := secondFactorCellDemands()
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSecondFactorCells(rules, demands)
			t.Logf("ПЕРЕПИСЬ клеток второго фактора в правилах (%s): правил %d · требований %d · найдено в своём правиле %d · находок %d",
				r.name, census.rules, census.demands, census.matched, len(findings))
			require.NotZero(t, census.demands, "требований ноль — проверка беспредметна")
			require.Emptyf(t, findings, "правило собственной полосы входа не считает отказ второго фактора "+
				"НАШЕЙ стороны — человек получает отказ, тревога молчит:\n  %s", strings.Join(findings, "\n  "))
		})
	}
}

// TestSecondFactorCellsTheRulesReadArePreSeeded — С3: каждая клетка, которую
// читают правила, есть в ВЫДАЧЕ производителя с нулём до первого события.
func TestSecondFactorCellsTheRulesReadArePreSeeded(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.LoginLaneRecorder()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code, "выдача производителя не читается")

	exposed := 0
	var cells []struct {
		series string
		labels map[string]string
	}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		m := exposedCellRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		exposed++
		labels, ok := selectorLabels(m[2])
		if !ok {
			continue
		}
		cells = append(cells, struct {
			series string
			labels map[string]string
		}{m[1], labels})
	}

	seen := 0
	for _, demands := range secondFactorCellDemands() {
		for _, c := range demands {
			found := false
			for _, e := range cells {
				if e.series == c.series && sameCell(e.labels, c.labels) {
					found = true
					break
				}
			}
			require.Truef(t, found, "клетка %s НЕ предзаведена производителем: "+
				"`A + пусто` в PromQL — пусто, и правило оглохло бы целиком до первого события", c)
			seen++
		}
	}
	t.Logf("ПЕРЕПИСЬ предзаведённых клеток: клеток в выдаче %d · требуемых клеток проверено %d", exposed, seen)
	require.NotZero(t, exposed, "выдача производителя пуста — судить нечего")
	require.NotZero(t, seen, "требуемых клеток ноль — проверка беспредметна")
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

func injectedRules(failingExpr, capacityExpr string) []alertRule {
	return []alertRule{
		{Alert: "KanameLoginLaneFailing", Expr: failingExpr},
		{Alert: "KanameLoginVerifierCapacityExhausted", Expr: capacityExpr},
	}
}

const (
	lawfulFailingExpr = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))
  + sum(increase(kaname_second_factor_refusals_total{reason="unavailable"}[10m])) > 0`
	lawfulCapacityExpr = `sum(increase(kaname_login_outcomes_total{outcome="capacity-exhausted"}[10m]))
  + sum(increase(kaname_password_verification_outcomes_total{outcome="capacity-exhausted"}[10m]))
  + sum(increase(kaname_second_factor_presentations_total{method="lookup_secret",outcome="capacity-exhausted"}[10m])) > 0`
)

func TestSecondFactorCellsInjection_LawfulTwinIsSilent(t *testing.T) {
	census, findings := judgeSecondFactorCells(injectedRules(lawfulFailingExpr, lawfulCapacityExpr), secondFactorCellDemands())
	require.Empty(t, findings)
	require.Equal(t, census.demands, census.matched)
}

func TestSecondFactorCellsInjection_DroppedTermIsFound(t *testing.T) {
	dropped := `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m])) > 0`
	_, findings := judgeSecondFactorCells(injectedRules(dropped, lawfulCapacityExpr), secondFactorCellDemands())
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "KanameLoginLaneFailing")
	require.Contains(t, findings[0], `reason="unavailable"`)
}

// Слагаемое, стоящее в СОСЕДНЕМ правиле, своё правило не спасает.
func TestSecondFactorCellsInjection_TermInTheNeighbourIsFound(t *testing.T) {
	neighbourCarries := `increase(kaname_login_outcomes_total{outcome="capacity-exhausted"}[10m])
  + sum(increase(kaname_second_factor_refusals_total{reason="unavailable"}[10m]))
  + sum(increase(kaname_password_verification_outcomes_total{outcome="capacity-exhausted"}[10m]))
  + sum(increase(kaname_second_factor_presentations_total{method="lookup_secret",outcome="capacity-exhausted"}[10m])) > 0`
	dropped := `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m])) > 0`
	_, findings := judgeSecondFactorCells(injectedRules(dropped, neighbourCarries), secondFactorCellDemands())
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "KanameLoginLaneFailing")
}

// Клетка, суженная или расширенная иначе, — не та клетка.
func TestSecondFactorCellsInjection_OtherCellOfTheSameSeriesIsFound(t *testing.T) {
	for name, expr := range map[string]string{
		"другое значение":     `sum(increase(kaname_second_factor_refusals_total{reason="not-enrolled"}[10m])) > 0`,
		"отрицание":           `sum(increase(kaname_second_factor_refusals_total{reason!="unavailable"}[10m])) > 0`,
		"лишний отбор":        `sum(increase(kaname_second_factor_refusals_total{reason="unavailable",pod="x"}[10m])) > 0`,
		"капасити без метода": `sum(increase(kaname_second_factor_presentations_total{outcome="capacity-exhausted"}[10m])) > 0`,
	} {
		t.Run(name, func(t *testing.T) {
			census, findings := judgeSecondFactorCells(injectedRules(expr, expr), secondFactorCellDemands())
			require.Zero(t, census.matched, "ни одно требование не выполнено: %v", findings)
			require.Len(t, findings, census.demands, "каждое требование — находка: %v", findings)
			joined := strings.Join(findings, "\n")
			require.Contains(t, joined, "KanameLoginLaneFailing:")
			require.Contains(t, joined, "KanameLoginVerifierCapacityExhausted:")
		})
	}
}

func TestSecondFactorCellsInjection_MissingRuleIsFound(t *testing.T) {
	_, findings := judgeSecondFactorCells([]alertRule{{Alert: "KanameLoginLaneFailing", Expr: lawfulFailingExpr}},
		secondFactorCellDemands())
	require.Len(t, findings, 2, "у пропавшего правила две клетки — две находки")
	for _, f := range findings {
		require.Contains(t, f, "KanameLoginVerifierCapacityExhausted: правила нет")
	}
}

// --- формы записи выражения: прочтение разбором PromQL, а не текстом ---

var refusalUnavailableCell = cellTerm{
	series: metrics.SecondFactorRefusalsMetric,
	labels: map[string]string{"reason": string(humansession.RefusalUnavailable)},
}

// J1, J4 — слагаемое присутствует ТЕКСТОМ, но правило его не считает:
// находка. T3, T4 — законные написания той же клетки: молчание.
func TestSecondFactorCellsInjection_ExpressionForms(t *testing.T) {
	const base = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))`
	for name, tc := range map[string]struct {
		expr  string
		reads bool
	}{
		"J1 слагаемое в комментарии PromQL": {expr: base + "\n  # + sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m]))\n  > 0", reads: false},
		"J1 комментарий в конце строки":     {expr: base + " > 0 # sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m]))", reads: false},
		"J4 слагаемое, умноженное на ноль":  {expr: base + "\n  + 0 * sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m])) > 0", reads: false},
		"J4 слагаемое за unless":            {expr: base + " unless sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m])) > 0", reads: false},
		"T3 одинарные кавычки":              {expr: base + "\n  + sum(increase(kaname_second_factor_refusals_total{reason='unavailable'}[10m])) > 0", reads: true},
		"T4 имя ряда отбором __name__":      {expr: base + "\n  + sum(increase({__name__=\"kaname_second_factor_refusals_total\",reason=\"unavailable\"}[10m])) > 0", reads: true},
		"близнец: каноническая запись":      {expr: base + "\n  + sum(increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m])) > 0", reads: true},
		"близнец: без sum и в скобках":      {expr: "(" + base + " + increase(kaname_second_factor_refusals_total{reason=\"unavailable\"}[10m])) > 0", reads: true},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.reads, exprReadsCell(tc.expr, refusalUnavailableCell), "выражение:\n%s", tc.expr)
		})
	}
}
