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
// слагаемое считающей стороны сравнения правила (`sum(increase(…))` либо
// `increase(…)`), читающее момент вычисления (без `offset` и `@ <число>`), и
// все слагаемые цепочки выходят с одним набором меток. Считающая сторона —
// векторная сторона сравнения с порогом в сторону роста (`A > 0` и `0 < A`);
// ветки `or` складываются, ветка за `and`/`unless` не считает. Слагаемое в
// комментарии, `0 * sum(…)`, `… unless sum(…)`, `sum by (reason)(…)` и голый
// `increase(…)` рядом с `sum(…)` клетку не считают. Каждая форма, о которой
// суждение выносит вердикт, и поставляемые правила сверяются с настоящим
// движком (second_factor_promql_engine_test.go).
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
	"errors"
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

// exprCountedCells — клетки, которые выражение СЧИТАЕТ: рост клетки поднимает
// тревогу, а без него правило молчит.
//
// Правило звонит, когда его выражение непусто. Вершина правила — сравнение
// либо `or`: `A or B` непусто, когда непуста любая ветка, и клетки веток
// складываются. Сравнение с числом звонит на рост ВЕКТОРНОЙ стороны, где бы она
// ни стояла (`A > 0` и `0 < A` — одно правило), и только в сторону роста:
// `> c` при c ≥ 0 и `>= c` при c > 0; `< c`, `>= 0`, `> -1`, `==` звонят без роста
// либо не звонят на рост. Сравнение двух векторов считает левую сторону только
// оператором `>`. Ветка за `and` и `unless`, правило без сравнения и
// сравнение с модификатором `bool` не считают ни одной клетки: первые
// сужаются чужой стороной, последние два непусты всегда.
//
// Считающая сторона — цепочка слагаемых `sum(increase(ряд{…}[окно]))` либо
// `increase(ряд{…}[окно])`, в любых скобках. Селектор вне такого слагаемого не
// засчитывается: `0 * sum(…)` держит клетку в тексте, но не даёт ей поднять
// тревогу. Селектор с неточным отбором (`=~`, `!=`, `!~`), со сдвигом `offset`
// либо с моментом `@ <число>` клеткой не является: он читает не момент
// вычисления правила (`@ start()` и `@ end()` у правила — момент вычисления).
//
// Цепочка из нескольких слагаемых считает что-либо, только если КАЖДОЕ
// слагаемое выходит с одним и тем же набором меток: `sum(…) + sum by (reason)(…)`
// и `sum(…) + increase(…)` движок вычисляет в пустоту — сопоставлять нечего, и
// тревога не звонит никогда. Тогда не считается ни одна клетка, а ошибка
// называет причину.
func exprCountedCells(expr string) ([]cellTerm, error) {
	root, err := promqlParser.ParseExpr(expr)
	if err != nil {
		return nil, fmt.Errorf("выражение не разбирается: %w", err)
	}
	return ruleCountedCells(root)
}

// ruleCountedCells — клетки, которые считает выражение правила либо ветка `or`.
func ruleCountedCells(e parser.Expr) ([]cellTerm, error) {
	be, ok := unparen(e).(*parser.BinaryExpr)
	switch {
	case !ok:
		return nil, fmt.Errorf("на вершине `%s` нет сравнения — выражение непусто всегда, тревога звонит без роста клетки", e)
	case be.Op == parser.LOR:
		left, lerr := ruleCountedCells(be.LHS)
		right, rerr := ruleCountedCells(be.RHS)
		cells := append(left, right...)
		if len(cells) == 0 {
			return nil, errors.Join(lerr, rerr)
		}
		return cells, nil
	case be.Op == parser.LAND || be.Op == parser.LUNLESS:
		return nil, fmt.Errorf("ветка `%s` сужена `%s` чужой стороной — рост клетки тревогу не поднимает", e, be.Op)
	case !be.Op.IsComparisonOperator():
		return nil, fmt.Errorf("на вершине `%s` нет сравнения — выражение непусто всегда, тревога звонит без роста клетки", e)
	case be.ReturnBool:
		return nil, fmt.Errorf("сравнение с модификатором bool даёт 0 либо 1 всегда — тревога звонит без клетки")
	}
	side, err := risingSide(be)
	if err != nil {
		return nil, err
	}
	return sideCountedCells(side)
}

// risingSide — сторона сравнения, рост которой поднимает тревогу.
func risingSide(be *parser.BinaryExpr) (parser.Expr, error) {
	if c, ok := numberValue(be.RHS); ok {
		return be.LHS, thresholdRises(be.Op, c, be)
	}
	if c, ok := numberValue(be.LHS); ok {
		return be.RHS, thresholdRises(mirroredComparison(be.Op), c, be)
	}
	if be.Op != parser.GTR {
		return nil, fmt.Errorf("сравнение двух векторов `%s` оператором %s — рост левой стороны тревогу не поднимает", be, be.Op)
	}
	return be.LHS, nil
}

// thresholdRises — звонит ли `вектор op c` на рост вектора от нуля и молчит ли
// без него.
func thresholdRises(op parser.ItemType, c float64, be *parser.BinaryExpr) error {
	if (op == parser.GTR && c >= 0) || (op == parser.GTE && c > 0) {
		return nil
	}
	return fmt.Errorf("сравнение `%s` звонит без роста клетки либо не звонит на её рост", be)
}

// mirroredComparison — оператор, при котором `c op A` равно `A op' c`.
func mirroredComparison(op parser.ItemType) parser.ItemType {
	switch op {
	case parser.LSS:
		return parser.GTR
	case parser.LTE:
		return parser.GTE
	case parser.GTR:
		return parser.LSS
	case parser.GTE:
		return parser.LTE
	}
	return op
}

// numberValue — значение стороны, если она число (с унарным знаком и в скобках).
func numberValue(e parser.Expr) (float64, bool) {
	switch n := unparen(e).(type) {
	case *parser.NumberLiteral:
		return n.Val, true
	case *parser.UnaryExpr:
		v, ok := numberValue(n.Expr)
		if !ok {
			return 0, false
		}
		if n.Op == parser.SUB {
			return -v, true
		}
		return v, true
	}
	return 0, false
}

// sideCountedCells — клетки цепочки слагаемых считающей стороны сравнения.
func sideCountedCells(side parser.Expr) ([]cellTerm, error) {
	terms := additiveTerms(side)
	if err := chainSharesOneLabelSet(terms); err != nil {
		return nil, err
	}
	var cells []cellTerm
	for _, term := range terms {
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

// matchesOnAllLabels — сопоставление векторов по всем меткам: без `on(…)` и
// `ignoring(…)`.
func matchesOnAllLabels(be *parser.BinaryExpr) bool {
	vm := be.VectorMatching
	return vm == nil || (!vm.On && len(vm.MatchingLabels) == 0)
}

// additiveTerms — слагаемые цепочки `a + b + …`; прочие операторы и сложение с
// `on(…)`/`ignoring(…)` слагаемых не раскрывают.
func additiveTerms(e parser.Expr) []parser.Expr {
	e = unparen(e)
	if be, ok := e.(*parser.BinaryExpr); ok && be.Op == parser.ADD && matchesOnAllLabels(be) {
		return append(additiveTerms(be.LHS), additiveTerms(be.RHS)...)
	}
	return []parser.Expr{e}
}

// outLabels — набор меток на выходе узла. known=false — набор зависит от рядов
// (метки ряда и метки цели, которые дописывает сбор), его разбор не знает;
// scalar — число без меток, с любым вектором сопоставляется.
type outLabels struct {
	known, scalar bool
	names         string // имена меток, отсортированные, через запятую
}

// termLabels — набор меток на выходе слагаемого.
func termLabels(e parser.Expr) outLabels {
	switch n := unparen(e).(type) {
	case *parser.NumberLiteral:
		return outLabels{known: true, scalar: true}
	case *parser.AggregateExpr:
		if n.Without {
			return outLabels{}
		}
		switch n.Op {
		case parser.SUM, parser.AVG, parser.MIN, parser.MAX, parser.COUNT, parser.GROUP,
			parser.STDDEV, parser.STDVAR, parser.QUANTILE:
			g := append([]string(nil), n.Grouping...)
			sort.Strings(g)
			return outLabels{known: true, names: strings.Join(g, ",")}
		}
		return outLabels{}
	case *parser.Call:
		switch n.Func.Name {
		case "vector":
			return outLabels{known: true}
		case "scalar", "time":
			return outLabels{known: true, scalar: true}
		}
		return outLabels{}
	case *parser.BinaryExpr:
		l, r := termLabels(n.LHS), termLabels(n.RHS)
		switch {
		case l.scalar && r.scalar:
			return l
		case l.scalar:
			return r
		case r.scalar:
			return l
		case !matchesOnAllLabels(n):
			return outLabels{}
		case n.Op == parser.LAND || n.Op == parser.LUNLESS:
			return l
		case l.known && r.known && l.names == r.names:
			return l
		}
		return outLabels{}
	}
	return outLabels{}
}

// chainSharesOneLabelSet — все векторные слагаемые цепочки выходят с одним
// набором меток; единственное слагаемое сопоставлять не с чем.
func chainSharesOneLabelSet(terms []parser.Expr) error {
	if len(terms) < 2 {
		return nil
	}
	var first *outLabels
	for _, term := range terms {
		ol := termLabels(term)
		if ol.scalar {
			continue
		}
		if !ol.known {
			return fmt.Errorf("слагаемое `%s` выходит с метками рядов, а не с общим набором цепочки — "+
				"`A + B` с разными наборами меток пусто, тревога не звонит никогда", term)
		}
		if first == nil {
			first = &ol
			continue
		}
		if ol.names != first.names {
			return fmt.Errorf("слагаемые цепочки выходят с разными наборами меток (by (%s) и by (%s)) — "+
				"`A + B` пусто, тревога не звонит никогда", first.names, ol.names)
		}
	}
	return nil
}

// increaseSelector — селектор слагаемого `sum(increase(…))` либо `increase(…)`,
// читающий момент вычисления правила: без `offset` и без `@ <число>`.
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
	if !ok || vs.OriginalOffset != 0 || vs.Timestamp != nil {
		return nil, false
	}
	return vs, true
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
// ровно такими точными отборами. why — причина, по которой не считает:
// неразборное выражение (сервер правил его не примет) либо цепочка, которую
// движок вычисляет в пустоту.
func exprReadsCell(expr string, c cellTerm) (reads bool, why string) {
	cells, err := exprCountedCells(expr)
	if err != nil {
		return false, err.Error()
	}
	for _, got := range cells {
		if got.series == c.series && sameCell(got.labels, c.labels) {
			return true, ""
		}
	}
	return false, "среди слагаемых считающей стороны сравнения нет слагаемого с точной записью клетки"
}

// exprCoversCell — читает ли выражение клетку ХОТЬ ГДЕ-НИБУДЬ: какой-либо
// селектор в любой функции и в любой позиции, каждый отбор которого
// выполняется на клетке. Отбор по метке, которой в клетке нет, — метка цели
// либо чужая: её значения разбор не знает, и такой отбор считается
// выполнимым. Это суждение шире [exprReadsCell] нарочно: оно ищет ЛИШНЕЕ
// чтение, и сомнение здесь — находка, а не молчание.
func exprCoversCell(expr string, c cellTerm) (bool, error) {
	root, err := promqlParser.ParseExpr(expr)
	if err != nil {
		return false, fmt.Errorf("выражение не разбирается: %w", err)
	}
	covered := false
	parser.Inspect(root, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok && !covered {
			covered = selectorCovers(vs, c)
		}
		return nil
	})
	return covered, nil
}

func selectorCovers(vs *parser.VectorSelector, c cellTerm) bool {
	if vs.Name != "" && vs.Name != c.series {
		return false
	}
	for _, m := range vs.LabelMatchers {
		if m.Name == labels.MetricName {
			if !m.Matches(c.series) {
				return false
			}
			continue
		}
		v, own := c.labels[m.Name]
		if !own {
			continue
		}
		if !m.Matches(v) {
			return false
		}
	}
	return true
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
			if reads, why := exprReadsCell(r.Expr, c); !reads {
				findings = append(findings, alert+": выражение не читает клетку "+c.String()+": "+why)
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
	var cells []cellTerm
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
		cells = append(cells, cellTerm{series: m[1], labels: labels})
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
	neighbourCarries := `sum(increase(kaname_login_outcomes_total{outcome="capacity-exhausted"}[10m]))
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

// expressionForm — запись выражения и вердикт: считает ли она клетку
// refusal/unavailable. Вердикт сверяется и с суждением, и с движком
// ([TestSecondFactorExpressionFormsAgreeWithTheEngine]).
type expressionForm struct {
	expr  string
	reads bool
}

const expressionFormsBase = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))`

// secondFactorExpressionForms — J1, J4…J8: слагаемое присутствует ТЕКСТОМ, но
// правило его не считает (движок вычисляет цепочку в пустоту либо в постоянный
// отказ): находка. T3, T4 и близнецы — законные написания той же клетки:
// молчание.
func secondFactorExpressionForms() map[string]expressionForm {
	const (
		base = expressionFormsBase
		cell = `kaname_second_factor_refusals_total{reason="unavailable"}`
	)
	return map[string]expressionForm{
		"J1 слагаемое в комментарии PromQL": {expr: base + "\n  # + sum(increase(" + cell + "[10m]))\n  > 0", reads: false},
		"J1 комментарий в конце строки":     {expr: base + " > 0 # sum(increase(" + cell + "[10m]))", reads: false},
		"J4 слагаемое, умноженное на ноль":  {expr: base + "\n  + 0 * sum(increase(" + cell + "[10m])) > 0", reads: false},
		"J4 слагаемое за unless":            {expr: base + " unless sum(increase(" + cell + "[10m])) > 0", reads: false},
		"T3 одинарные кавычки":              {expr: base + "\n  + sum(increase(kaname_second_factor_refusals_total{reason='unavailable'}[10m])) > 0", reads: true},
		"T4 имя ряда отбором __name__":      {expr: base + "\n  + sum(increase({__name__=\"kaname_second_factor_refusals_total\",reason=\"unavailable\"}[10m])) > 0", reads: true},
		"близнец: каноническая запись":      {expr: base + "\n  + sum(increase(" + cell + "[10m])) > 0", reads: true},

		// J5: слагаемое выходит с иным набором меток, чем цепочка: `{} + {reason=…}` — пусто.
		"J5 sum by (reason) в цепочке sum":     {expr: base + "\n  + sum by (reason) (increase(" + cell + "[10m])) > 0", reads: false},
		"J5 sum without (job) в цепочке sum":   {expr: base + "\n  + sum without (job) (increase(" + cell + "[10m])) > 0", reads: false},
		"J5 близнец: sum by () — тот же набор": {expr: base + "\n  + sum by () (increase(" + cell + "[10m])) > 0", reads: true},
		// J6: голый increase несёт метки ряда и цели; рядом с sum(…) — пусто.
		"J6 голый increase в цепочке sum, в скобках":          {expr: "(" + base + " + increase(" + cell + "[10m])) > 0", reads: false},
		"J6 голый increase в цепочке sum":                     {expr: base + "\n  + increase(" + cell + "[10m]) > 0", reads: false},
		"J6 близнец: голый increase — единственное слагаемое": {expr: "increase(" + cell + "[10m]) > 0", reads: true},
		// J7, J8: селектор читает не момент вычисления правила.
		"J7 селектор с @ 0":                       {expr: base + "\n  + sum(increase(" + cell + "[10m] @ 0)) > 0", reads: false},
		"J7 близнец: @ end() — момент вычисления": {expr: base + "\n  + sum(increase(" + cell + "[10m] @ end())) > 0", reads: true},
		"J8 селектор со сдвигом offset 10m":       {expr: base + "\n  + sum(increase(" + cell + "[10m] offset 10m)) > 0", reads: false},
		"J8 близнец: offset 0s — сдвига нет":      {expr: base + "\n  + sum(increase(" + cell + "[10m] offset 0s)) > 0", reads: true},
		// N: сторона и ветка, которые СЧИТАЮТ. Сравнение с числом звонит на рост
		// векторной стороны, где бы она ни стояла; `or` звонит, если звонит любая
		// ветка; ветка за `and`/`unless` и сравнение не в сторону роста — нет.
		"N3 сравнение наоборот: 0 < цепочка":               {expr: "0 < " + base + "\n  + sum(increase(" + cell + "[10m]))", reads: true},
		"N3 близнец: 0 > цепочка — звонит только на убыль": {expr: "0 > " + base + "\n  + sum(increase(" + cell + "[10m]))", reads: false},
		"N1 близнец: живая ветка or":                       {expr: base + " > 0\n  or sum(increase(" + cell + "[10m])) > 0", reads: true},
		"N1 близнец: клетка в первой ветке or":             {expr: "sum(increase(" + cell + "[10m])) > 0\n  or " + base + " > 0", reads: true},
		"N1 мёртвая ветка or: and on() vector(0) > 0":      {expr: base + " > 0\n  or sum(increase(" + cell + "[10m])) and on() vector(0) > 0", reads: false},
		"N1 ветка or без сравнения звонит всегда":          {expr: base + " > 0\n  or sum(increase(" + cell + "[10m]))", reads: false},
		"N4 цепочка < 1 — звонит без роста":                {expr: base + "\n  + sum(increase(" + cell + "[10m])) < 1", reads: false},
		"N4 цепочка >= 0 — звонит без роста":               {expr: base + "\n  + sum(increase(" + cell + "[10m])) >= 0", reads: false},
		"N4 близнец: цепочка >= 1":                         {expr: base + "\n  + sum(increase(" + cell + "[10m])) >= 1", reads: true},
		"N4 цепочка > -1 — звонит без роста":               {expr: base + "\n  + sum(increase(" + cell + "[10m])) > -1", reads: false},
		"N5 правило без сравнения звонит всегда":           {expr: base + "\n  + sum(increase(" + cell + "[10m]))", reads: false},
		"N6 близнец: цепочка > vector(0)":                  {expr: base + "\n  + sum(increase(" + cell + "[10m])) > vector(0)", reads: true},
		"N6 цепочка >= vector(0) — звонит без роста":       {expr: base + "\n  + sum(increase(" + cell + "[10m])) >= vector(0)", reads: false},
		"N7 близнец: порог со знаком в скобках, 0 < …":     {expr: "(-0) < (" + base + "\n  + sum(increase(" + cell + "[10m])))", reads: true},
	}
}

func TestSecondFactorCellsInjection_ExpressionForms(t *testing.T) {
	for name, tc := range secondFactorExpressionForms() {
		t.Run(name, func(t *testing.T) {
			reads, why := exprReadsCell(tc.expr, refusalUnavailableCell)
			require.Equal(t, tc.reads, reads, "выражение:\n%s\nпричина: %s", tc.expr, why)
		})
	}
}
