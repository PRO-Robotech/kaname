// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_producer_ledger_test.go — КАЖДОЕ значение закрытых перечней
// производителя второго фактора разнесено по сторонам: «наша сторона → правило
// X» либо «сторона вызывающего → никакого» (kaname#258, класс п.1).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Проба клеток (second_factor_alert_cells_test.go) держит три известные клетки.
// Класс шире: производитель заводит новое значение отказа или исхода
// предъявления — и правило о нём молчит, пока кто-нибудь не вспомнит дописать
// требование. Здесь требование выводится ИЗ ПЕРЕЧНЕЙ производителя
// (`humansession.SecondFactorRefusals()`, `humansession.PresentationCells()`):
// значение без записи — находка, и решение о стороне принимается в момент его
// заведения, а не после первого молчаливого отказа на стенде.
//
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Л1  у каждого значения перечней есть запись (перепись производителя);
//	Л2  у каждой записи есть значение (запись, пережившая своё значение, — находка);
//	Л3  «наша сторона» — выражение названного правила СЧИТАЕТ названную клетку
//	    (разбором PromQL, [exprReadsCell]);
//	Л4  «сторона вызывающего» — ни одно правило объекта её клетку не считает:
//	    тревога на отказ, вызванный предъявителем, звонила бы на каждый
//	    неверный код.
package deploy_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// producerValue — значение перечня производителя и клетка, которую оно растит.
type producerValue struct {
	key  string
	cell cellTerm
}

// secondFactorProducerValues — перепись закрытых перечней производителя.
func secondFactorProducerValues() []producerValue {
	var out []producerValue
	for _, r := range humansession.SecondFactorRefusals() {
		out = append(out, producerValue{
			key:  "refusal/" + string(r),
			cell: cellTerm{series: metrics.SecondFactorRefusalsMetric, labels: map[string]string{"reason": string(r)}},
		})
	}
	for _, c := range humansession.PresentationCells() {
		out = append(out, producerValue{
			key: "presentation/" + c.Method.String() + "/" + string(c.Outcome),
			cell: cellTerm{series: metrics.SecondFactorPresentationsMetric,
				labels: map[string]string{"method": c.Method.String(), "outcome": string(c.Outcome)}},
		})
	}
	return out
}

// sideVerdict — решение о значении. rule пусто — сторона вызывающего; иначе
// правило, которое обязано считать клетку reads (nil — собственная клетка
// значения).
type sideVerdict struct {
	rule  string
	reads *cellTerm
	why   string
}

const (
	ruleLaneFailing = "KanameLoginLaneFailing"
	ruleCapacity    = "KanameLoginVerifierCapacityExhausted"
)

// pairedUnavailable — клетка, которую производитель пишет ПАРОЙ с исходом
// `material-unreadable` (sf_present.go, sf_enroll.go; пару держит
// second_factor_not_an_attempt_test.go): правило считает её, а не исход
// предъявления, чтобы не считать один отказ дважды.
var pairedUnavailable = cellTerm{
	series: metrics.SecondFactorRefusalsMetric,
	labels: map[string]string{"reason": string(humansession.RefusalUnavailable)},
}

func caller(why string) sideVerdict { return sideVerdict{why: why} }

// secondFactorSideLedger — запись на КАЖДОЕ значение перечней.
func secondFactorSideLedger() map[string]sideVerdict {
	return map[string]sideVerdict{
		"refusal/not-enrolled":           caller("фактора у человека нет — состояние предъявителя"),
		"refusal/already-enrolled":       caller("фактор уже заведён — повтор заведения предъявителем"),
		"refusal/enrollment-not-pending": caller("подтверждать нечего — порядок шагов предъявителя"),
		"refusal/session-not-fresh":      caller("сессия не свежа — предъявитель повышает уровень"),
		"refusal/unavailable": {rule: ruleLaneFailing,
			why: "материал не открывается ни одним ключом перечня — 503 человеку с верным кодом"},

		"presentation/totp/matched":    caller("успех, не отказ"),
		"presentation/totp/mismatched": caller("неверный код предъявителя"),
		"presentation/totp/replayed":   caller("повтор кода предъявителем"),
		"presentation/totp/material-unreadable": {rule: ruleLaneFailing, reads: &pairedUnavailable,
			why: "наш отказ; считается парной клеткой refusal/unavailable"},

		"presentation/lookup_secret/matched":    caller("успех, не отказ"),
		"presentation/lookup_secret/mismatched": caller("неверный запасной код предъявителя"),
		"presentation/lookup_secret/material-unreadable": {rule: ruleLaneFailing, reads: &pairedUnavailable,
			why: "наш дефект хранения набора; считается парной клеткой refusal/unavailable"},
		"presentation/lookup_secret/capacity-exhausted": {rule: ruleCapacity,
			why: "ёмкость проверяющего, общая с паролем, исчерпана — отказ по нагрузке"},
	}
}

// sideLedgerCensus — объём осмотренного одним суждением.
type sideLedgerCensus struct {
	values int // значений у производителя
	ours   int // из них — наша сторона
	caller int // из них — сторона вызывающего
	rules  int // правил осмотрено
}

// judgeSideLedger — суждение над ПРОИЗВОЛЬНЫМИ перечнем, записью и правилами:
// инъекция зовёт его же.
func judgeSideLedger(values []producerValue, ledger map[string]sideVerdict, rules []alertRule) (sideLedgerCensus, []string) {
	census := sideLedgerCensus{values: len(values), rules: len(rules)}
	byName := map[string]alertRule{}
	for _, r := range rules {
		byName[r.Alert] = r
	}
	var findings []string
	seen := map[string]bool{}
	for _, v := range values {
		seen[v.key] = true
		verdict, ok := ledger[v.key]
		if !ok {
			findings = append(findings, v.key+": значение производителя без записи — реши сторону: "+
				"«наша сторона → правило» либо «сторона вызывающего → никакого»")
			continue
		}
		if verdict.rule == "" {
			census.caller++
			for _, r := range rules {
				if exprReadsCell(r.Expr, v.cell) {
					findings = append(findings, v.key+": сторона вызывающего, а правило "+r.Alert+
						" считает её клетку "+v.cell.String()+" — тревога звонила бы на отказ предъявителя")
				}
			}
			continue
		}
		census.ours++
		want := v.cell
		if verdict.reads != nil {
			want = *verdict.reads
		}
		r, ok := byName[verdict.rule]
		if !ok {
			findings = append(findings, v.key+": наша сторона, а правила "+verdict.rule+" в наборе нет")
			continue
		}
		if !exprReadsCell(r.Expr, want) {
			findings = append(findings, v.key+": наша сторона, а правило "+verdict.rule+
				" не считает клетку "+want.String())
		}
	}
	for key := range ledger {
		if !seen[key] {
			findings = append(findings, key+": запись есть, значения у производителя нет — запись истекла вместе с ним")
		}
	}
	sort.Strings(findings)
	return census, findings
}

func TestSecondFactorProducerValuesAreSidedInTheRules(t *testing.T) {
	values := secondFactorProducerValues()
	require.NotEmpty(t, values, "перечни производителя пусты — судить нечего, это не зелёное")
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSideLedger(values, secondFactorSideLedger(), rules)
			t.Logf("ПЕРЕПИСЬ сторон второго фактора (%s): значений у производителя %d · наша сторона %d · "+
				"сторона вызывающего %d · правил %d · находок %d",
				r.name, census.values, census.ours, census.caller, census.rules, len(findings))
			require.NotZero(t, census.ours, "ни одного значения нашей стороны — проверка беспредметна")
			require.Emptyf(t, findings, "значения второго фактора не разнесены по правилам:\n  %s",
				strings.Join(findings, "\n  "))
		})
	}
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

func lawfulLedgerRules() []alertRule { return injectedRules(lawfulFailingExpr, lawfulCapacityExpr) }

func TestSideLedgerInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeSideLedger(secondFactorProducerValues(), secondFactorSideLedger(), lawfulLedgerRules())
	require.Empty(t, findings)
	require.Equal(t, census.values, census.ours+census.caller)
}

func TestSideLedgerInjection_NewProducerValueWithoutEntryIsFound(t *testing.T) {
	values := append(secondFactorProducerValues(), producerValue{
		key:  "refusal/store-failed",
		cell: cellTerm{series: metrics.SecondFactorRefusalsMetric, labels: map[string]string{"reason": "store-failed"}},
	})
	_, findings := judgeSideLedger(values, secondFactorSideLedger(), lawfulLedgerRules())
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "refusal/store-failed: значение производителя без записи")
}

func TestSideLedgerInjection_EntryOutlivingItsValueIsFound(t *testing.T) {
	ledger := secondFactorSideLedger()
	ledger["refusal/retired"] = caller("снятое значение")
	_, findings := judgeSideLedger(secondFactorProducerValues(), ledger, lawfulLedgerRules())
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "refusal/retired: запись есть, значения у производителя нет")
}

func TestSideLedgerInjection_OurSideNotCountedIsFound(t *testing.T) {
	dropped := `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m])) > 0`
	_, findings := judgeSideLedger(secondFactorProducerValues(), secondFactorSideLedger(),
		injectedRules(dropped, lawfulCapacityExpr))
	// refusal/unavailable и две пары material-unreadable читают одну клетку.
	require.Len(t, findings, 3, "%v", findings)
	for _, f := range findings {
		require.Contains(t, f, "правило KanameLoginLaneFailing не считает клетку")
	}
}

func TestSideLedgerInjection_CallerSideCountedIsFound(t *testing.T) {
	noisy := lawfulFailingExpr[:len(lawfulFailingExpr)-len(" > 0")] +
		"\n  + sum(increase(kaname_second_factor_presentations_total{method=\"totp\",outcome=\"mismatched\"}[10m])) > 0"
	_, findings := judgeSideLedger(secondFactorProducerValues(), secondFactorSideLedger(),
		injectedRules(noisy, lawfulCapacityExpr))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "presentation/totp/mismatched: сторона вызывающего, а правило KanameLoginLaneFailing")
}
