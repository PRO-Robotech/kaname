// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_verifier_side_ledger_test.go — КАЖДЫЙ исход проверяющего пароля
// разнесён по сторонам, и исходы нашей стороны считает правило отказов —
// через КАЖДОГО вызывающего, а не только через вход (kaname#692).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Проверяющий один на процесс: им сверяют пароль вход, повышение уровня, смена
// пароля, а церемония — секрет клиента. Каждая сверка пишет исход в ряд
// проверяющего (`kaname_password_verification_outcomes_total{outcome}`). Исход
// «наша сторона» (`IsOurError()`: формат вне перечня, тело не разбирается,
// параметры выше потолка) правило отказов прежде видело только через вход
// (`kaname_login_outcomes_total{outcome="verifier-issue"}`), а ряд проверяющего
// не читало ни одно правило: негодное хранимое значение у повышения уровня, у
// смены пароля и у секрета клиента тревоги не поднимало.
//
// Требование выводится из словаря производителя (`passwordverify.Outcomes()`)
// и его же деления сторон (`IsOurError()`), а не из второго списка:
//
//	П1  у каждого исхода есть запись; запись без исхода — находка;
//	П2  запись «наша сторона → KanameLoginLaneFailing» стоит ровно у исходов,
//	    которые производитель сам называет своими (`IsOurError()`): разойтись
//	    ведомость и производитель не могут;
//	П3  «наша сторона» — выражение правила СЧИТАЕТ клетку (разбор PromQL) и
//	    звонит на её рост (настоящий движок); «сторона вызывающего» — ни одно
//	    правило её клетку не ЧИТАЕТ (`mismatched` на каждый неверный пароль
//	    звонить не должен).
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func verifierCell(o passwordverify.Outcome) cellTerm {
	return cellTerm{series: metrics.PasswordVerificationOutcomesMetric, labels: map[string]string{"outcome": string(o)}}
}

// verifierProducerValues — перепись словаря проверяющего.
func verifierProducerValues() []producerValue {
	var out []producerValue
	for _, o := range passwordverify.Outcomes() {
		out = append(out, producerValue{key: "verifier/" + string(o), cell: verifierCell(o)})
	}
	return out
}

// verifierSideLedger — запись на КАЖДЫЙ исход словаря.
func verifierSideLedger() map[string]sideVerdict {
	return map[string]sideVerdict{
		"verifier/matched":          caller("успех, не отказ"),
		"verifier/mismatched":       caller("неверный пароль либо секрет предъявителя"),
		"verifier/material-missing": caller("материала нет — законное состояние личности либо клиент без секрета"),
		"verifier/format-not-in-registry": {rule: ruleLaneFailing,
			why: "хранимое значение нашего формата не читается — повтор не поможет"},
		"verifier/body-not-parsable": {rule: ruleLaneFailing,
			why: "хранимое значение повреждено — находка о хранилище"},
		"verifier/params-above-ceiling": {rule: ruleLaneFailing,
			why: "параметры хранимого значения выше потолка — сверка не начата"},
		"verifier/capacity-exhausted": {rule: ruleCapacity,
			why: "ёмкость проверяющего исчерпана — отказ по нагрузке, своё правило"},
	}
}

// judgeVerifierSides — П2: «наша сторона → правило отказов» ровно у исходов,
// которые производитель называет своими.
func judgeVerifierSides(ledger map[string]sideVerdict) []string {
	var findings []string
	for _, o := range passwordverify.Outcomes() {
		v, ok := ledger["verifier/"+string(o)]
		if !ok {
			continue // П1 судит judgeSideLedger
		}
		if o.IsOurError() != (v.rule == ruleLaneFailing) {
			findings = append(findings, "verifier/"+string(o)+": производитель называет исход своим="+
				boolWord(o.IsOurError())+", а запись ведёт его к правилу «"+v.rule+"»")
		}
	}
	return findings
}

func boolWord(b bool) string {
	if b {
		return "да"
	}
	return "нет"
}

func TestPasswordVerifierOutcomesAreSidedInTheRules(t *testing.T) {
	values := verifierProducerValues()
	require.NotEmpty(t, values, "словарь проверяющего пуст — судить нечего, это не зелёное")
	require.Empty(t, judgeVerifierSides(verifierSideLedger()))
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSideLedger(values, verifierSideLedger(), rules)
			t.Logf("ПЕРЕПИСЬ сторон проверяющего пароля (%s): исходов %d · наша сторона %d · сторона вызывающего %d · "+
				"правил %d · находок %d", r.name, census.values, census.ours, census.caller, census.rules, len(findings))
			require.NotZero(t, census.ours, "ни одного исхода нашей стороны — проверка беспредметна")
			require.NotZero(t, census.caller, "ни одного исхода стороны вызывающего — Л4 беспредметна")
			require.Emptyf(t, findings, "исходы проверяющего пароля не разнесены по правилам:\n  %s",
				strings.Join(findings, "\n  "))

			byName := map[string]alertRule{}
			for _, rule := range rules {
				byName[rule.Alert] = rule
			}
			ledger := verifierSideLedger()
			for _, v := range values {
				verdict := ledger[v.key]
				if verdict.rule == "" {
					continue
				}
				require.Truef(t, engineReadsCell(t, byName[verdict.rule].Expr, v.cell),
					"движок: %s не звонит на рост клетки %s", verdict.rule, v.cell)
			}
		})
	}
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

const lawfulVerifierFailingExpr = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))
  + sum(increase(kaname_password_verification_outcomes_total{outcome="format-not-in-registry"}[10m]))
  + sum(increase(kaname_password_verification_outcomes_total{outcome="body-not-parsable"}[10m]))
  + sum(increase(kaname_password_verification_outcomes_total{outcome="params-above-ceiling"}[10m])) > 0`

func TestVerifierLedgerInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeSideLedger(verifierProducerValues(), verifierSideLedger(),
		injectedRules(lawfulVerifierFailingExpr, lawfulCapacityExpr))
	require.Empty(t, findings)
	require.Equal(t, census.values, census.ours+census.caller)
}

// Снятый терм одного исхода нашей стороны — находка о нём и только о нём.
func TestVerifierLedgerInjection_DroppedOurTermIsFound(t *testing.T) {
	dropped := strings.Replace(lawfulVerifierFailingExpr,
		"\n  + sum(increase(kaname_password_verification_outcomes_total{outcome=\"body-not-parsable\"}[10m]))", "", 1)
	require.NotEqual(t, lawfulVerifierFailingExpr, dropped, "инъекция не сняла терм")
	_, findings := judgeSideLedger(verifierProducerValues(), verifierSideLedger(), injectedRules(dropped, lawfulCapacityExpr))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "verifier/body-not-parsable: наша сторона, а правило KanameLoginLaneFailing не считает клетку")
}

// Неточный отбор по ряду, где рядом лежат исходы вызывающего: правило звонило
// бы на каждый неверный пароль.
func TestVerifierLedgerInjection_WideSelectorCoversTheCallerSide(t *testing.T) {
	for name, term := range map[string]string{
		"отрицание != matched": `sum(increase(kaname_password_verification_outcomes_total{outcome!="matched"}[10m]))`,
		"ряд целиком":          `sum(increase(kaname_password_verification_outcomes_total[10m]))`,
	} {
		t.Run(name, func(t *testing.T) {
			expr := lawfulVerifierFailingExpr[:len(lawfulVerifierFailingExpr)-len(" > 0")] + "\n  + " + term + " > 0"
			_, findings := judgeSideLedger(verifierProducerValues(), verifierSideLedger(), injectedRules(expr, lawfulCapacityExpr))
			joined := strings.Join(findings, "\n")
			require.Contains(t, joined, "verifier/mismatched: сторона вызывающего, а правило KanameLoginLaneFailing")
		})
	}
}

// П2: запись, разошедшаяся с делением производителя, — находка в обе стороны.
func TestVerifierLedgerInjection_SideDisagreeingWithTheProducerIsFound(t *testing.T) {
	ledger := verifierSideLedger()
	ledger["verifier/body-not-parsable"] = caller("ошибочно отданный вызывающему")
	ledger["verifier/mismatched"] = sideVerdict{rule: ruleLaneFailing, why: "ошибочно взятый на себя"}
	findings := judgeVerifierSides(ledger)
	require.Len(t, findings, 2, "%v", findings)
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "verifier/body-not-parsable: производитель называет исход своим=да")
	require.Contains(t, joined, "verifier/mismatched: производитель называет исход своим=нет")
}

func TestVerifierLedgerInjection_OutcomeWithoutEntryIsFound(t *testing.T) {
	values := append(verifierProducerValues(), producerValue{key: "verifier/salt-missing", cell: verifierCell("salt-missing")})
	_, findings := judgeSideLedger(values, verifierSideLedger(), injectedRules(lawfulVerifierFailingExpr, lawfulCapacityExpr))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "verifier/salt-missing: значение производителя без записи")
}
