// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// self_service_store_failure_ledger_test.go — сбой хранилища у КАЖДОГО глагола
// своих данных считает правило отказов нашей стороны (kaname#691).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Глаголы под живой сессией (повышение уровня, второй фактор, запасные коды,
// смена и заведение пароля) отвечают на сбой хранилища одним `UNAVAILABLE` без
// причины. Клетку им заводит производитель
// (`kaname_self_service_store_failures_total{verb}`, перечень
// `humansession.StoreFailureVerbs()`), а звонить на неё обязано правило
// `KanameLoginLaneFailing`: иначе оператор узнаёт об отказе от людей.
//
// Перечень производителя разносится по сторонам тем же суждением, что значения
// второго фактора ([judgeSideLedger]): глагол без записи — находка, запись без
// глагола — находка, «наша сторона» — правило СЧИТАЕТ клетку разбором PromQL.
// Правило читает ряд ЦЕЛИКОМ: все его значения — наша сторона, и новый глагол
// не требует правки выражения; появись в ряду значение стороны вызывающего,
// его запись «сторона вызывающего» покраснеет на покрытии (Л4).
//
// Звонит ли поставленное правило на рост клетки КАЖДОГО глагола, решает
// настоящий движок, а не только разбор.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// storeFailureSeries — ряд целиком: его и считает правило.
var storeFailureSeries = cellTerm{series: metrics.SelfServiceStoreFailuresMetric, labels: map[string]string{}}

// storeFailureCell — клетка одного глагола.
func storeFailureCell(v humansession.StoreFailureVerb) cellTerm {
	return cellTerm{series: metrics.SelfServiceStoreFailuresMetric, labels: map[string]string{"verb": string(v)}}
}

// storeFailureProducerValues — перепись закрытого перечня производителя.
func storeFailureProducerValues() []producerValue {
	var out []producerValue
	for _, v := range humansession.StoreFailureVerbs() {
		out = append(out, producerValue{key: "store-failure/" + string(v), cell: storeFailureCell(v)})
	}
	return out
}

// storeFailureSideLedger — запись на КАЖДЫЙ глагол перечня.
func storeFailureSideLedger() map[string]sideVerdict {
	ours := func(why string) sideVerdict {
		return sideVerdict{rule: ruleLaneFailing, reads: &storeFailureSeries, why: why}
	}
	return map[string]sideVerdict{
		"store-failure/step-up":                 ours("хранилище не ответило на повышении уровня — человеку 503"),
		"store-failure/second-factor-enroll":    ours("хранилище не ответило на заведении второго фактора"),
		"store-failure/second-factor-confirm":   ours("хранилище не ответило на подтверждении второго фактора"),
		"store-failure/second-factor-status":    ours("хранилище не ответило на чтении состояния второго фактора"),
		"store-failure/second-factor-remove":    ours("хранилище не ответило на снятии второго фактора"),
		"store-failure/backup-codes-regenerate": ours("хранилище не ответило на перечеканке запасных кодов"),
		"store-failure/password-change":         ours("хранилище не ответило на смене пароля"),
		"store-failure/password-enroll":         ours("хранилище не ответило на заведении пароля"),
		"store-failure/own-sessions-list":       ours("хранилище не ответило на перечне своих сессий (kaname#735)"),
		"store-failure/own-session-end":         ours("хранилище не ответило на выходе из выбранной сессии (kaname#735)"),
		"store-failure/own-sessions-end-others": ours("хранилище не ответило на выходе из прочих сессий (kaname#735)"),
	}
}

func TestSelfServiceStoreFailuresAreCountedByTheLaneRule(t *testing.T) {
	values := storeFailureProducerValues()
	require.NotEmpty(t, values, "перечень производителя пуст — судить нечего, это не зелёное")
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSideLedger(values, storeFailureSideLedger(), rules)
			t.Logf("ПЕРЕПИСЬ сторон сбоя хранилища глаголов (%s): значений у производителя %d · наша сторона %d · "+
				"сторона вызывающего %d · правил %d · находок %d",
				r.name, census.values, census.ours, census.caller, census.rules, len(findings))
			require.NotZero(t, census.ours, "ни одного значения нашей стороны — проверка беспредметна")
			require.Emptyf(t, findings, "сбой хранилища глагола своих данных не считает ни одно правило:\n  %s",
				strings.Join(findings, "\n  "))

			var lane *alertRule
			for i := range rules {
				if rules[i].Alert == ruleLaneFailing {
					lane = &rules[i]
				}
			}
			require.NotNil(t, lane, "правила %s в объекте нет", ruleLaneFailing)
			for _, v := range values {
				require.Truef(t, engineReadsCell(t, lane.Expr, v.cell),
					"движок: %s не звонит на рост клетки %s:\n%s", ruleLaneFailing, v.cell, lane.Expr)
			}
		})
	}
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

const lawfulStoreFailureExpr = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))
  + sum(increase(kaname_self_service_store_failures_total[10m])) > 0`

func TestStoreFailureLedgerInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeSideLedger(storeFailureProducerValues(), storeFailureSideLedger(),
		injectedRules(lawfulStoreFailureExpr, lawfulCapacityExpr))
	require.Empty(t, findings)
	require.Equal(t, census.values, census.ours)
}

func TestStoreFailureLedgerInjection_DroppedTermIsFound(t *testing.T) {
	dropped := `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m])) > 0`
	_, findings := judgeSideLedger(storeFailureProducerValues(), storeFailureSideLedger(),
		injectedRules(dropped, lawfulCapacityExpr))
	require.Len(t, findings, len(humansession.StoreFailureVerbs()), "%v", findings)
	for _, f := range findings {
		require.Contains(t, f, "правило KanameLoginLaneFailing не считает клетку "+storeFailureSeries.String())
	}
}

// Отбор одного глагола вместо ряда целиком: прочие глаголы не считаются.
func TestStoreFailureLedgerInjection_SingleVerbSelectorIsFound(t *testing.T) {
	one := `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))
  + sum(increase(kaname_self_service_store_failures_total{verb="step-up"}[10m])) > 0`
	_, findings := judgeSideLedger(storeFailureProducerValues(), storeFailureSideLedger(),
		injectedRules(one, lawfulCapacityExpr))
	require.Len(t, findings, len(humansession.StoreFailureVerbs()), "запись читает ряд целиком: %v", findings)
}

func TestStoreFailureLedgerInjection_VerbWithoutEntryIsFound(t *testing.T) {
	values := append(storeFailureProducerValues(), producerValue{
		key: "store-failure/email-change", cell: storeFailureCell("email-change"),
	})
	_, findings := judgeSideLedger(values, storeFailureSideLedger(), injectedRules(lawfulStoreFailureExpr, lawfulCapacityExpr))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "store-failure/email-change: значение производителя без записи")
}

func TestStoreFailureLedgerInjection_EntryOutlivingItsVerbIsFound(t *testing.T) {
	ledger := storeFailureSideLedger()
	ledger["store-failure/retired"] = caller("снятый глагол")
	_, findings := judgeSideLedger(storeFailureProducerValues(), ledger, injectedRules(lawfulStoreFailureExpr, lawfulCapacityExpr))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "store-failure/retired: запись есть, значения у производителя нет")
}
