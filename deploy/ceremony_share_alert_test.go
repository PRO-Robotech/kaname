// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_share_alert_test.go — отказ сверки секрета клиента сверх ДОЛИ
// церемонии в ёмкости проверяющего считает правило ёмкости (kaname#693).
//
// Доля церемонии — половина ёмкости проверяющего; сверка сверх неё получает
// отказ ДО проверяющего, поэтому клетка исчерпания проверяющего
// (`kaname_password_verification_outcomes_total{outcome="capacity-exhausted"}`)
// не растёт, а наружу отказ тот же, что у исчерпания проверяющего. Своя клетка
// у него — `kaname_password_verifier_ceremony_share_exhausted_total`; правило
// `KanameLoginVerifierCapacityExhausted` обязано её СЧИТАТЬ (разбор PromQL) и
// звонить на её рост (настоящий движок), а клетка — быть в выдаче
// производителя с нулём до первого события: `A + пусто` в PromQL — пусто.
package deploy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

var ceremonyShareCell = cellTerm{series: metrics.CeremonyShareExhaustedMetric, labels: map[string]string{}}

// judgeShareCell — находки правила ёмкости о клетке доли над ПРОИЗВОЛЬНЫМ
// набором правил: инъекция зовёт его же.
func judgeShareCell(rules []alertRule) []string {
	for _, r := range rules {
		if r.Alert != ruleCapacity {
			continue
		}
		if reads, why := exprReadsCell(r.Expr, ceremonyShareCell); !reads {
			return []string{ruleCapacity + ": выражение не считает клетку " + ceremonyShareCell.String() + ": " + why}
		}
		return nil
	}
	return []string{ruleCapacity + ": правила нет в наборе — клетку " + ceremonyShareCell.String() + " не читает никто"}
}

func TestCapacityRuleCountsTheCeremonyShareRefusal(t *testing.T) {
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			t.Logf("ПЕРЕПИСЬ (%s): правил %d · требование: %s → %s", r.name, len(rules), ruleCapacity, ceremonyShareCell)
			findings := judgeShareCell(rules)
			require.Emptyf(t, findings, "отказ сверх доли церемонии не поднимает тревоги ёмкости:\n  %s",
				strings.Join(findings, "\n  "))
			for _, rule := range rules {
				if rule.Alert == ruleCapacity {
					require.Truef(t, engineReadsCell(t, rule.Expr, ceremonyShareCell),
						"движок: %s не звонит на рост клетки %s:\n%s", ruleCapacity, ceremonyShareCell, rule.Expr)
				}
			}
		})
	}
}

func TestCeremonyShareCellIsExposedBeforeTheFirstRefusal(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.LoginLaneRecorder()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code, "выдача производителя не читается")
	lines := strings.Split(rec.Body.String(), "\n")
	require.NotEmpty(t, lines, "выдача производителя пуста — судить нечего")
	require.Contains(t, lines, metrics.CeremonyShareExhaustedMetric+" 0",
		"клетка доли не выдана с нулём до первого отказа — правило ёмкости оглохло бы целиком")
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

const lawfulShareCapacityExpr = lawfulCapacityExpr + "\n  + sum(increase(kaname_password_verifier_ceremony_share_exhausted_total[10m])) > 0"

func TestCeremonyShareInjection(t *testing.T) {
	lawful := strings.Replace(lawfulShareCapacityExpr, " > 0\n  +", "\n  +", 1)
	require.Empty(t, judgeShareCell(injectedRules(lawfulFailingExpr, lawful)), "законный близнец:\n%s", lawful)
	require.Len(t, judgeShareCell(injectedRules(lawfulFailingExpr, lawfulCapacityExpr)), 1, "снятый терм — находка")
	neighbour := strings.Replace(lawfulFailingExpr, " > 0",
		"\n  + sum(increase(kaname_password_verifier_ceremony_share_exhausted_total[10m])) > 0", 1)
	require.Len(t, judgeShareCell(injectedRules(neighbour, lawfulCapacityExpr)), 1, "терм в соседнем правиле — находка")
	require.Len(t, judgeShareCell([]alertRule{{Alert: ruleLaneFailing, Expr: lawfulFailingExpr}}), 1, "правила нет — находка")
}
