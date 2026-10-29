// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_alert_rules_test.go — у рядов ключей доступа есть правила тревоги,
// и КАЖДОЕ значение их закрытых перечней разнесено: «правило X считает
// клетку» либо «записанное решение, почему не считает никто» (kaname#310).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ряды `kaname_access_key_refusals_total`, `kaname_access_key_events_total` и
// `kaname_access_key_sign_count_regressions_total` объявлены производителем и
// описаны страницей, а правила не читало ни одно. Гейт паритета объекта со
// страницей этого не видит по построению: ряд без правила не стоит ни в одном из
// двух сверяемых наборов. Страница же сама называет два исхода действием
// оператора:
//
//   - отказ происхождения либо доверяющей стороны — привязка `authn.access-keys.*`
//     разъехалась с доменом консоли. Каждый заведённый человек теряет способ
//     входа и получает единый отказ; тишина ряда неотличима от «ключами никто не
//     пользуется». Тот же отказ пишут исходы `origin` и `rp-id-hash` полосы
//     входа ключом и ветви ключа повышения — ПОСЛЕ перехода входа без пароля
//     (kaname#827) это главный путь, где разъезд проявляется первым;
//   - регрессия счётчика подписи — клонированный аутентификатор либо повтор
//     утверждения: «предмет разбора, а не шум».
//
// Почему происхождение — сторона, на которой звонит правило, а не «предъявитель»:
// браузер подписывает испытание только своей доверяющей стороне, и ключ,
// заведённый на наш идентификатор, чужому происхождению не ответит. Испытание
// доходит до нас с чужим происхождением, когда консоль открыта по адресу, которого
// привязка не знает, — это расхождение конфигурации посадки, а его признак виден
// только в ряде.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	К1  у каждого значения перечней производителя ключей (полоса × причина
//	    отказа, событие, регрессия) есть запись; запись без значения — находка;
//	К2  «правило X» — выражение X СЧИТАЕТ клетку (разбором PromQL и движком);
//	К3  «решение: не читает никто» — ни один селектор ни одного правила её
//	    клетку не покрывает: тревога на отказ предъявителя звонила бы на каждую
//	    ошибку человека;
//	К4  клетки, которые читают правила, предзаведены производителем нулём.
//
// Суждение — то же, что у второго фактора ([judgeSideLedger]); совпадение
// объекта со страницей держит TestDeliveredAlertRulesMatchThePublishedPage.
package deploy_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

const (
	ruleAccessKeyBinding    = "KanameAccessKeyBindingMismatch"
	ruleAccessKeyRegression = "KanameAccessKeySignCountRegressed"
)

// accessKeyRegressionCell — ряд регрессий без меток.
var accessKeyRegressionCell = cellTerm{series: metrics.AccessKeySignCountRegressionsMetric, labels: map[string]string{}}

// accessKeyReasonCell — клетка, которую правило читает по причине на ВСЕХ
// полосах: отбор без метки `lane`, сумма по полосам.
func accessKeyReasonCell(reason access_keys.Refusal) cellTerm {
	return cellTerm{series: metrics.AccessKeyRefusalsMetric, labels: map[string]string{"reason": string(reason)}}
}

// accessKeyProducerValues — перепись закрытых перечней производителя ключей:
// решётка «полоса × причина», как её засевает приёмник, события и ряд
// регрессий.
func accessKeyProducerValues() []producerValue {
	var out []producerValue
	for _, lane := range access_keys.Lanes() {
		for _, reason := range access_keys.Refusals() {
			out = append(out, producerValue{
				key: "refusal/" + string(lane) + "/" + string(reason),
				cell: cellTerm{series: metrics.AccessKeyRefusalsMetric,
					labels: map[string]string{"lane": string(lane), "reason": string(reason)}},
			})
		}
	}
	for _, e := range access_keys.Events() {
		out = append(out, producerValue{
			key:  "event/" + string(e),
			cell: cellTerm{series: metrics.AccessKeyEventsMetric, labels: map[string]string{"event": string(e)}},
		})
	}
	out = append(out, producerValue{key: "sign-count-regression", cell: accessKeyRegressionCell})
	return out
}

// accessKeyRefusalDecisions — решение о каждой ПРИЧИНЕ отказа; полос оно не
// различает: разъезд привязки одинаково виден на заведении и на утверждении.
func accessKeyRefusalDecisions() map[access_keys.Refusal]sideVerdict {
	binding := func(r access_keys.Refusal, why string) sideVerdict {
		c := accessKeyReasonCell(r)
		return sideVerdict{rule: ruleAccessKeyBinding, reads: &c, why: why}
	}
	return map[access_keys.Refusal]sideVerdict{
		access_keys.RefusalSessionNotFresh:     caller("сессия не свежа — предъявитель повышает уровень"),
		access_keys.RefusalChallengeUnknown:    caller("испытание не выдавалось — порядок шагов предъявителя"),
		access_keys.RefusalChallengeConsumed:   caller("испытание уже предъявлено — повтор предъявителя"),
		access_keys.RefusalChallengeExpired:    caller("испытание истекло — предъявитель опоздал"),
		access_keys.RefusalMalformed:           caller("тело ответа аутентификатора не разбирается — предъявитель"),
		access_keys.RefusalOriginNotAllowed:    binding(access_keys.RefusalOriginNotAllowed, "происхождение консоли вне привязки — посадка разъехалась с доменом"),
		access_keys.RefusalRPIDMismatch:        binding(access_keys.RefusalRPIDMismatch, "доверяющая сторона не наша — посадка разъехалась с доменом"),
		access_keys.RefusalUserNotPresent:      caller("присутствие не подтверждено — предъявитель"),
		access_keys.RefusalAlgorithmNotAllowed: caller("алгоритм аутентификатора вне перечня — устройство предъявителя"),
		access_keys.RefusalNotDiscoverable:     caller("ключ не обнаруживаемый — устройство предъявителя"),
		access_keys.RefusalSignature:           caller("подпись не сошлась — предъявитель"),
		access_keys.RefusalUnknownCredential:   caller("ключ неизвестен — предъявитель"),
		access_keys.RefusalForeignKey:          caller("ключ чужой — предъявитель"),
		access_keys.RefusalUserHandle:          caller("чужой дескриптор — предъявитель"),
		access_keys.RefusalCounter:             caller("счётчик не вырос — сигнал клонирования читает ряд регрессий, а не эта клетка"),
		access_keys.RefusalCounterRace:         caller("сдвиг счётчика перехвачен другим утверждением того же ключа — конкуренция предъявителя"),
		access_keys.RefusalLastSignInMethod:    caller("снимается последний способ входа — запрос человека"),
		access_keys.RefusalNotFound:            caller("ключа нет — запрос человека"),
		access_keys.RefusalForm:                caller("форма запроса — предъявитель"),
	}
}

// accessKeySideLedger — запись на КАЖДОЕ значение перечней ключей.
func accessKeySideLedger() map[string]sideVerdict {
	out := map[string]sideVerdict{}
	for _, lane := range access_keys.Lanes() {
		for reason, v := range accessKeyRefusalDecisions() {
			out["refusal/"+string(lane)+"/"+string(reason)] = v
		}
	}
	for key, why := range map[string]string{
		"event/registration-challenge-issued": "событие жизненного цикла, не отказ",
		"event/registered":                    "событие жизненного цикла, не отказ",
		"event/assertion-challenge-issued":    "событие жизненного цикла, не отказ",
		"event/asserted":                      "событие жизненного цикла, не отказ",
		"event/revoked":                       "снятие ключа человеком — событие, не отказ",
		"event/transferred":                   "перенос из прежнего компонента — событие, не отказ",
	} {
		out[key] = caller(why)
	}
	out["sign-count-regression"] = sideVerdict{rule: ruleAccessKeyRegression,
		why: "клонированный аутентификатор либо повтор утверждения — предмет разбора, а не шум"}
	return out
}

func TestAccessKeyProducerValuesAreSidedInTheRules(t *testing.T) {
	values := accessKeyProducerValues()
	require.NotEmpty(t, values, "перечни производителя ключей пусты — судить нечего, это не зелёное")
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	ledger := accessKeySideLedger()
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSideLedger(values, ledger, rules)
			t.Logf("ПЕРЕПИСЬ сторон ключей доступа (%s): значений у производителя %d · читает правило %d · "+
				"решение «не читает никто» %d · правил %d · находок %d",
				r.name, census.values, census.ours, census.caller, census.rules, len(findings))
			require.NotZero(t, census.ours, "ни одного значения, которое читает правило, — проверка беспредметна")
			require.Emptyf(t, findings, "значения ключей доступа не разнесены по правилам:\n  %s",
				strings.Join(findings, "\n  "))

			byName := map[string]alertRule{}
			for _, rule := range rules {
				byName[rule.Alert] = rule
			}
			engined := 0
			for _, v := range values {
				verdict := ledger[v.key]
				if verdict.rule == "" {
					continue
				}
				rule, ok := byName[verdict.rule]
				require.Truef(t, ok, "правила %s в объекте нет", verdict.rule)
				require.Truef(t, engineReadsCell(t, rule.Expr, v.cell),
					"движок: %s не звонит на рост клетки %s:\n%s", verdict.rule, v.cell, rule.Expr)
				engined++
			}
			t.Logf("движок: клеток, на рост которых звонит своё правило, %d", engined)
		})
	}
}

// Исходы происхождения и доверяющей стороны полосы входа ключом и ветви ключа
// повышения считает то же правило привязки (запись — loginLaneOutcomeSideLedger).
func TestAccessKeyLoginOriginOutcomesAreCountedByTheBindingRule(t *testing.T) {
	ledger := loginLaneOutcomeSideLedger()
	want := []string{"access-key-login/origin", "access-key-login/rp-id-hash",
		"step-up-access-key/origin", "step-up-access-key/rp-id-hash"}
	for _, key := range want {
		require.Equalf(t, ruleAccessKeyBinding, ledger[key].rule,
			"%s: исход разъезда привязки не отнесён к правилу %s — вход без пароля ломается молча", key, ruleAccessKeyBinding)
	}
}

// exposedBareCellRe — клетка ряда без меток в текстовой выдаче.
var exposedBareCellRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*) (\S+)$`)

// К4: каждая клетка, которую читают правила ключей, есть в выдаче
// производителя до первого события.
func TestAccessKeyCellsTheRulesReadArePreSeeded(t *testing.T) {
	reg := metrics.NewRegistry()
	reg.AccessKeyRecorder()
	reg.LoginLaneRecorder()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code, "выдача производителя не читается")

	var cells []cellTerm
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if m := exposedCellRe.FindStringSubmatch(line); m != nil {
			if labels, ok := selectorLabels(m[2]); ok {
				cells = append(cells, cellTerm{series: m[1], labels: labels})
			}
			continue
		}
		if m := exposedBareCellRe.FindStringSubmatch(line); m != nil {
			cells = append(cells, cellTerm{series: m[1], labels: map[string]string{}})
		}
	}

	// Требуемое: клетка, которую считает правило (у причины отказа — отбор без
	// полосы: достаточно одной засеянной полосы с этой причиной).
	var demands []cellTerm
	for _, v := range accessKeySideLedger() {
		if v.rule == "" {
			continue
		}
		if v.reads != nil {
			demands = append(demands, *v.reads)
		} else {
			demands = append(demands, accessKeyRegressionCell)
		}
	}
	for key, v := range loginLaneOutcomeSideLedger() {
		if v.rule != ruleAccessKeyBinding {
			continue
		}
		for _, pv := range loginLaneOutcomeProducerValues() {
			if pv.key == key {
				demands = append(demands, pv.cell)
			}
		}
	}

	seen := 0
	for _, d := range demands {
		found := false
		for _, e := range cells {
			if e.series != d.series {
				continue
			}
			sub := true
			for k, val := range d.labels {
				if e.labels[k] != val {
					sub = false
				}
			}
			if sub {
				found = true
				break
			}
		}
		require.Truef(t, found, "клетка %s НЕ предзаведена производителем: `A + пусто` в PromQL — пусто, "+
			"и правило оглохло бы целиком до первого события", d)
		seen++
	}
	t.Logf("ПЕРЕПИСЬ предзаведённых клеток ключей: клеток в выдаче %d · требований проверено %d", len(cells), seen)
	require.NotZero(t, len(cells), "выдача производителя пуста — судить нечего")
	require.NotZero(t, seen, "требований ноль — проверка беспредметна")
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

const (
	lawfulAccessKeyBindingExpr = `sum(increase(kaname_access_key_refusals_total{reason="origin-not-allowed"}[10m]))
  + sum(increase(kaname_access_key_refusals_total{reason="rp-id-mismatch"}[10m]))
  + sum(increase(kaname_access_key_login_outcomes_total{outcome="origin"}[10m]))
  + sum(increase(kaname_access_key_login_outcomes_total{outcome="rp-id-hash"}[10m]))
  + sum(increase(kaname_step_up_access_key_outcomes_total{outcome="origin"}[10m]))
  + sum(increase(kaname_step_up_access_key_outcomes_total{outcome="rp-id-hash"}[10m])) > 0`
	lawfulAccessKeyRegressionExpr = `sum(increase(kaname_access_key_sign_count_regressions_total[1h])) > 0`
)

func accessKeyInjectedRules(binding, regression string) []alertRule {
	return []alertRule{
		{Alert: ruleAccessKeyBinding, Expr: binding},
		{Alert: ruleAccessKeyRegression, Expr: regression},
	}
}

func TestAccessKeyLedgerInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeSideLedger(accessKeyProducerValues(), accessKeySideLedger(),
		accessKeyInjectedRules(lawfulAccessKeyBindingExpr, lawfulAccessKeyRegressionExpr))
	require.Empty(t, findings)
	require.Equal(t, census.values, census.ours+census.caller)
	// две причины на трёх полосах и ряд регрессий
	require.Equal(t, 2*len(access_keys.Lanes())+1, census.ours)
}

func TestAccessKeyLedgerInjection_DroppedOriginTermIsFound(t *testing.T) {
	dropped := strings.Replace(lawfulAccessKeyBindingExpr,
		`sum(increase(kaname_access_key_refusals_total{reason="origin-not-allowed"}[10m]))
  + `, "", 1)
	require.NotEqual(t, lawfulAccessKeyBindingExpr, dropped, "инъекция не сняла слагаемое")
	_, findings := judgeSideLedger(accessKeyProducerValues(), accessKeySideLedger(),
		accessKeyInjectedRules(dropped, lawfulAccessKeyRegressionExpr))
	require.Len(t, findings, len(access_keys.Lanes()), "по находке на полосу: %v", findings)
	for _, f := range findings {
		require.Contains(t, f, "/origin-not-allowed: наша сторона, а правило "+ruleAccessKeyBinding+" не считает клетку")
	}
}

func TestAccessKeyLedgerInjection_MissingRegressionRuleIsFound(t *testing.T) {
	_, findings := judgeSideLedger(accessKeyProducerValues(), accessKeySideLedger(),
		[]alertRule{{Alert: ruleAccessKeyBinding, Expr: lawfulAccessKeyBindingExpr}})
	require.Equal(t, []string{"sign-count-regression: наша сторона, а правила " + ruleAccessKeyRegression + " в наборе нет"}, findings)
}

func TestAccessKeyLedgerInjection_CallerReasonCountedIsFound(t *testing.T) {
	for name, tc := range map[string]struct{ expr, key string }{
		"причина предъявителя": {
			expr: strings.Replace(lawfulAccessKeyBindingExpr, `reason="rp-id-mismatch"`, `reason=~"rp-id-mismatch|signature"`, 1),
			key:  "refusal/assertion/signature"},
		"ряд отказов по полосе без причины": {
			expr: lawfulAccessKeyBindingExpr[:len(lawfulAccessKeyBindingExpr)-len(" > 0")] +
				"\n  + sum(increase(kaname_access_key_refusals_total{lane=\"assertion\"}[10m])) > 0",
			key: "refusal/assertion/counter"},
		"событие жизненного цикла": {
			expr: lawfulAccessKeyBindingExpr[:len(lawfulAccessKeyBindingExpr)-len(" > 0")] +
				"\n  + sum(increase(kaname_access_key_events_total{event=\"revoked\"}[10m])) > 0",
			key: "event/revoked"},
	} {
		t.Run(name, func(t *testing.T) {
			_, findings := judgeSideLedger(accessKeyProducerValues(), accessKeySideLedger(),
				accessKeyInjectedRules(tc.expr, lawfulAccessKeyRegressionExpr))
			require.Contains(t, strings.Join(findings, "\n"), tc.key+": сторона вызывающего, а правило "+ruleAccessKeyBinding)
		})
	}
}

func TestAccessKeyLedgerInjection_NewProducerReasonWithoutDecisionIsFound(t *testing.T) {
	values := append(accessKeyProducerValues(), producerValue{
		key: "refusal/assertion/store-failed",
		cell: cellTerm{series: metrics.AccessKeyRefusalsMetric,
			labels: map[string]string{"lane": "assertion", "reason": "store-failed"}},
	})
	_, findings := judgeSideLedger(values, accessKeySideLedger(),
		accessKeyInjectedRules(lawfulAccessKeyBindingExpr, lawfulAccessKeyRegressionExpr))
	require.Equal(t, []string{"refusal/assertion/store-failed: значение производителя без записи — реши сторону: " +
		"«наша сторона → правило» либо «сторона вызывающего → никакого»"}, findings)
}

func TestAccessKeyLedgerInjection_DecisionOutlivingItsValueIsFound(t *testing.T) {
	ledger := accessKeySideLedger()
	ledger["event/retired"] = caller("снятое событие")
	_, findings := judgeSideLedger(accessKeyProducerValues(), ledger,
		accessKeyInjectedRules(lawfulAccessKeyBindingExpr, lawfulAccessKeyRegressionExpr))
	require.Equal(t, []string{"event/retired: запись есть, значения у производителя нет — запись истекла вместе с ним"}, findings)
}

// Движок различает канон правил ключей: звонит на рост своей клетки и молчит,
// когда растёт клетка предъявителя.
func TestAccessKeyRulesEnginePremise(t *testing.T) {
	origin := cellTerm{series: metrics.AccessKeyRefusalsMetric,
		labels: map[string]string{"lane": "registration", "reason": "origin-not-allowed"}}
	signature := cellTerm{series: metrics.AccessKeyRefusalsMetric,
		labels: map[string]string{"lane": "assertion", "reason": "signature"}}
	require.True(t, engineReadsCell(t, lawfulAccessKeyBindingExpr, origin), "канон привязки не звонит на рост своей клетки")
	require.False(t, engineFires(t, lawfulAccessKeyBindingExpr, &signature), "канон привязки звонит на отказ подписи")
	require.True(t, engineReadsCell(t, lawfulAccessKeyRegressionExpr, accessKeyRegressionCell), "канон регрессий не звонит на рост ряда")
}
