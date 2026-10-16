// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_lane_our_side_outcomes_ledger_test.go — исходы НАШЕЙ стороны рядов
// подтверждения адреса, смены адреса, входа ключом и ветви ключа повышения
// считает правило отказов полосы входа (kaname#735).
//
// Правило KanameLoginLaneFailing объявлено как «звонят отказы нашей стороны»,
// а прежде не читало `store-failed` и `mark-not-reapplied` смены адреса,
// `store-failed` подтверждения адреса, входа ключом и ветви ключа повышения.
// Каждое значение перечня производителя разносится по сторонам тем же
// суждением, что второй фактор ([judgeSideLedger]): значение без записи —
// находка, запись без значения — находка, наша сторона — правило СЧИТАЕТ
// клетку, сторона вызывающего — ни одно правило её не читает.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

func outcomeCell(series, outcome string) cellTerm {
	return cellTerm{series: series, labels: map[string]string{"outcome": outcome}}
}

// loginLaneOutcomeProducerValues — перепись четырёх закрытых перечней.
func loginLaneOutcomeProducerValues() []producerValue {
	var out []producerValue
	add := func(prefix, series string, values []string) {
		for _, v := range values {
			out = append(out, producerValue{key: prefix + "/" + v, cell: outcomeCell(series, v)})
		}
	}
	var verify, change, akLogin, akStepUp []string
	for _, o := range humansession.VerificationOutcomes() {
		verify = append(verify, string(o))
	}
	for _, o := range humansession.EmailChangeOutcomes() {
		change = append(change, string(o))
	}
	for _, o := range humansession.AccessKeyLoginOutcomes() {
		akLogin = append(akLogin, string(o))
	}
	for _, o := range humansession.StepUpAccessKeyOutcomes() {
		akStepUp = append(akStepUp, string(o))
	}
	add("address-verification", metrics.AddressVerificationOutcomesMetric, verify)
	add("email-change", metrics.EmailChangeOutcomesMetric, change)
	add("access-key-login", metrics.AccessKeyLoginOutcomesMetric, akLogin)
	add("step-up-access-key", metrics.StepUpAccessKeyOutcomesMetric, akStepUp)
	return out
}

func loginLaneOutcomeSideLedger() map[string]sideVerdict {
	ours := func(why string) sideVerdict { return sideVerdict{rule: ruleLaneFailing, why: why} }
	return map[string]sideVerdict{
		"address-verification/letter-queued":             caller("письмо поставлено — успех"),
		"address-verification/letter-paced":              caller("интервал писем человека не истёк"),
		"address-verification/already-verified":          caller("адрес уже подтверждён — повтор человека"),
		"address-verification/no-session":                caller("сессии нет — предъявитель"),
		"address-verification/confirmed":                 caller("успех"),
		"address-verification/code-mismatched":           caller("неверный код человека"),
		"address-verification/code-not-found":            caller("кода нет либо истёк — состояние человека"),
		"address-verification/code-exhausted":            caller("исчерпан предел попыток человека"),
		"address-verification/invite-not-valid":          caller("приглашение больше не действует — состояние записи"),
		"address-verification/store-failed":              ours("хранилище не ответило на подтверждении адреса — человек застревает на экране подтверждения"),
		"address-verification/position-refused-lane":     caller("неподтверждённый адрес обратился к закрытому пути — положение человека"),
		"address-verification/position-refused-listener": caller("неподтверждённый адрес обратился к закрытому методу — положение человека"),

		"email-change/letter-queued":      caller("письмо поставлено — успех"),
		"email-change/address-taken":      caller("занятый адрес — запрос человека"),
		"email-change/person-paced":       caller("темп запросов человека"),
		"email-change/recipient-paced":    caller("окно писем адресата полно"),
		"email-change/no-session":         caller("сессии нет — предъявитель"),
		"email-change/not-verified":       caller("адрес человека не подтверждён"),
		"email-change/step-up-required":   caller("человек повышает уровень"),
		"email-change/not-fresh":          caller("сессия не свежа — предъявитель"),
		"email-change/field-refused":      caller("форма поля — предъявитель"),
		"email-change/confirmed":          caller("успех"),
		"email-change/code-mismatched":    caller("неверный код человека"),
		"email-change/code-not-found":     caller("кода нет, истёк либо вытеснен"),
		"email-change/code-exhausted":     caller("исчерпан предел попыток человека"),
		"email-change/address-in-use":     caller("адрес заняли между запросом и предъявлением"),
		"email-change/store-failed":       ours("хранилище не ответило на смене адреса"),
		"email-change/mark-not-reapplied": ours("отметка подтверждения не поставлена на новый адрес — дефект хранилища, исход откатан"),

		"access-key-login/issued":             caller("успех"),
		"access-key-login/challenge-issued":   caller("выдано испытание — успех шага"),
		"access-key-login/signature":          caller("подпись не сошлась — предъявитель"),
		"access-key-login/credential-unknown": caller("ключ неизвестен либо снят — предъявитель"),
		"access-key-login/origin":             {rule: ruleAccessKeyBinding, why: "происхождение консоли вне привязки — посадка разъехалась с доменом (kaname#310)"},
		"access-key-login/rp-id-hash":         {rule: ruleAccessKeyBinding, why: "доверяющая сторона не наша — посадка разъехалась с доменом (kaname#310)"},
		"access-key-login/presence":           caller("присутствие не подтверждено — предъявитель"),
		"access-key-login/counter":            caller("счётчик не вырос — предъявитель"),
		"access-key-login/challenge":          caller("испытания нет либо оно предъявлено — порядок шагов"),
		"access-key-login/user-handle":        caller("чужой дескриптор — предъявитель"),
		"access-key-login/blocked":            caller("личность заблокирована"),
		"access-key-login/rate-limited":       caller("темп попыток"),
		"access-key-login/store-failed":       ours("хранилище не ответило на входе ключом"),

		"step-up-access-key/challenge-issued":   caller("выдано испытание — успех шага"),
		"step-up-access-key/signature":          caller("подпись не сошлась — предъявитель"),
		"step-up-access-key/credential-unknown": caller("ключ неизвестен либо чужой — предъявитель"),
		"step-up-access-key/origin":             {rule: ruleAccessKeyBinding, why: "происхождение консоли вне привязки — посадка разъехалась с доменом (kaname#310)"},
		"step-up-access-key/rp-id-hash":         {rule: ruleAccessKeyBinding, why: "доверяющая сторона не наша — посадка разъехалась с доменом (kaname#310)"},
		"step-up-access-key/presence":           caller("присутствие не подтверждено — предъявитель"),
		"step-up-access-key/counter":            caller("счётчик не вырос — предъявитель"),
		"step-up-access-key/challenge":          caller("испытания этой сессии нет — порядок шагов"),
		"step-up-access-key/user-handle":        caller("чужой дескриптор — предъявитель"),
		"step-up-access-key/store-failed":       ours("хранилище не ответило на ветви ключа повышения"),
	}
}

func TestLoginLaneOurSideOutcomesAreCountedByTheLaneRule(t *testing.T) {
	values := loginLaneOutcomeProducerValues()
	require.NotEmpty(t, values, "перечни производителя пусты — судить нечего, это не зелёное")
	renders := alertRenders(t)
	require.NotEmpty(t, renders, "перепись профилей пуста — судить нечего, это не зелёное")
	ledger := loginLaneOutcomeSideLedger()
	for _, r := range renders {
		t.Run(r.name, func(t *testing.T) {
			rules, objects := chartAlertRules(t, renderStandaloneChart(t, r.chain, r.sets...))
			require.Equal(t, 1, objects, "объект правил не отрендерился — судить нечего")
			census, findings := judgeSideLedger(values, ledger, rules)
			t.Logf("ПЕРЕПИСЬ сторон исходов полосы входа (%s): значений у производителя %d · наша сторона %d · "+
				"сторона вызывающего %d · правил %d · находок %d",
				r.name, census.values, census.ours, census.caller, census.rules, len(findings))
			require.NotZero(t, census.ours, "ни одного значения нашей стороны — проверка беспредметна")
			require.Emptyf(t, findings, "исходы нашей стороны не считает правило:\n  %s", strings.Join(findings, "\n  "))

			var lane *alertRule
			for i := range rules {
				if rules[i].Alert == ruleLaneFailing {
					lane = &rules[i]
				}
			}
			require.NotNil(t, lane, "правила %s в объекте нет", ruleLaneFailing)
			for _, v := range values {
				// Исходы разъезда привязки считает правило ключей; движок для
				// него — в access_key_alert_rules_test.go.
				if ledger[v.key].rule != ruleLaneFailing {
					continue
				}
				require.Truef(t, engineReadsCell(t, lane.Expr, v.cell),
					"движок: %s не звонит на рост клетки %s:\n%s", ruleLaneFailing, v.cell, lane.Expr)
			}
		})
	}
}

// --- инъекция: суждение способно упасть, законный близнец молчит ---

const lawfulLoginLaneOutcomesExpr = `sum(increase(kaname_login_outcomes_total{outcome=~"store-failed|verifier-issue"}[10m]))
  + sum(increase(kaname_address_verification_outcomes_total{outcome="store-failed"}[10m]))
  + sum(increase(kaname_email_change_outcomes_total{outcome="store-failed"}[10m]))
  + sum(increase(kaname_email_change_outcomes_total{outcome="mark-not-reapplied"}[10m]))
  + sum(increase(kaname_access_key_login_outcomes_total{outcome="store-failed"}[10m]))
  + sum(increase(kaname_step_up_access_key_outcomes_total{outcome="store-failed"}[10m])) > 0`

// loginLaneLedgerRules — правило полосы входа с выражением expr, законное
// правило ёмкости и законное правило привязки ключей.
func loginLaneLedgerRules(expr string) []alertRule {
	return append(injectedRules(expr, lawfulCapacityExpr),
		alertRule{Alert: ruleAccessKeyBinding, Expr: lawfulAccessKeyBindingExpr})
}

func TestLoginLaneOutcomesLedgerInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeSideLedger(loginLaneOutcomeProducerValues(), loginLaneOutcomeSideLedger(),
		loginLaneLedgerRules(lawfulLoginLaneOutcomesExpr))
	require.Empty(t, findings)
	require.Equal(t, census.values, census.ours+census.caller)
	// пять исходов хранилища и четыре исхода разъезда привязки ключей
	require.Equal(t, 9, census.ours)
}

func TestLoginLaneOutcomesLedgerInjection_DroppedTermIsFound(t *testing.T) {
	dropped := strings.Replace(lawfulLoginLaneOutcomesExpr,
		"\n  + sum(increase(kaname_email_change_outcomes_total{outcome=\"mark-not-reapplied\"}[10m]))", "", 1)
	require.NotEqual(t, lawfulLoginLaneOutcomesExpr, dropped, "инъекция не сняла слагаемое")
	_, findings := judgeSideLedger(loginLaneOutcomeProducerValues(), loginLaneOutcomeSideLedger(),
		loginLaneLedgerRules(dropped))
	require.Len(t, findings, 1, "%v", findings)
	require.Contains(t, findings[0], "email-change/mark-not-reapplied: наша сторона, а правило KanameLoginLaneFailing не считает клетку")
}

func TestLoginLaneOutcomesLedgerInjection_CallerSideCountedIsFound(t *testing.T) {
	wide := strings.Replace(lawfulLoginLaneOutcomesExpr,
		`kaname_access_key_login_outcomes_total{outcome="store-failed"}`,
		`kaname_access_key_login_outcomes_total{outcome=~"store-failed|signature"}`, 1)
	_, findings := judgeSideLedger(loginLaneOutcomeProducerValues(), loginLaneOutcomeSideLedger(),
		loginLaneLedgerRules(wide))
	require.Contains(t, strings.Join(findings, "\n"), "access-key-login/signature: сторона вызывающего, а правило KanameLoginLaneFailing")
}
