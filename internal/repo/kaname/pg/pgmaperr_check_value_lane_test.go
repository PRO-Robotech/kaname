// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_check_value_lane_test.go — полоса отказа проверки (23514) по вопросу
// «чьё это значение» на ВСЕЙ схеме, а не на трёх таблицах (kaname#395).
//
// Предмет. Значение колонки, которую пишет служба (закрытый словарь, константа
// домена, отчеканенный идентификатор, отметка времени, выведенная строка),
// вызывающий не присылает. Отказ проверки на ней — дефект службы: отвечать на
// него `INVALID_ARGUMENT` значит обвинить вызывающего в ошибке, которую ему
// нечем исправить, и не оставить оператору ни строки в журнале. Отказ по
// значению, которое прислал вызывающий, остаётся полосой ввода с прежним
// текстом.
//
// Проба синтетическая: поля отказа заполняет она сама. Что кладёт настоящий
// сервер (таблицу, имя ограничения, строку целиком в `Detail`), утверждает
// integration-проба той же полосы (`check_value_lane_integration_test.go`).

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// cvBearerInDetail — материал строки так, как его положил бы сервер в `Detail`:
// дайджест предъявителя сессии. Ни в ответ, ни в журнал он доехать не вправе.
const cvBearerInDetail = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

// cvCheckPgErr — отказ проверки в той форме, в какой его отдаёт сервер: имя
// таблицы, имя ограничения, текст драйвера с обоими и строка целиком в `Detail`.
func cvCheckPgErr(constraint, table string) *pgconn.PgError {
	return &pgconn.PgError{
		Code:           "23514",
		ConstraintName: constraint,
		TableName:      table,
		Message:        `new row for relation "` + table + `" violates check constraint "` + constraint + `"`,
		Detail:         "Failing row contains (hss-probe, " + cvBearerInDetail + ", bogus-reason).",
	}
}

func cvCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestWrapPgErr_ServiceProducedCheckIsOurDefect — сторона 1. Колонку
// `human_sessions.ended_reason` пишут только константы домена: причина из
// запроса до неё не доходит. Сработавшее ограничение — наш дефект.
func TestWrapPgErr_ServiceProducedCheckIsOurDefect(t *testing.T) {
	const constraint, table = "human_sessions_ended_reason_check", "human_sessions"
	logBuf := cvCaptureLog(t)

	pgErr := cvCheckPgErr(constraint, table)
	err := wrapPgErr(pgErr, "HumanSession", "hss-probe")

	require.False(t, stderrors.Is(err, iamerr.ErrInvalidArg),
		"%s: значение производит служба — вызывающий обвинён в чужом дефекте: %v", constraint, err)
	require.True(t, stderrors.Is(err, iamerr.ErrInternal), "%s: want ErrInternal, got %v", constraint, err)
	require.Equal(t, iamerr.ErrInternal.Error(), err.Error(),
		"текст отказа фиксированный: ни имени ограничения, ни текста драйвера, ни строки")

	logged := logBuf.String()
	require.Contains(t, logged, "check backstop fired",
		"положительный контроль: оператор узнаёт о сработавшем рубеже")
	require.Contains(t, logged, "constraint="+constraint, "запись называет ограничение")
	require.Contains(t, logged, "table="+table, "запись называет таблицу")
	require.Contains(t, logged, "id=hss-probe", "запись называет строку")
	require.NotContains(t, logged, cvBearerInDetail, "материал строки не доезжает до журнала")
	require.NotContains(t, logged, "Failing row", "Detail не доезжает до журнала")
	require.NotContains(t, logged, pgErr.Message, "текст драйвера не доезжает до журнала")
}

// TestWrapPgErr_CallerSentCheckStaysInputLane — сторона 2, законный близнец:
// та же форма отказа, отличается ОДНИМ фактом — значение прислал вызывающий.
// Без неё сторона 1 зеленела бы на переводчике, объявляющем дефектом службы
// всякую проверку.
func TestWrapPgErr_CallerSentCheckStaysInputLane(t *testing.T) {
	const constraint, table = "accounts_description_check", "accounts"
	logBuf := cvCaptureLog(t)

	err := wrapPgErr(cvCheckPgErr(constraint, table), "Account", "acc-probe")

	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "%s: полоса ввода, получено %v", constraint, err)
	require.Equal(t, "Illegal argument description: length must be <=256", iamerr.StripSentinel(err),
		"текст полосы ввода прежний")
	require.False(t, strings.Contains(logBuf.String(), "check backstop fired"),
		"значение вызывающего не пишет записи о рубеже службы: %s", logBuf.String())
}

// TestWrapPgErr_ServiceValueLaneJudgesTheRefusingTable — близнец по второй
// координате: то же имя ограничения, но таблицы, о которой перепись не
// говорит ничего. Переводчик судит строку, названную сервером, а не похожее
// имя, и неизвестное полосе дефекта не отдаёт.
func TestWrapPgErr_ServiceValueLaneJudgesTheRefusingTable(t *testing.T) {
	logBuf := cvCaptureLog(t)

	err := wrapPgErr(cvCheckPgErr("human_sessions_ended_reason_check", secretTable), "HumanSession", "hss-probe")

	require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg),
		"ограничение таблицы вне переписи не отводится в полосу дефекта, получено %v", err)
	require.Equal(t, "Illegal argument: value violates a constraint", iamerr.StripSentinel(err))
	require.False(t, strings.Contains(logBuf.String(), "check backstop fired"),
		"близнец не пишет записи о рубеже: %s", logBuf.String())
}

// cvCallerValueSpec — СПЕЦИФИКАЦИЯ полосы ввода: проверки схемы, судящие
// значение, которое прислал вызывающий (публичный или внутренний, в том числе
// соседняя служба и манифест модуля), — как есть, после обрезки пробелов либо
// арифметикой от присланного числа. Всякая иная живая проверка судит значение
// службы и обязана отвечать фиксированным INTERNAL.
//
// Перепись в коде (`checkValueLanes`) — реализация; спецификация — независимый
// от неё ответ на тот же вопрос, и integration-проба сверяет с ним ответ
// переводчика на каждой живой проверке. Совпадение двух перечней не довод:
// довод — ответ переводчика, который судит по одному из них.
var cvCallerValueSpec = map[string]struct{}{
	"access_binding_subjects_id_nonempty_ck":               {},
	"access_binding_subjects_type_ck":                      {},
	"access_bindings_expires_future_ck":                    {},
	"access_bindings_grant_form_ck":                        {},
	"access_bindings_labels_valid":                         {},
	"access_bindings_resource_ck":                          {},
	"access_bindings_subject_ck":                           {},
	"access_bindings_target_resources_card_ck":             {},
	"access_bindings_wildcard_subject_is_system_ck":        {},
	"accounts_description_check":                           {},
	"accounts_labels_valid":                                {},
	"authorization_codes_challenge_form_ck":                {},
	"authorization_codes_challenge_method_ck":              {},
	"authorization_codes_redirect_uri_ck":                  {},
	"catalog_module_nonempty":                              {},
	"catalog_module_undotted":                              {},
	"catalog_resource_module_undotted":                     {},
	"catalog_resource_nonempty":                            {},
	"catalog_resource_object_type_form":                    {},
	"catalog_resource_resource_undotted":                   {},
	"catalog_verb_nonempty":                                {},
	"catalog_verb_undotted":                                {},
	"client_assertion_replay_assertion_ck":                 {},
	"client_assertion_replay_client_ck":                    {},
	"cluster_admin_grants_subject_id_check":                {},
	"federated_trusted_issuers_alg_ck":                     {},
	"federated_trusted_issuers_expires_future_ck":          {},
	"federated_trusted_issuers_issuer_ck":                  {},
	"federated_trusted_issuers_key_not_blank":              {},
	"federated_trusted_issuers_subject_ck":                 {},
	"group_members_type_check":                             {},
	"groups_description_check":                             {},
	"groups_labels_valid":                                  {},
	"interactive_clients_post_logout_uris_count_ck":        {},
	"interactive_clients_redirect_uris_count_ck":           {},
	"login_failures_key_check":                             {},
	"minted_token_revocations_reason_ck":                   {},
	"minted_token_revocations_subject_ck":                  {},
	"projects_description_check":                           {},
	"projects_labels_valid":                                {},
	"public_read_publication_object_id_nonempty":           {},
	"public_read_publication_object_type_model_dictionary": {},
	"recovery_completions_external_id_check":               {},
	"recovery_completions_jti_check":                       {},
	"resource_mirror_id_nonempty":                          {},
	"resource_mirror_type_nonempty":                        {},
	"resource_parent_edge_no_self":                         {},
	"resource_parent_edge_object_id_nonempty":              {},
	"resource_parent_edge_parent_id_nonempty":              {},
	"role_rule_ref_module_undotted":                        {},
	"role_rule_ref_nonempty":                               {},
	"role_rule_ref_resource_undotted":                      {},
	"role_rule_ref_verb_nonempty":                          {},
	"role_rule_ref_verb_undotted":                          {},
	"role_rule_selectors_arm_shape":                        {},
	"role_rule_selectors_labels_valid":                     {},
	"role_rule_selectors_types_nonempty":                   {},
	"role_verb_type_nonempty":                              {},
	"role_verb_verb_canonical":                             {},
	"role_verb_verb_nonempty":                              {},
	"roles_description_check":                              {},
	"roles_labels_valid":                                   {},
	"roles_owner_module_name_prefix":                       {},
	"roles_permissions_valid":                              {},
	"roles_rule_wildcards_confined":                        {},
	"roles_rules_valid":                                    {},
	"sa_oauth_clients_declared_audiences_wellformed":       {},
	"service_account_oauth_clients_description_check":      {},
	"service_account_oauth_clients_expires_future_ck":      {},
	"service_account_oauth_clients_labels_valid":           {},
	"service_accounts_description_check":                   {},
	"service_accounts_labels_valid":                        {},
	"session_revocations_reason_check":                     {},
	"session_revocations_token_jti_check":                  {},
	"session_revocations_ttl_future_ck":                    {},
	"user_access_keys_algorithm_check":                     {},
	"user_access_keys_credential_id_check":                 {},
	"user_access_keys_description_check":                   {},
	"user_access_keys_public_key_check":                    {},
	"user_access_keys_sign_count_check":                    {},
	"user_oauth_clients_description_check":                 {},
	"user_oauth_clients_expires_future_ck":                 {},
	"user_oauth_clients_labels_valid":                      {},
	"user_token_revocations_reason_check":                  {},
	"users_display_name_check":                             {},
	"users_email_check":                                    {},
	"users_external_id_check":                              {},
	"users_invite_status_consistency":                      {},
	"users_labels_valid":                                   {},
}

// cvLiveCheck — одна живая проверка схемы: таблица и имя ограничения.
type cvLiveCheck struct{ table, constraint string }

// cvJudge — ответ переводчика на КАЖДУЮ проверку перечня против спецификации.
// Находка называет таблицу, ограничение, ожидавшуюся полосу и полученный
// ответ. Счёт полос возвращается отдельно: «находок 0» при «проверено 0» —
// не вердикт.
func cvJudge(live []cvLiveCheck, spec map[string]struct{}) (findings []string, input, defect int) {
	for _, c := range live {
		err := wrapPgErr(cvCheckPgErr(c.constraint, c.table), "CheckCensus", "census")
		if _, caller := spec[c.constraint]; caller {
			input++
			if !stderrors.Is(err, iamerr.ErrInvalidArg) || iamerr.StripSentinel(err) != checkText(cvCheckPgErr(c.constraint, c.table)) {
				findings = append(findings, c.table+"."+c.constraint+
					": значение присылает вызывающий — ждали INVALID_ARGUMENT с текстом полосы ввода, получено «"+err.Error()+"»")
			}
			continue
		}
		defect++
		if !stderrors.Is(err, iamerr.ErrInternal) || err.Error() != iamerr.ErrInternal.Error() {
			findings = append(findings, c.table+"."+c.constraint+
				": значение производит служба — ждали фиксированный INTERNAL, получено «"+err.Error()+"»")
		}
	}
	return findings, input, defect
}

// cvUndecided — прямое направление переписи: живые проверки, о которых она не
// говорит ничего. Такой отказ отвечал бы прежней полосой ввода без решения.
func cvUndecided(live []cvLiveCheck) []string {
	var out []string
	for _, c := range live {
		if checkValueLaneOf(c.table, c.constraint) == checkLaneUndecided {
			out = append(out, c.table+"."+c.constraint+": перепись о проверке не говорит ничего — решение не принято")
		}
	}
	return out
}

// cvSwapLanes подменяет перепись на время пробы.
func cvSwapLanes(t *testing.T, mutate func(map[string]*checkTableLanes)) {
	t.Helper()
	saved := checkValueLanes
	copied := make(map[string]*checkTableLanes, len(saved))
	for k, v := range saved {
		copied[k] = v
	}
	mutate(copied)
	checkValueLanes = copied
	t.Cleanup(func() { checkValueLanes = saved })
}

// cvInjectionLive — синтетическая перепись из двух близнецов: служебная колонка
// и ввод вызывающего. Живая схема для инъекции не нужна — её предмет решение
// переписи и ответ переводчика, а не схема.
var cvInjectionLive = []cvLiveCheck{
	{"human_sessions", "human_sessions_ended_reason_check"},
	{"accounts", "accounts_description_check"},
}

// TestCheckValueCensus_ServiceCheckReturnedToInputLaneIsFound — инъекция в обе
// стороны. Контроль: неподменённая перепись находок не даёт. Инъекция 1:
// служебное ограничение возвращено в полосу ввода перечнем таблицы. Инъекция 2:
// таблица снята с переписи, и отказ уходит в общую ветку без решения. Каждая
// обязана покраснеть и назвать ограничение, а близнец полосы ввода — промолчать.
func TestCheckValueCensus_ServiceCheckReturnedToInputLaneIsFound(t *testing.T) {
	cvCaptureLog(t)
	const target = "human_sessions.human_sessions_ended_reason_check"

	findings, input, defect := cvJudge(cvInjectionLive, cvCallerValueSpec)
	require.Empty(t, findings, "контроль: неподменённая перепись обязана молчать")
	require.Equal(t, 1, input, "контроль: осмотрен близнец полосы ввода")
	require.Equal(t, 1, defect, "контроль: осмотрена служебная колонка")

	for name, mutate := range map[string]func(map[string]*checkTableLanes){
		"в перечне ввода таблицы": func(m map[string]*checkTableLanes) {
			m["human_sessions"] = &checkTableLanes{caller: []string{"human_sessions_ended_reason_check"}}
		},
		"таблица снята с переписи": func(m map[string]*checkTableLanes) {
			delete(m, "human_sessions")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cvSwapLanes(t, mutate)
			findings, _, _ := cvJudge(cvInjectionLive, cvCallerValueSpec)
			require.Len(t, findings, 1, "инъекция обязана дать ровно одну находку: %v", findings)
			require.Contains(t, findings[0], target, "находка называет ограничение")
			require.Contains(t, findings[0], "ждали фиксированный INTERNAL", "находка называет ожидавшуюся полосу")
		})
	}
}

// TestCheckValueCensus_NewCheckOfAMixedTableIsUndecided — прямое направление
// переписи на синтетике. Проверка, заведённая у таблицы, куда попадает
// присланное, без решения — находка; такая же проверка у таблицы, которую
// служба пишет целиком, решена построением — законный близнец молчит.
func TestCheckValueCensus_NewCheckOfAMixedTableIsUndecided(t *testing.T) {
	require.Empty(t, cvUndecided(cvInjectionLive), "контроль: решённые проверки находок не дают")

	undecided := cvUndecided([]cvLiveCheck{{"accounts", "accounts_new_ck"}})
	require.Len(t, undecided, 1, "проверка смешанной таблицы без решения обязана быть находкой")
	require.Contains(t, undecided[0], "accounts.accounts_new_ck")

	require.Empty(t, cvUndecided([]cvLiveCheck{{"human_sessions", "human_sessions_new_ck"}}),
		"близнец: таблица, которую служба пишет целиком, решает новую проверку построением")
}

// cvIssuanceDisagreement — отказ проверки таблицы записей выпуска (kaname#319)
// у обоих её переводчиков: писателя выпуска (`issuanceRefusal`, судит классом
// отказа) и общего (`wrapPgErr`, судит переписью). Находка называет
// ограничение и тот ответ, который не фиксированный INTERNAL.
func cvIssuanceDisagreement(constraint string) []string {
	pgErr := cvCheckPgErr(constraint, issuanceTable)
	var out []string
	for _, a := range []struct {
		who string
		err error
	}{
		{"писатель выпуска", issuanceRefusal(context.Background(), pgErr, "tok-probe", "tfm-probe")},
		{"перепись", wrapPgErr(pgErr, "AccessToken", "tok-probe")},
	} {
		if !stderrors.Is(a.err, iamerr.ErrInternal) || a.err.Error() != iamerr.ErrInternal.Error() {
			out = append(out, issuanceTable+"."+constraint+": "+a.who+
				" — значение производит служба, ждали фиксированный INTERNAL, получено «"+a.err.Error()+"»")
		}
	}
	return out
}

// TestCheckValueCensus_IssuanceTableAnswersAsItsWriter — у отказа проверки
// таблицы записей выпуска два переводчика, и ответ у них один. Каждое значение
// записи производит служба (`RecordAccessToken`, «ИСХОДОВ ДВА»), писатель
// судит отказ классом, а не именем, — значит и перепись обязана решать таблицу
// целиком. Имя ограничения синтетическое: решение не зависит от имени, в том
// числе у проверки, заведённой позже. Инъекция роняет только решение переписи
// о таблице.
func TestCheckValueCensus_IssuanceTableAnswersAsItsWriter(t *testing.T) {
	cvCaptureLog(t)
	const constraint = "access_tokens_later_ck"

	require.Empty(t, cvIssuanceDisagreement(constraint), "контроль: оба переводчика отвечают фиксированным INTERNAL")

	t.Run("таблица снята с переписи", func(t *testing.T) {
		cvSwapLanes(t, func(m map[string]*checkTableLanes) { delete(m, issuanceTable) })
		findings := cvIssuanceDisagreement(constraint)
		require.Len(t, findings, 1, "расходится ровно перепись, писатель судит классом: %v", findings)
		require.Contains(t, findings[0], issuanceTable+"."+constraint+": перепись", "находка называет ограничение и переводчика")
		require.Contains(t, findings[0], "invalid argument", "находка называет полученную полосу ввода")
	})
}
