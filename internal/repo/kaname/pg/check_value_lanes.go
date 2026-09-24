// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// check_value_lanes.go — перепись проверок схемы по вопросу «чьё это значение»
// (kaname#395): дом решения, какой отказ 23514 есть ввод вызывающего, а какой —
// дефект службы.
//
// # Зачем
//
// Колонку, которую пишет служба, вызывающий не присылает. Отказ проверки на ней
// значит «служба записала то, чего её собственная схема не допускает», и ответ
// `INVALID_ARGUMENT` обвинял бы вызывающего в ошибке, которую ему нечем
// исправить, а оператору не оставлял бы ни строки в журнале. Такой отказ
// отвечает фиксированным `INTERNAL` с записью о сработавшем рубеже; отказ по
// значению, которое прислал вызывающий, остаётся полосой ввода с текстом
// `checkText`.
//
// # Правило решения
//
// Проверка — полоса ВВОДА, если её предикат читает значение, которое прислал
// вызывающий (как есть, после обрезки пробелов либо арифметикой от присланного
// числа — срок от присланного ttl), и отказ может вызвать это значение, пока
// колонки службы держат то, что служба пишет на пути вызывающего. Иначе —
// полоса ДЕФЕКТА СЛУЖБЫ: значение чеканит, штампует, выводит, раскладывает,
// сериализует служба либо берёт его из своего закрытого словаря (в том числе
// переводом перечисления контракта в слово).
//
// Вызывающий — всякий, кто присылает значение запросом: арендатор, соседняя
// служба (регистрация ресурса, публикация чтения), модуль своим манифестом
// (`InternalModuleService.Apply`), поставщик личности своим вебхуком. Посадка
// вызывающим не считается: её величины судит страж старта, а не запрос.
//
// # Форма переписи
//
// Ключ — таблица так, как её называет сервер в отказе. Таблица без перечней
// (`nil`) пишется службой целиком: ВСЯКАЯ её проверка, в том числе заведённая
// позже миграцией, судит значение службы — ввода, который она могла бы судить,
// в такой таблице нет. У таблицы, куда попадает присланное, КАЖДАЯ проверка
// названа своей полосой: новая проверка такой таблицы решения не получает, пока
// его не примут, и проба переписи на живой схеме
// (`TestIntegration_CheckLedgerCoversTheLiveSchema`) называет её. Нерешённый
// отказ, как и отказ таблицы вне переписи, отвечает прежней полосой ввода.
//
// Решения, принятые раньше этой переписи, в ней сохранены, а не пересмотрены:
// форму имени и имени роли служба судит сама (#718, #1279, #1903) — эти
// проверки отводятся в полосу дефекта своими ветвями до общей; проекция
// «роль → тип × глагол» отдаёт отказ пустой пары вызывающему (`ReplaceRoleVerbs`,
// `TestIAMRV109_EmptyPairIsRefusedAndNothingIsWritten`); полосу дефекта
// таблицы клиентов называет перечень #317 (`interactiveClientProducedValueChecks`).
//
// # Чего здесь нет
//
// Таблица секрета способа входа по имени здесь не называется: её называет только
// её адаптер (гейт `internal/check` о материале способа входа), и решение о ней
// приходит предикатом `isLoginMethodsTable` — все её проверки судят значения
// службы.
//
// Отказ 23514, поднятый триггером БЕЗ клаузы `CONSTRAINT` (вид участника группы,
// вид субъекта выдачи, ярус потолка, адреса возврата клиента), имени не несёт и
// разбору по нему не поддаётся; каждый такой триггер судит присланное и отвечает
// полосой ввода общим текстом. Отказ триггера С клаузой
// (`role_rule_selectors_types_live`) в переписи есть — рядом со своей таблицей.

import (
	"maps"
	"slices"
)

// checkTableLanes — решение переписи о таблице, куда попадает присланное:
// каждая её проверка в одном из двух перечней.
type checkTableLanes struct {
	// caller — проверки, судящие значение, которое прислал вызывающий.
	caller []string
	// service — проверки, судящие значение, которое производит служба.
	service []string
}

// checkValueLanes — перепись проверок схемы. Основание — рядом с каждой
// таблицей.
var checkValueLanes = map[string]*checkTableLanes{
	// Выведенные строки материализации выдачи — служба раскладывает принятую
	// выдачу в кортежи.
	"access_binding_emitted_tuples": nil,
	// Множество субъектов выдачи: идентификатор и слово вида прислал вызывающий.
	"access_binding_subjects": {caller: []string{
		"access_binding_subjects_id_nonempty_ck",
		"access_binding_subjects_type_ck",
	}},
	// Члены цели выдачи — материализация по правилу и зеркалу, пишет служба.
	"access_binding_target_members": nil,
	// Выдача: субъект, роль, область, цель, срок и метки прислал вызывающий.
	// Выдавшего и отозвавшего называет служба по проверенному принципалу;
	// состояние, отзыв, ярус и форму отношения системной выдачи ставит служба —
	// на пути вызывающего отношение пусто, и его проверки молчат.
	"access_bindings": {
		caller: []string{
			"access_bindings_expires_future_ck",
			"access_bindings_grant_form_ck",
			"access_bindings_labels_valid",
			"access_bindings_resource_ck",
			"access_bindings_subject_ck",
			"access_bindings_target_resources_card_ck",
			"access_bindings_wildcard_subject_is_system_ck",
		},
		service: []string{
			"access_bindings_granted_by_check",
			"access_bindings_granted_relation_shape_ck",
			"access_bindings_relation_form_anchor_ck",
			"access_bindings_relation_form_is_system_ck",
			"access_bindings_revoked_by_check",
			"access_bindings_revoked_consistency_ck",
			"access_bindings_scope_ck",
			"access_bindings_status_ck",
		},
	},
	// Вызов ключа доступа — вызов, назначение и срок чеканит служба.
	"access_key_challenges": nil,
	// Проекция посадки, записанная при старте; её величины судит страж старта.
	"account_admission_rate_limits": nil,
	// Описание и метки прислал вызывающий; форму имени служба судит сама (#718).
	"accounts": {
		caller:  []string{"accounts_description_check", "accounts_labels_valid"},
		service: []string{"accounts_name_check"},
	},
	// Журнал аудита — событие пишет служба.
	"audit_outbox": nil,
	// Код авторизации: вызов PKCE, его способ и адрес возврата прислал клиент;
	// дайджест, сроки и погашение — служба.
	"authorization_codes": {
		caller: []string{
			"authorization_codes_challenge_form_ck",
			"authorization_codes_challenge_method_ck",
			"authorization_codes_redirect_uri_ck",
		},
		service: []string{
			"authorization_codes_deactivated_pair_ck",
			"authorization_codes_deactivated_reason_ck",
			"authorization_codes_digest_form_ck",
			"authorization_codes_expiry_after_issue_ck",
		},
	},
	// Каталог модуля: имя модуля — из манифеста; живость и снятие — служба.
	"catalog_module": {
		caller:  []string{"catalog_module_nonempty", "catalog_module_undotted"},
		service: []string{"catalog_module_live_matches_retired"},
	},
	// Каталог ресурса: модуль, ресурс и тип модели — из манифеста; точечное имя
	// склеивает служба, живость, снятие и преемника ставит служба.
	"catalog_resource": {
		caller: []string{
			"catalog_resource_module_undotted",
			"catalog_resource_nonempty",
			"catalog_resource_object_type_form",
			"catalog_resource_resource_undotted",
		},
		service: []string{
			"catalog_resource_dotted_form",
			"catalog_resource_live_matches_retired",
			"catalog_resource_successor_only_when_retired",
		},
	},
	// Каталог глагола: глагол — из манифеста; каноническую форму наводит служба
	// (`modulecatalog.canonicalVerb`), живость — служба.
	"catalog_verb": {
		caller:  []string{"catalog_verb_nonempty", "catalog_verb_undotted"},
		service: []string{"catalog_verb_canonical", "catalog_verb_live_matches_retired"},
	},
	// Повтор утверждения клиента: идентификаторы утверждения и клиента — из
	// утверждения, которое предъявил вызывающий.
	"client_assertion_replay": {caller: []string{
		"client_assertion_replay_assertion_ck",
		"client_assertion_replay_client_ck",
	}},
	// Выдача администратора кластера: идентификатор субъекта прислал
	// вызывающий; слово вида служба переводит из перечисления контракта,
	// идентификатор, выдавшего и срок ставит служба.
	"cluster_admin_grants": {
		caller: []string{"cluster_admin_grants_subject_id_check"},
		service: []string{
			"cluster_admin_grants_granted_by_check",
			"cluster_admin_grants_id_check",
			"cluster_admin_grants_subject_type_check",
			"cluster_admin_grants_until_check",
		},
	},
	// Корневой кластер заводится схемой; писателя у службы нет.
	"clusters": nil,
	// Доверенный издатель: издатель, субъект, ключ и его алгоритм прислал
	// вызывающий; срок — арифметикой от присланного ttl.
	"federated_trusted_issuers": {caller: []string{
		"federated_trusted_issuers_alg_ck",
		"federated_trusted_issuers_expires_future_ck",
		"federated_trusted_issuers_issuer_ck",
		"federated_trusted_issuers_key_not_blank",
		"federated_trusted_issuers_subject_ck",
	}},
	// Очередь кортежей модели прав — пишет служба.
	"fga_outbox": nil,
	// Участник группы: слово вида прислал вызывающий.
	"group_members": {caller: []string{"group_members_type_check"}},
	// Описание и метки прислал вызывающий; форму имени служба судит сама (#718).
	"groups": {
		caller:  []string{"groups_description_check", "groups_labels_valid"},
		service: []string{"groups_name_check"},
	},
	// Сессия человека: дайджест предъявителя, способы, уровень, сроки и причину
	// завершения пишет служба; причина — константа домена.
	"human_sessions": nil,
	// Окно допуска личностей — счётчик службы.
	"identity_admission_windows": nil,
	// Журнал личностей пишет триггер схемы.
	"identity_journal": nil,
	// Клиент: перечни адресов возврата прислал вызывающий; идентификатор,
	// состояние, способ и материал секрета — служба и производитель клиента
	// (перечень #317), форму имени служба судит сама (#718).
	interactiveClientsTable: {
		caller: []string{
			"interactive_clients_post_logout_uris_count_ck",
			"interactive_clients_redirect_uris_count_ck",
		},
		service: append(slices.Sorted(maps.Keys(interactiveClientProducedValueChecks)),
			"interactive_clients_name_check"),
	},
	// Очередь писем — событие и адресата пишет служба.
	"invite_mail_outbox": nil,
	// Окно писем: адресата приводит к канонической форме служба.
	"invite_mail_windows": nil,
	// Неудачный вход: ключ — присланный адрес (писатель сам отвечает на пустой
	// полосой ввода); область — словарь службы.
	"login_failures": {
		caller:  []string{"login_failures_key_check"},
		service: []string{"login_failures_scope_check"},
	},
	// Членство — идентификатор и состояние чеканит служба.
	"memberships": nil,
	// Отсечка выпущенных токенов: субъект и причину прислал вызывающий;
	// решившего называет служба по проверенному принципалу.
	"minted_token_revocations": {
		caller:  []string{"minted_token_revocations_reason_ck", "minted_token_revocations_subject_ck"},
		service: []string{"minted_token_revocations_decider_ck"},
	},
	// Операция — вид принципала ставит служба.
	"operations": nil,
	// Проекция посадки, записанная при старте; её величины судит страж старта.
	"own_ceilings": nil,
	// Учёт числа ресурсов ведут схема и служба.
	"project_resource_quotas": nil,
	// Описание и метки прислал вызывающий; форму имени служба судит сама (#718).
	"projects": {
		caller:  []string{"projects_description_check", "projects_labels_valid"},
		service: []string{"projects_name_check"},
	},
	// Очередь компенсаций поставщика — пишет служба.
	"provider_compensation_outbox": nil,
	// Публикация чтения: тип и идентификатор объекта прислал его владелец.
	"public_read_publication": {caller: []string{
		"public_read_publication_object_id_nonempty",
		"public_read_publication_object_type_model_dictionary",
	}},
	// Код восстановления — идентификатор, дайджест и сроки чеканит служба.
	"recovery_codes": nil,
	// Завершение восстановления: внешний субъект и идентификатор токена прислал
	// вебхук поставщика личности; человека и счёт сессий определяет служба.
	"recovery_completions": {
		caller:  []string{"recovery_completions_external_id_check", "recovery_completions_jti_check"},
		service: []string{"recovery_completions_count_check", "recovery_completions_user_id_check"},
	},
	// Токен обновления — дайджесты, сроки, поколение и ротацию ведёт служба.
	"refresh_tokens": nil,
	// Факт отношения выводит триггер схемы из очереди кортежей.
	"relation_fact": nil,
	// Журнал ресурсов — событие пишет служба.
	"resource_journal": nil,
	// Зеркало чужого ресурса: тип и идентификатор прислала служба-владелец;
	// метки служба сериализует в объект сама.
	"resource_mirror": {
		caller:  []string{"resource_mirror_id_nonempty", "resource_mirror_type_nonempty"},
		service: []string{"resource_mirror_labels_object"},
	},
	// Цепь предков: идентификаторы объекта и родителя прислал владелец; типы
	// переводит в словарь модели и глубину считает служба.
	"resource_parent_edge": {
		caller: []string{
			"resource_parent_edge_no_self",
			"resource_parent_edge_object_id_nonempty",
			"resource_parent_edge_parent_id_nonempty",
		},
		service: []string{
			"resource_parent_edge_depth_bounded",
			"resource_parent_edge_object_type_model_dictionary",
			"resource_parent_edge_object_type_nonempty",
			"resource_parent_edge_parent_type_model_dictionary",
			"resource_parent_edge_parent_type_nonempty",
		},
	},
	// Очередь сверки зеркала — пишет служба.
	"resource_reconcile_outbox": nil,
	// Сирота выдачи — следствие снятия, пишет служба.
	"role_grant_orphan": nil,
	// Ссылки правил роли: модуль, ресурс и глагол — из присланного правила;
	// живость — служба.
	"role_rule_ref": {
		caller: []string{
			"role_rule_ref_module_undotted",
			"role_rule_ref_nonempty",
			"role_rule_ref_resource_undotted",
			"role_rule_ref_verb_nonempty",
			"role_rule_ref_verb_undotted",
		},
		service: []string{"role_rule_ref_live_true"},
	},
	// Селекторы правил роли: метки, имена и типы — из присланного правила;
	// рукав, отпечаток, форму объекта меток и живость ставит служба. Живость
	// присланного типа судит триггер, поднимающий отказ по имени
	// `role_rule_selectors_types_live`: таблицы он сегодня не называет, но
	// назвавший её отказ обязан остаться вводом.
	"role_rule_selectors": {
		caller: []string{
			"role_rule_selectors_arm_shape",
			"role_rule_selectors_labels_valid",
			"role_rule_selectors_types_live",
			"role_rule_selectors_types_nonempty",
		},
		service: []string{
			"role_rule_selectors_arm_valid",
			"role_rule_selectors_fp_nonempty",
			"role_rule_selectors_labels_obj",
			"role_rule_selectors_live_true",
		},
	},
	// Сокращение селектора — следствие снятия каталога, пишет служба.
	"role_selector_prune": nil,
	// Проекция «роль → тип × глагол»: пара из присланных разрешений, отказ пустой
	// пары — ввод (`ReplaceRoleVerbs`); живость — служба.
	"role_verb": {
		caller: []string{
			"role_verb_type_nonempty",
			"role_verb_verb_canonical",
			"role_verb_verb_nonempty",
		},
		service: []string{"role_verb_live_true"},
	},
	// Роль: описание, метки, разрешения и правила прислал вызывающий, имя
	// модульной роли и её модуль — манифест; форму имени роли служба судит сама
	// (#1903). Якорь яруса, живость и системность роли, которой владеет модуль,
	// ставит служба.
	"roles": {
		caller: []string{
			"roles_description_check",
			"roles_labels_valid",
			"roles_owner_module_name_prefix",
			"roles_permissions_valid",
			"roles_rule_wildcards_confined",
			"roles_rules_valid",
		},
		service: []string{
			"roles_custom_name_check",
			"roles_definition_tier_xor",
			"roles_live_matches_retired",
			"roles_owner_module_is_cluster_tier",
			"roles_system_name_check",
		},
	},
	// Ключ сервисного аккаунта: описание, метки и объявленные аудитории прислал
	// вызывающий, срок — от присланного ttl. Вид, форму удостоверения, ключ и
	// его алгоритм, идентификаторы и перечень доверенных субъектов пишет служба.
	"service_account_oauth_clients": {
		caller: []string{
			"sa_oauth_clients_declared_audiences_wellformed",
			"service_account_oauth_clients_description_check",
			"service_account_oauth_clients_expires_future_ck",
			"service_account_oauth_clients_labels_valid",
		},
		service: []string{
			"service_account_oauth_clients_credential_kind_ck",
			"service_account_oauth_clients_credential_shape_ck",
			"service_account_oauth_clients_hydra_client_id_check",
			"service_account_oauth_clients_id_check",
			"service_account_oauth_clients_key_algorithm_check",
			"service_account_oauth_clients_trusted_subjects_array_ck",
		},
	},
	// Описание и метки прислал вызывающий; форму имени служба судит сама (#718).
	"service_accounts": {
		caller:  []string{"service_accounts_description_check", "service_accounts_labels_valid"},
		service: []string{"service_accounts_name_check"},
	},
	// Отзыв токена: идентификатор токена, причину и срок хранения прислал
	// вызывающий; отозвавшего называет служба.
	"session_revocations": {
		caller: []string{
			"session_revocations_reason_check",
			"session_revocations_token_jti_check",
			"session_revocations_ttl_future_ck",
		},
		service: []string{"session_revocations_revoked_by_check"},
	},
	// Очередь изменений субъекта — пишет служба.
	"subject_change_outbox": nil,
	// Семейство токенов: идентификатор, живость, отзыв и выданную область решает
	// церемония службы.
	"token_families": nil,
	// Ключ подписи порождает и ведёт служба.
	"token_signing_keys": nil,
	// Ключ доступа: описание и материал удостоверения (идентификатор, ключ,
	// алгоритм, счётчик) — из ответа аутентификатора, который прислал
	// вызывающий. Идентификатор и дескриптор человека чеканит служба, форму
	// имени служба судит сама (#718).
	"user_access_keys": {
		caller: []string{
			"user_access_keys_algorithm_check",
			"user_access_keys_credential_id_check",
			"user_access_keys_description_check",
			"user_access_keys_public_key_check",
			"user_access_keys_sign_count_check",
		},
		service: []string{
			"user_access_keys_id_form_check",
			"user_access_keys_name_check",
			"user_access_keys_user_handle_check",
		},
	},
	// Токен человека: описание и метки прислал вызывающий, срок — от присланного
	// ttl. Вид, форму удостоверения, ключ и идентификаторы пишет служба.
	"user_oauth_clients": {
		caller: []string{
			"user_oauth_clients_description_check",
			"user_oauth_clients_expires_future_ck",
			"user_oauth_clients_labels_valid",
		},
		service: []string{
			"user_oauth_clients_credential_kind_ck",
			"user_oauth_clients_credential_shape_ck",
			"user_oauth_clients_hydra_client_id_check",
			"user_oauth_clients_id_check",
			"user_oauth_clients_key_algorithm_check",
		},
	},
	// Отсечка токенов человека: причину прислал вызывающий; отозвавшего
	// называет служба по проверенному принципалу.
	"user_token_revocations": {
		caller:  []string{"user_token_revocations_reason_check"},
		service: []string{"user_token_revocations_revoked_by_check"},
	},
	// Человек: адрес, отображаемое имя, метки и внешний субъект прислал
	// вызывающий (арендатор или вебхук поставщика личности). Состояние
	// приглашения ставит служба, но его согласие с внешним субъектом нарушает
	// присланный пустой субъект — и эта проверка остаётся полосой ввода.
	"users": {
		caller: []string{
			"users_display_name_check",
			"users_email_check",
			"users_external_id_check",
			"users_invite_status_consistency",
			"users_labels_valid",
		},
		service: []string{"users_invite_status_check"},
	},
}

// checkValueLane — полоса проверки по переписи.
type checkValueLane int

const (
	// checkLaneUndecided — перепись о проверке не говорит ничего: отказ без
	// имени ограничения (триггер, судящий присланное), таблица вне переписи
	// либо проверка, которой в перечнях таблицы нет.
	checkLaneUndecided checkValueLane = iota
	// checkLaneCaller — значение прислал вызывающий.
	checkLaneCaller
	// checkLaneService — значение производит служба.
	checkLaneService
)

// checkValueLaneOf — полоса проверки `constraint` таблицы `table` по переписи.
func checkValueLaneOf(table, constraint string) checkValueLane {
	if constraint == "" {
		return checkLaneUndecided
	}
	if isLoginMethodsTable(table) {
		return checkLaneService
	}
	lanes, declared := checkValueLanes[table]
	switch {
	case !declared:
		return checkLaneUndecided
	case lanes == nil:
		return checkLaneService
	case slices.Contains(lanes.caller, constraint):
		return checkLaneCaller
	case slices.Contains(lanes.service, constraint):
		return checkLaneService
	}
	return checkLaneUndecided
}
