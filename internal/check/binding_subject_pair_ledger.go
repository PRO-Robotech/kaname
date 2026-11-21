// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// binding_subject_pair_ledger.go — ЗАКРЫТЫЙ перечень мест, законно
// обращающихся к одиночной паре субъекта выдачи (kaname#917; гейт —
// binding_subject_pair.go). Ключ — «файл::место», числа — ТОЧНЫЕ.
//
// Новое место сюда вносится только с основанием из словаря BindingPairClasses
// и словами в теле PR; по умолчанию новое место переводится на весь набор.
// Место класса «откат к прежней форме» обязано читать и набор: гейт требует
// значения типа Subject/[]Subject либо таблицы access_binding_subjects в том же
// месте — ветвь пары без ветви набора и есть дефект kaname#880/#888.

// bindingPairFallbackSQL — основание SQL-ветви пары рядом с ветвью набора.
const bindingPairFallbackSQL = "условие называет субъекта ОБЕИМИ формами: ветвь пары (её ведёт индекс " +
	"access_bindings_subject_idx) и ветвь набора access_binding_subjects; пара — член набора, " +
	"объединение не сужает ответ"

// bindingPairFallbackGo — основание Go-отката к паре при пустом наборе.
const bindingPairFallbackGo = "пустой набор — выдача, записанная до дочерней таблицы субъектов, либо строка, " +
	"прочитанная без загрузки набора: её единственный субъект — пара; при непустом наборе читается набор"

// BindingSubjectPairLedger — законные места и точные числа доступов.
var BindingSubjectPairLedger = map[string]BindingPairEntry{
	// ── новые closed structural proofs: само имя в ledger не даёт разрешения ──
	"internal/repo/kaname/pg/invite_preparation.go::inviteBinding": {
		Go: 2, Class: BindingPairSingleton,
		Why: "оба поля проекции и единственный Subjects member берутся из одного typed Subject в том же AccessBinding literal",
	},
	"internal/repo/kaname/pg/grant_delegation_revoke_stage.go::grantDelegationRevokeTx.WithdrawGrantDelegation": {
		Go: 2, Class: BindingPairGuardedFanout,
		Why: "b.Subjects сохраняется целиком; fallback пары только при len==0; оба события обходят каждый member без фильтра или среза",
	},
	"internal/repo/kaname/pg/role_mutation_stage.go::roleMutationStage.stageBinding": {
		Go: 2, Class: BindingPairStagedSet,
		Why: "query читает весь набор того же binding ID до MaxSubjects+1; overflow и row errors не дают усечения; NormalizeSubjects и BuildRoleTuples используют весь результат",
	},
	"internal/repo/kaname/pg/group_native_questions.go::var groupNativeCarrierQueries": {
		SQL: 2, Class: BindingPairCompleteSetSQL,
		Why: "проверены обе correlated SQL фазы, единственный полный range массива и весь paging consumer; одна primary фаза отдельно proof не получает",
	},
	"internal/repo/kaname/pg/policy_partition_plan.go::const policyActorSources": {
		SQL: 4, Class: BindingPairCompleteSetSQL,
		Why: "primary speaker/wildcard OR correlated child subject predicate с тем же binding и speaker array; весь query и complete paging consumer имеют closed proof",
	},
	"internal/repo/kaname/pg/policy_partition_plan.go::const policyMutationCarriers": {
		SQL: 5, Class: BindingPairCompleteSetSQL,
		Why: "выбор по primary OR child group и UNION всех child guards для тех же carriers; полнота statement и paging проверяется до разрешения пары",
	},
	"internal/repo/kaname/pg/policy_partition_plan.go::const policyOldBindingSubjects": {
		SQL: 7, Class: BindingPairCompleteSetSQL,
		Why: "UNION ALL primary и полного child set одного binding $3; conservative unqualified census тоже покрыт whole-program proof",
	},
	// ── запись проекции ────────────────────────────────────────────────────
	"internal/repo/kaname/pg/registration_account_writer.go::RegistrationAccountWriterStore.ApplyRegistrationAccountWriters": {
		Go: 2, Class: BindingPairProjection,
		Why: "установщик пишет проекцию единственного субъекта назначенного модуля и тот же полный набор через InsertSubjects",
	},
	"internal/apps/kaname/api/access_binding/create.go::CreateAccessBindingUseCase.Execute": {
		Go: 4, Class: BindingPairProjection,
		Why: "нормализация набора: пара прежней формы запроса — вход NormalizeSubjects, затем пара " +
			"записывается проекцией subjects[0] (строка выдачи и якорь уникальности)",
	},
	"internal/repo/kaname/pg/access_binding_repo.go::abWriter.insertAt": {
		Go: 3, SQL: 2, Class: BindingPairProjection,
		Why: "строка access_bindings несёт проекцию subjects[0]; подсказка отказа уникальности называет пару, " +
			"на которой стоит access_bindings_active_grant_uniq",
	},
	"internal/repo/kaname/pg/access_binding_repo.go::const abCols": {
		SQL: 2, Class: BindingPairProjection,
		Why: "перечень колонок строки выдачи: пара переносится в поле проекции (scanABWithVersion)",
	},
	"internal/repo/kaname/pg/access_binding_repo.go::scanABWithVersion": {
		Go: 2, Class: BindingPairProjection,
		Why: "перенос колонок пары строки в поле проекции; набор загружается отдельно (ListSubjects*)",
	},
	"internal/repo/kaname/pg/binding_decision.go::prepareBindingSequenceProgram": {
		Go: 4, Class: BindingPairProjection,
		Why: "полный b.Subjects вместе с парой нормализуется; каждый normalized subject сериализуется в subjects без фильтра, а пара отдельно переносится в поля заголовка подготовленной create-программы",
	},
	"internal/repo/kaname/pg/resource_withdrawal_snapshot.go::resourceCapturedBinding": {
		Go: 2, Class: BindingPairProjection,
		Why: "декодер захваченного header переносит поля проекции; snapshot и captureBindings отдельно требуют захваченный полный набор того же binding ID до разворачивания выдачи",
	},
	// ── прежняя форма запроса ──────────────────────────────────────────────
	"internal/apps/kaname/api/access_binding/handler.go::Handler.Create": {
		Go: 2, Class: BindingPairLegacyInput,
		Why: "пара прежней формы запроса (subject_type/subject_id) переносится в выдачу как вход " +
			"нормализации; набор того же запроса — поле subjects",
	},
	// ── якорь уникальности ─────────────────────────────────────────────────
	"internal/repo/kaname/pg/registration_account_writer.go::registrationWriterOwnsGrant": {
		Go: 2, Class: BindingPairUniqueAnchor,
		Why: "при отзыве установщик сверяет естественный ключ прямой выдачи (access_bindings_active_relation_grant_uniq) с координатами своего журнала; полный набор обязан содержать ровно ту же служебную учётку",
	},
	"internal/repo/kaname/pg/resource_installation_sources.go::const resourceInstallationWitnessSQL": {
		SQL: 4, Class: BindingPairUniqueAnchor,
		Why: "свидетельство собственного назначения требует ровно одного child subject той же service_account и того же account вместе с совпадающей парой системной fga_writer выдачи; LIMIT 33 и флаг unsupported отклоняют переполнение, а не принимают усечённый набор",
	},
	"internal/repo/kaname/pg/module_seed_writer.go::moduleSeedWriter.grant": {
		SQL: 4, Class: BindingPairUniqueAnchor,
		Why: "системная выдача пишет строку с проекцией и проверяет её естественный ключ по паре — тот же, " +
			"что стерегут частичные UNIQUE (access_bindings_active_grant_uniq / _active_relation_grant_uniq); " +
			"набор из одного субъекта пишется следом",
	},
	// ── каноническая нормализация: типизированное доказательство вызова ─────
	"internal/repo/kaname/pg/binding_decision.go::GrantPolicyWriters.bindingDecisionOnce": {
		Go: 2, Class: BindingPairCanonicalFallback,
		Why: "полный Subjects прочитан для существующей выдачи либо передан предложением Create; пара служит только входом канонической нормализации того же binding",
	},
	"internal/repo/kaname/pg/binding_withdrawal_stage.go::BindingStageParticipant.stageWithdrawal": {
		Go: 2, Class: BindingPairCanonicalFallback,
		Why: "ListSubjects загружает полный набор; NormalizeSubjects сохраняет набор перед сериализацией заголовка staged withdrawal",
	},
	"internal/repo/kaname/pg/grant_mutation_preflight.go::bindingDecisionPreflight": {
		Go: 2, Class: BindingPairCanonicalFallback,
		Why: "NormalizeSubjects получает полный набор предложения; canonical primary не меняется, сортируется только копия полного результата для блокировок",
	},
	// ── откат к прежней форме: Go ──────────────────────────────────────────
	"internal/domain/access_binding.go::AccessBinding.Validate": {
		Go: 4, Class: BindingPairFallback,
		Why: "проверка самой проекции (тип пары из словаря, пара непуста) и запрет подстановочного субъекта " +
			"несистемной выдаче — по паре И по каждому члену набора (до kaname#917 — только по паре)",
	},
	"internal/apps/kaname/api/access_binding/helpers.go::callerIsSubjectOf": {
		Go: 1, Class: BindingPairFallback, Why: bindingPairFallbackGo,
	},
	"internal/apps/kaname/api/access_binding/list.go::groupSubjectsOf": {
		Go: 2, Class: BindingPairFallback, Why: bindingPairFallbackGo,
	},
	"internal/apps/kaname/api/access_binding/revoke_subject_fanout.go::bindingSubjectsOf": {
		Go: 2, Class: BindingPairFallback, Why: bindingPairFallbackGo,
	},
	"internal/apps/kaname/api/access_binding/role_tuple_reconciler.go::RoleTupleReconciler.ReconcileRoleTuples": {
		Go: 2, Class: BindingPairFallback, Why: bindingPairFallbackGo,
	},
	"internal/repo/kaname/pg/reconcile_adapter.go::bindingSubjects": {
		Go: 2, Class: BindingPairFallback, Why: bindingPairFallbackGo,
	},
	"internal/repo/kaname/pg/resource_object_binding.go::resourceCapturedSubjects": {
		Go: 2, Class: BindingPairFallback,
		Why: "все captured rows декодируются, проверяются на binding ID, ordinal и дубликаты и целиком передаются NormalizeSubjects; пара используется только при пустом результате захвата",
	},
	// ── откат к прежней форме: SQL ─────────────────────────────────────────
	"internal/repo/kaname/pg/access_binding_repo.go::abReader.ListSubjectPrivileges": {
		SQL: 5, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/access_binding_repo.go::bindingHasSubjectTypeInAccount": {
		SQL: 1, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/access_binding_repo.go::bindingNamesSubject": {
		SQL: 2, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/access_binding_repo.go::bindingNamesSubjectID": {
		SQL: 2, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/access_binding_repo.go::const membershipHoldingBindingsPredicate": {
		SQL: 2, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/deletion_hold.go::var holdShapes": {
		SQL: 2, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/group_repo.go::groupWriter.Delete": {
		SQL: 4, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/service_account_repo.go::saWriter.Delete": {
		SQL: 4, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/user_repo.go::userReader.ListAccountsForUser": {
		SQL: 2, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
	"internal/repo/kaname/pg/user_repo.go::userWriter.Delete": {
		SQL: 4, Class: BindingPairFallback, Why: bindingPairFallbackSQL,
	},
}

// BindingPairOutsideBuildLedger — непроверочные файлы радиуса, которых нет в
// прод-сборке, с основанием. Пусто — каждый такой файл находка.
var BindingPairOutsideBuildLedger = map[string]string{}
