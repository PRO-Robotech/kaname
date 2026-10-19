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
	// ── запись проекции ────────────────────────────────────────────────────
	"internal/apps/kaname/api/access_binding/create.go::CreateAccessBindingUseCase.Execute": {
		Go: 4, Class: BindingPairProjection,
		Why: "нормализация набора: пара прежней формы запроса — вход NormalizeSubjects, затем пара " +
			"записывается проекцией subjects[0] (строка выдачи и якорь уникальности)",
	},
	"internal/repo/kaname/pg/access_binding_repo.go::abWriter.Insert": {
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
	// ── прежняя форма запроса ──────────────────────────────────────────────
	"internal/apps/kaname/api/access_binding/handler.go::Handler.Create": {
		Go: 2, Class: BindingPairLegacyInput,
		Why: "пара прежней формы запроса (subject_type/subject_id) переносится в выдачу как вход " +
			"нормализации; набор того же запроса — поле subjects",
	},
	// ── якорь уникальности ─────────────────────────────────────────────────
	"internal/repo/kaname/pg/module_seed_writer.go::moduleSeedWriter.grant": {
		SQL: 4, Class: BindingPairUniqueAnchor,
		Why: "системная выдача пишет строку с проекцией и проверяет её естественный ключ по паре — тот же, " +
			"что стерегут частичные UNIQUE (access_bindings_active_grant_uniq / _active_relation_grant_uniq); " +
			"набор из одного субъекта пишется следом",
	},
	// ── откат к прежней форме: Go ──────────────────────────────────────────
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
