// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// constants_extended.go — id-префиксы и константы.
// Стиль формата отличается от corelib `ids.NewID` (3-char prefix +
// 17-char crockford-base32) — здесь используется `<prefix>_<17-char crockford>`
// с `_` separator, чтобы префиксы могли быть длиннее 3 символов
// (`cag`, `org`, `cond`, `evt`, `soc`).
//
// DB CHECK constraints в миграциях 0011..0014 enforce'ат соответствие
// формату per-таблица (например `^cag_[0-9a-hjkmnp-tv-z]{17}$`).
package domain

// id-префиксы. Singleton (`cluster_root`) — литерал, не генерируется.
// Outbox events (`evt_`) — ULID-based, длина 20..30.
const (
	PrefixClusterAdminGrant = "cag"
	PrefixCondition         = "cond"
	PrefixSAOAuthClient     = "soc"
	PrefixUserOAuthClient   = "uoc"
	PrefixAuditEvent        = "evt"

	// ClusterSingletonID — единственный валидный id для кластера.
	ClusterSingletonID = "cluster_root"

	// OwnerRoleID — deterministic id of the net-new `owner` system-role
	// (RBAC explicit-model 2026), seeded by migration 0035 as
	// `'rol' || substr(md5('owner'),1,17)`. The Account.Create auto-binding
	// references it. Kept here so the use-case does not re-hash the name at
	// runtime (and stays in lockstep with the migration seed id).
	OwnerRoleID = "rol72122ce96bfec66e2"

	// ClusterAdminRoleID — deterministic id of the system cluster-admin role
	// (`admin`, name 'admin'), seeded by migration 0001 as
	// `'rol' || substr(md5('admin'),1,17)` and re-seeded with its `*.*.*` rules by
	// migration 0031. This is the canonical "GLOBAL super-admin" role.
	//
	// IMPORTANT: the `owner` role (OwnerRoleID) carries the SAME `*.*.*`
	// wildcard SHAPE as cluster-admin, so the GLOBAL+all exception MUST be
	// keyed on this PINNED id (+ is_system), not on the shape alone — otherwise
	// owner would be misclassified as cluster-admin and slip past the reject.
	ClusterAdminRoleID = "rol21232f297a57a5a74"

	// SystemAdminRoleID — id второй суперпользовательской системной роли
	// (`system.admin`; свод посеял её под именем `kacho-system.admin`, перевод
	// имени — миграция 20260913143007, kacho#2554). Тоже законный суперпользователь
	// кластера: исключение «кластер + все объекты» узнаёт его по этому
	// закреплённому id (`IsClusterAdminRole`).
	//
	// Значение — каноническая форма `rol` + 17 знаков алфавита фундамента,
	// полученная однократно генератором и замороженная. Свод посеял роль
	// рукописным id с буквой вне алфавита; миграция 20261029150000 перевела строку
	// роли и каждую ссылку на неё на это значение одной транзакцией (kaname#543,
	// приёмка system-roles-carry-canonical-ids.md). Перевод id ОДНОЙ роли —
	// однократный акт миграции над посевом самого продукта, а не глагол: операции
	// смены id в API нет (ban #15). Константа и миграция — два написания одного
	// значения; их равенство держит проба SRCI-01 (id роли по имени после всей
	// цепочки равен константе).
	SystemAdminRoleID = "rol58ksy03r9xd053my3"

	// SystemViewerRoleID — id второй системной роли пола каталога
	// (`system.viewer`; свод посеял её под именем `kacho-system.viewer`, перевод
	// имени — миграция 20260913143007, kacho#2554).
	//
	// Значение — каноническая форма, как у SystemAdminRoleID. Свод посеял роль id
	// длиной 21, и до kaname#543 проверка формы держала его закрытым перечнем
	// «посеянного вопреки длине»; миграция 20261029150000 перевела роль на это
	// значение, и перечень снят вместе с ветвью проверки формы, которая его
	// читала. Прежний id после перевода не адресует ничего.
	SystemViewerRoleID = "rol6ht762gm6sj2cdvan"
)

// OwnerRoleRules is the canonical authored policy of the `owner` system-role:
// `[{module:"*", resources:["*"], verbs:["*"]}]` (the `*.*.*` "selector all" shape).
// It MUST stay byte-for-byte semantically in lockstep with the migration 0035
// seed (`rules` JSONB column). Exposed so the seed layer can derive the owner role's
// materializing selectors (role_rule_selectors) for the forward fast-path WITHOUT
// re-encoding the wildcard-expansion type set in SQL.
func OwnerRoleRules() Rules {
	return Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}
}

// Condition expressions whitelist (migration 0012
// access_binding_conditions_expression_whitelist_ck).
const (
	ConditionMFAFresh        = "mfa_fresh"
	ConditionNonExpired      = "non_expired"
	ConditionSourceIPInRange = "source_ip_in_range"
	ConditionBusinessHours   = "business_hours"
	ConditionDeviceCompliant = "device_compliant"
)
