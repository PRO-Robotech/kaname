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

	// SystemAdminRoleID — the hand-rolled deterministic id of the second `*.*.*`
	// superuser system role (`kacho-system.admin`), seeded by migration 0001 and
	// re-seeded with `*.*.*` rules by migration 0031. Also a legitimate
	// cluster-admin superuser.
	SystemAdminRoleID = "rol000000000sysadmin"

	// SystemViewerRoleID — рукописный детерминированный id второй системной роли
	// пола каталога (`kacho-system.viewer`), посеянной миграцией 0001.
	//
	// ДЛИНА ЕГО — 21, а не 20, и это ФАКТ ПРИМЕНЁННОЙ МИГРАЦИИ, а не описка,
	// которую можно поправить: id неизменяем на всю жизнь ресурса (ban #15,
	// «операции смены id НЕ существует»), а применённую миграцию править нельзя
	// (ban #5). Переименование поздней миграцией сверх того есть перенос выдачи с
	// одной роли на другую — тихое расширение прав, отвергаемое гейтом
	// `TestNoMigrationMovesGrantsBetweenRoles`.
	//
	// Поэтому литерал назван здесь и стоит в закрытом перечне
	// `SeededResourceIDs()`: проверка формы принимает то, что продукт сам посеял,
	// а не объявляет собственный посев негодным. Задача #1808.
	SystemViewerRoleID = "rol000000000sysviewer"
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
