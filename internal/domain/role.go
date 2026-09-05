// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// Role — multi-scope. Exactly one scope field is non-NULL:
//   - is_system=true + ClusterID set: system role (`kacho-system.admin`, ...).
//   - is_system=false + AccountID set: account-scoped custom role.
//   - is_system=false + ProjectID set: project-scoped custom role.
//
// Enforced by DB CHECK `roles_definition_tier_xor` + a partial UNIQUE per scope.
// Domain.Validate duplicates the CHECK to give friendly errors before
// reaching the DB. (The legacy B2B-tenant role scope was removed; a custom
// role is scoped to exactly one of {account, project}.)
type Role struct {
	ID          RoleID
	ClusterID   ClusterID // set for system role
	AccountID   AccountID // set for account-scoped custom
	ProjectID   ProjectID // set for project-scoped custom
	Name        RoleName
	Description Description
	// Rules — authored policy (RBAC rules-model 2026). Source of truth + public
	// API surface. Compiled into Permissions (internal, FGA-emit) by CompileRules.
	Rules Rules
	// Permissions — INTERNAL compiled form (anchor/names arms; match_labels NOT
	// compiled). Derived from Rules via CompileRules; NOT a public API field for
	// rules-roles. Legacy permissions-only roles (no Rules) keep their stored set.
	Permissions Permissions
	IsSystem    bool
	// OwnerModule — модуль, которому роль принадлежит. Пусто у ПЛАТФОРМЕННОЙ
	// роли (admin/edit/view/owner, kacho-system.*), непусто у роли, объявленной
	// манифестом этого модуля.
	//
	// Носит ровно ОДИН смысл — владение, — и потому отделяет послабление
	// подстановки от кластерного якоря: `IsSystem` продолжает означать «арендатор
	// эту роль не правит» и больше не означает «этой роли можно подставлять
	// звёздочку». Политика выводится из пары ОДНИМ местом — [PolicyOfRole].
	//
	// Наружу не проецируется: `Role` публичного контракта этой колонки не несёт
	// (задача продукта #1032, тип изменения — ВВОДЯЩЕЕ, без нового поля API).
	OwnerModule string
	CreatedAt   time.Time
	// CreatedByUserID — authoring principal (governance/audit). Optional.
	CreatedByUserID UserID
	// UpdatedAt — last-mutation timestamp. Zero until first Update.
	UpdatedAt time.Time
	// Labels — tenant-facing метки САМОГО ресурса Role (НЕ путать с
	// Rule.MatchLabels, отбирающим объекты под грантом). Делают Role
	// label-selectable наравне с account/project (ARM_LABELS-грант на iam.role →
	// v_list по `labels @> matchLabels`; List фильтрует viewer ∪ v_list).
	Labels Labels
	// Integrity — целость роли: даёт ли она то, что объявляет (#1035).
	//
	// ВЫВОДИТСЯ НА ЧТЕНИИ и НЕ ХРАНИТСЯ: колонки у неё нет, в перечень колонок
	// писателя она не входит и [Role.Validate] её не судит. Нулевое значение
	// означает «этим путём не вычислено» — так её и видят пути, которые роль не
	// читают, а возвращают эхом мутации.
	Integrity RoleIntegrity

	// Lifecycle — ОБЪЯВЛЕНА роль манифестом модуля сегодня либо СНЯТА (#1913).
	//
	// Отдельно от `Integrity` рядом, и различие несущее: `RoleHealthEmpty` даёт
	// и снятая роль, и объявленная, чьи строки каталога сняты, — а следующий шаг
	// у арендатора разный. Довод целиком — [RoleLifecycle].
	//
	// ПРИХОДИТ ЧТЕНИЕМ: колонки пометки у строки есть, но заполняют это поле
	// `Get` и `List`, а ответ операции его не несёт — нулевое состояние там
	// означает «этим ответом не вычислено», ровно как у соседа.
	Lifecycle RoleLifecycle

	// Withdrawn — ЧТО у роли отобрано и почему (#1992): строки ведомости
	// переселения. ОБЪЯСНЯЕТ состояние целости и не определяет его — у роли,
	// пострадавшей третьим путём, переселения не было вовсе, и список пуст при
	// нездоровом состоянии.
	//
	// Пустой срез означает «отобранного нет», а не «не читали»: разводит их
	// [RoleIntegrity.Health] рядом, у которого нулевое состояние есть «этим
	// ответом не вычислено».
	Withdrawn []WithdrawnGrant

	// PrunedSelectorTypes — какие точечные типы ВЫРЕЗАНЫ из отбора правил этой
	// роли и почему (#1988): строки ведомости вырезания.
	//
	// Сосед [Role.Withdrawn] отвечает про ДВЕ проекции правила, у которых есть
	// пара «тип + глагол»; эта — про ТРЕТЬЮ, где глагола нет вовсе. Разные
	// ведомости, разные события, поэтому два поля, а не одно.
	//
	// Пустой срез означает «вырезанного нет», а не «не читали»: разводит их
	// [RoleIntegrity.Health] рядом, у которого нулевое состояние есть «этим
	// ответом не вычислено».
	PrunedSelectorTypes []PrunedSelectorType

	// RuleStates — состояние КАЖДОГО правила роли (#1962): действует, отозвано
	// платформой либо не разрешилось. Записей ровно по числу правил.
	//
	// Отвечает на вопрос, которого нет ни у `Integrity`, ни у `Withdrawn`: КАКОЕ
	// правило пострадало и по КАКОЙ ИЗ ДВУХ причин. Картина счётчиков у причин
	// ОДИНАКОВА, а следующий шаг арендатора — разный.
	//
	// ПРИХОДИТ ЧТЕНИЕМ, НЕ ХРАНИТСЯ — тем же доводом, что `Integrity` рядом.
	// ПУСТОЙ СРЕЗ означает «этим путём не вычислено» и законен: ответ операции
	// состояния не несёт. У роли БЕЗ правил он пуст и на чтении — состояние есть
	// свойство правила, и у роли без правил его нет.
	RuleStates []RuleState

	// TypeVerbs — набор глаголов ТИПА, каким его объявляет ЖИВАЯ строка каталога
	// (#1994). Тем же набором идёт материализация, поэтому превью и эмиссия не
	// могут разойтись.
	//
	// ПРИХОДИТ ПРОВЯЗКОЙ, НЕ ХРАНИТСЯ — как и `Integrity` рядом: колонки у неё
	// нет, писатель её не пишет, [Role.Validate] её не судит. Отличие от
	// `Integrity` в том, чем является НУЛЕВОЕ значение: там оно означает «этим
	// путём не вычислено» и законно, здесь — ОТКАЗ проекции. Показ по словарю,
	// порождённому сборкой, неотличим от честного превью, поэтому «нечем
	// ответить» обязано быть отказом, а не тихим запасным путём.
	TypeVerbs TypeVerbLookup
}

// Validate — multi-scope XOR formula + rules/permissions.
//
// A role is valid when EITHER it carries authored Rules (the rules-model 2026
// authority) OR a legacy compiled Permissions set (back-compat read of
// pre-rules roles).
//
// When Rules is set (a rules-role) it is validated through Rules.Validate with
// the policy derived from the row ([PolicyOfRole] of IsSystem + OwnerModule) and
// the compiled Permissions projection is validated
// for the 4-seg grammar + cap ONLY — NOT the ≥1 lower bound (ValidateCompiled): a
// label-only role (all rules ARM_LABELS) compiles to an EMPTY permission set by
// design and must be accepted. The ≥1 floor is retained for the LEGACY
// permissions-only path (no Rules) so a degenerate legacy role with an
// empty set cannot exist.
// `modules` — набор модулей платформы, каким его знает вызывающий: правило роли
// называет модуль, а домен закрытого набора не объявляет (module_set.go).
func (r Role) Validate(modules ModuleSet) error {
	var errs error
	// Имя судится ПО ЯРУСУ: ограничений в таблице два, и каждое условлено
	// вычисляемым `is_system`. Ярус берётся оттуда же, откуда его берёт база, —
	// из непустого `cluster_id` (`IsSystemDerived`), а не из поля `IsSystem`:
	// поле — проекция чтения, а решение о форме принимается до записи.
	errs = multierr.Append(errs, r.Name.ValidateAtTier(r.IsSystemDerived()))
	errs = multierr.Append(errs, r.Description.Validate())
	errs = multierr.Append(errs, r.Labels.Validate())
	if len(r.Rules) > 0 {
		errs = multierr.Append(errs, r.Rules.Validate(PolicyOfRole(r.IsSystem, r.OwnerModule), modules))
		// Rules-role: the compiled set may legitimately be empty (label-only).
		errs = multierr.Append(errs, r.Permissions.ValidateCompiled())
	} else {
		// Legacy permissions-only role: must carry ≥1 permission.
		errs = multierr.Append(errs, r.Permissions.Validate())
	}

	clusterSet := r.ClusterID != ""
	accountSet := r.AccountID != ""
	projectSet := r.ProjectID != ""

	if r.IsSystem {
		// system: cluster_id only; the rest empty.
		if !clusterSet || accountSet || projectSet {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: system role must have only cluster_id set"))
		}
	} else {
		// custom: cluster_id IS NULL, and exactly one of {account, project}.
		if clusterSet {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: custom role must not have cluster_id"))
		}
		set := 0
		if accountSet {
			set++
		}
		if projectSet {
			set++
		}
		if set != 1 {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument: custom role must have exactly one of (account_id, project_id) set"))
		}
	}
	return errs
}
