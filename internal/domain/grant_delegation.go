// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// grant_delegation.go — делегирование права выдавать (задача PRO-Robotech/kaname#986,
// приёмка docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md).
//
// Делегирование — запись, которую заводит держатель права выдавать на аккаунте и
// которая допускает служебную учётку (делегата) выдавать роли ОДНОГО модуля на
// объекты этого модуля в этом аккаунте. Четыре оси (роли, типы цели, типы
// субъекта, аккаунт) неизменяемы; отзыв переводит запись в REVOKED, и строка
// остаётся для аудита.

import (
	"slices"
	"strings"
	"time"
)

// PrefixGrantDelegation — префикс идентификатора делегирования (`gdl` + 17 знаков
// crockford-base32, `ids.NewID`).
const PrefixGrantDelegation = "gdl"

// Пределы осей делегирования — границы размера запроса (Р6 приёмки), а не предел
// числа ресурсов: число делегирований kaname не ограничивает (Р-В7).
const (
	MaxGrantDelegationRoles        = 16
	MaxGrantDelegationTargetTypes  = 16
	MaxGrantDelegationSubjectTypes = 4
)

// GrantDelegationID — идентификатор делегирования.
type GrantDelegationID string

// GrantDelegationStatus — состояние делегирования; слово хранения.
type GrantDelegationStatus string

const (
	// GrantDelegationActive — делегирование действует.
	GrantDelegationActive GrantDelegationStatus = "ACTIVE"
	// GrantDelegationRevoked — отозвано; конечное состояние.
	GrantDelegationRevoked GrantDelegationStatus = "REVOKED"
)

// GrantDelegationActor — принципал шага жизненного цикла: вид ("user" |
// "service_account") и идентификатор.
type GrantDelegationActor struct {
	Type string
	ID   string
}

// GrantDelegation — делегирование права выдавать.
type GrantDelegation struct {
	ID        GrantDelegationID
	AccountID AccountID
	// DelegateID — служебная учётка-делегат. Тип делегата один
	// (`SubjectTypeServiceAccount`), поэтому хранится только идентификатор.
	DelegateID   ServiceAccountID
	RoleIDs      []RoleID
	TargetTypes  []string
	SubjectTypes []SubjectType
	// Module — модуль ролей и типов делегирования; выводится, на вход не
	// принимается.
	Module      string
	Status      GrantDelegationStatus
	DelegatedBy GrantDelegationActor
	CreatedAt   time.Time
	RevokedAt   *time.Time
	RevokedBy   *GrantDelegationActor
}

// Active — делегирование действует.
func (d GrantDelegation) Active() bool { return d.Status == GrantDelegationActive }

// AllowsRole — роль входит в набор ролей делегирования.
func (d GrantDelegation) AllowsRole(id RoleID) bool { return slices.Contains(d.RoleIDs, id) }

// AllowsTargetType — тип объекта цели входит в набор типов делегирования.
func (d GrantDelegation) AllowsTargetType(dotted string) bool {
	return slices.Contains(d.TargetTypes, dotted)
}

// AllowsSubjectType — тип субъекта выдачи входит в набор типов делегирования.
func (d GrantDelegation) AllowsSubjectType(t SubjectType) bool {
	return slices.Contains(d.SubjectTypes, t)
}

// IsDelegate — принципал (вид, идентификатор) — делегат этого делегирования.
//
// Сравнивается ПАРА, а не голый идентификатор: вид принципала нормализуется
// одной функцией (`SubjectTypeOfPrincipal`), поэтому человек с совпавшим
// идентификатором делегатом не считается by construction.
func (d GrantDelegation) IsDelegate(principalType, principalID string) bool {
	t, ok := SubjectTypeOfPrincipal(principalType)
	return ok && t == SubjectTypeServiceAccount && principalID != "" && principalID == string(d.DelegateID)
}

// IsDelegateSubject — субъект выдачи — сам делегат (Д4: себе делегат не выдаёт).
func (d GrantDelegation) IsDelegateSubject(s Subject) bool {
	return s.Type == SubjectTypeServiceAccount && string(s.ID) == string(d.DelegateID)
}

// SubjectTypeOfPrincipal — тип субъекта по виду принципала вызова. Единственная
// нормализация вида для сравнения «вызывающий — делегат» и «субъект — делегат»
// (условие CE-22 разбора классов): вид принципала пишется словом хранения
// ("service_account"), тип субъекта контракта — именем значения
// (`SUBJECT_TYPE_SERVICE_ACCOUNT`); обе формы приводятся к `SubjectType`.
func SubjectTypeOfPrincipal(t string) (SubjectType, bool) {
	switch strings.TrimPrefix(strings.ToLower(t), "subject_type_") {
	case string(SubjectTypeUser):
		return SubjectTypeUser, true
	case string(SubjectTypeServiceAccount):
		return SubjectTypeServiceAccount, true
	case string(SubjectTypeGroup):
		return SubjectTypeGroup, true
	case string(SubjectTypeSystemClass):
		return SubjectTypeSystemClass, true
	default:
		return "", false
	}
}

// ModuleOfCatalogType — модуль точечного типа каталога по его имени
// (`<модуль>.<ресурс>`, например `registry.registries` → `registry`). Пусто,
// если имя без точки.
func ModuleOfCatalogType(dotted string) string {
	m, _, ok := strings.Cut(dotted, ".")
	if !ok {
		return ""
	}
	return m
}

// SortedGrantDelegationAxes — оси делегирования по возрастанию строки: оси —
// наборы, порядок входа не хранится (Р1, `api-repeated-order`).
func SortedGrantDelegationAxes(d GrantDelegation) GrantDelegation {
	d.RoleIDs = slices.Clone(d.RoleIDs)
	slices.Sort(d.RoleIDs)
	d.TargetTypes = slices.Clone(d.TargetTypes)
	slices.Sort(d.TargetTypes)
	d.SubjectTypes = slices.Clone(d.SubjectTypes)
	slices.Sort(d.SubjectTypes)
	return d
}

// RoleDeclaringModule — модуль, манифест которого объявил роль; пусто — роль не
// модульная (платформенная, своя роль аккаунта либо проекта). Это и есть «роль
// модуля» Д2 приёмки.
//
// Владельца несёт колонка `OwnerModule`, её проставляет применитель манифеста.
// У ролей, посеянных до её заведения, колонка пуста, и владение читается ТЕМ ЖЕ
// признаком, что у снятия ролей модуля (`RetireRole`): первый сегмент имени
// кластерной роли. Признак принимается лишь тогда, когда каждое правило роли
// называет этот же модуль: платформенные `admin`, `edit`, `view`, `owner` точки в
// имени не несут, а у `system.*` модуль правил с сегментом имени не совпадает.
func RoleDeclaringModule(r Role) string {
	if r.OwnerModule != "" {
		return r.OwnerModule
	}
	if r.AccountID != "" || r.ProjectID != "" || len(r.Rules) == 0 {
		return ""
	}
	prefix, _, ok := strings.Cut(string(r.Name), ".")
	if !ok || prefix == "" {
		return ""
	}
	for _, rule := range r.Rules {
		if rule.Module != prefix {
			return ""
		}
	}
	return prefix
}
