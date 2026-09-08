// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_binding_scope.go — typed Scope enum for the RBAC v2 AccessBinding
// shape. The Scope tier anchors the binding in the
// cluster ▶ account ▶ project hierarchy; per-resourceName grants emit
// direct FGA tuples that respect Scope only as a sanity guard.
package domain

import (
	"errors"
	"strings"
)

// Scope — anchor tier for an AccessBinding.
type Scope int8

const (
	ScopeUnspecified Scope = 0
	ScopeCluster     Scope = 1
	ScopeAccount     Scope = 2
	ScopeProject     Scope = 3
)

// ErrScopeMismatch — Scope does not match (resource_type, resource_id).
// Service-layer maps to gRPC InvalidArgument.
var ErrScopeMismatch = errors.New("scope does not match resource_type / resource_id")

// String — debug-friendly rendering (matches proto enum names).
func (s Scope) String() string {
	switch s {
	case ScopeCluster:
		return "CLUSTER"
	case ScopeAccount:
		return "ACCOUNT"
	case ScopeProject:
		return "PROJECT"
	default:
		return "SCOPE_UNSPECIFIED"
	}
}

// Dotted scope-type API projection (redesign-2026 F7). The AccessBinding
// scope-anchor is renamed resource_type/resource_id → scopeType/scopeId on the
// wire, with the word "resource" freed for the reintroduced target. The wire
// scopeType is dotted (`iam.{cluster,account,project}`) while the within-service
// storage keeps the bare kind (`cluster`/`account`/`project`) — the two are mapped
// at the API boundary (dto on output, handler on input). Only the three hierarchy
// tiers can anchor a binding, so the mapping is total over them.
const (
	ScopeTypeClusterDotted = "iam.cluster"
	ScopeTypeAccountDotted = "iam.account"
	ScopeTypeProjectDotted = "iam.project"
)

// scopeKind — одна запись словаря областей: ВСЁ, что домен знает о голом виде.
//
//	tier    ярус, которым вид якорится (либо в который выводится)
//	dotted  проволочная форма; ПУСТО ⇒ вид якорем быть не может
//	idOK    годен ли идентификатор под этот вид; nil ⇒ вид не якорь и id не судит
type scopeKind struct {
	tier   Scope
	dotted string
	idOK   func(id string) bool
}

// scopeVocabulary — ЕДИНСТВЕННОЕ объявление отношения «вид ↔ ярус» в этом
// пакете. Читают его ВСЕ переводы ниже; второго перечисления видов не заводится.
//
// # Что здесь было и почему сведено (задача продукта #2057)
//
// Отношение несли ТРИ места: эта карта (тогда — только перевод в проволочную
// форму), `ValidateAgainst` со своим `switch` по ярусу и `DeriveFromResourceType`
// с обратным `switch` по строке. Они были согласованы и дрейфовали независимо:
// каждое перечисляло виды само, и расхождение вышло бы МОЛЧА — ни компилятор, ни
// обзор диффа второго перечня не видят.
//
// Приём не нов: тем же способом раньше сведён словарь ЯКОРЯ, где вторая карта
// разошлась с первой на двадцать записей. Здесь он применён к ярусу.
//
// # Унаследованные написания
//
// `cloud` и `folder` ярус ВЫВОДЯТ, но якорем не бывают: проволочной формы у них
// нет, поэтому ни `IsScopeAnchorKind`, ни `ScopeTypeFromDotted` их не принимают.
// Публичный `Create` приводит `scopeType` закрытым переводом из трёх значений —
// то есть по пути запроса эти виды недостижимы; они остаются ради путей, у
// которых на руках голая строка.
//
// # Третье место — СХЕМА, и это объявлено, а не умолчано
//
// Тот же вывод делает триггер `access_bindings_scope_default` на BEFORE INSERT:
// он проставляет ярус, когда писатель его не назвал, и делает это НА УРОВНЕ БАЗЫ
// (ban #10), поэтому снять его в пользу домена нельзя. Значит мест остаётся два,
// и второе объявлено ОСОЗНАННО: согласие двух объявлений держит интеграционная
// проба `internal/migrations/scope_default_agrees_with_domain_integration_test.go`
// — она читает ЖИВУЮ функцию из каталога и сверяет её ветви с этой картой в обе
// стороны.
var scopeVocabulary = map[string]scopeKind{
	"cluster": {
		tier:   ScopeCluster,
		dotted: ScopeTypeClusterDotted,
		idOK:   func(id string) bool { return id == ClusterSingletonID },
	},
	"account": {
		tier:   ScopeAccount,
		dotted: ScopeTypeAccountDotted,
		idOK:   func(id string) bool { return strings.HasPrefix(id, PrefixAccount) },
	},
	"project": {
		tier:   ScopeProject,
		dotted: ScopeTypeProjectDotted,
		idOK:   func(id string) bool { return strings.HasPrefix(id, PrefixProject) },
	},
	// Унаследованные написания: ярус выводят, якорем не бывают.
	"cloud":  {tier: ScopeAccount},
	"folder": {tier: ScopeProject},
}

// scopeAnchorByDotted — обратный указатель, ВЫВЕДЕННЫЙ из того же объявления:
// выписанный вручную разошёлся бы с прямым, и разошёлся бы молча.
var scopeAnchorByDotted = func() map[string]string {
	m := make(map[string]string, len(scopeVocabulary))
	for bare, k := range scopeVocabulary {
		if k.dotted != "" {
			m[k.dotted] = bare
		}
	}
	return m
}()

// scopeAnchorByTier — второй выведенный указатель: ярус → голый вид ЯКОРЯ.
//
// Строится только по записям с проволочной формой, и это несущее ограничение, а
// не экономия: унаследованные написания делят ярус с якорем (`cloud` — с
// `account`), поэтому карта по ВСЕМ записям была бы неоднозначной и молча
// зависела бы от порядка обхода. Кардинальность проверяется пробой пакета.
var scopeAnchorByTier = func() map[Scope]string {
	m := make(map[Scope]string, len(scopeVocabulary))
	for bare, k := range scopeVocabulary {
		if k.dotted != "" {
			m[k.tier] = bare
		}
	}
	return m
}()

// ScopeTierByKind — копия словаря «вид → ярус».
//
// Экспорт заведён ради ОДНОГО вызывающего — пробы согласия с триггером схемы
// (см. §«Третье место» выше). Второе объявление отношения живёт в другом
// пакете, поэтому сверить его иначе нечем: без этого читателя согласие двух
// объявлений было бы обещанием, а не проверкой.
//
// Отдаётся копия: словарь неизменяем by construction, и вызывающий не должен
// иметь возможности это нарушить.
func ScopeTierByKind() map[string]Scope {
	m := make(map[string]Scope, len(scopeVocabulary))
	for bare, k := range scopeVocabulary {
		m[bare] = k.tier
	}
	return m
}

// ValidateAgainst checks that the Scope is consistent with the binding's
// (resource_type, resource_id). Returns ErrScopeMismatch if not.
//
// CLUSTER ⇒ resource_type='cluster', resource_id='cluster_root'
// ACCOUNT ⇒ resource_type='account', resource_id starts with 'acc'
// PROJECT ⇒ resource_type='project', resource_id starts with 'prj'
//
// Виды и их требования к идентификатору берутся из [scopeVocabulary]; своего
// перечисления здесь нет — оно было и разошлось бы с картой молча.
func (s Scope) ValidateAgainst(resourceType, resourceID string) error {
	bare, ok := scopeAnchorByTier[s]
	if !ok || bare != resourceType {
		return ErrScopeMismatch
	}
	if idOK := scopeVocabulary[bare].idOK; idOK == nil || !idOK(resourceID) {
		return ErrScopeMismatch
	}
	return nil
}

// IsScopeAnchorKind reports whether a bare within-service kind may anchor an
// AccessBinding. Only the three hierarchy tiers can; a per-object type names an
// object UNDER the anchor and belongs to the `target` axis (F8), whose vocabulary
// is the materialization feed (`ValidTargetType`).
func IsScopeAnchorKind(bare string) bool {
	return scopeVocabulary[bare].dotted != ""
}

// ScopeTypeToDotted maps the bare within-service anchor kind to the dotted wire
// scopeType. An unrecognized kind is returned unchanged (defensive — a binding
// anchor is always one of the three tiers).
func ScopeTypeToDotted(bare string) string {
	if dotted := scopeVocabulary[bare].dotted; dotted != "" {
		return dotted
	}
	return bare
}

// ScopeTypeFromDotted maps the dotted wire scopeType to the bare within-service
// anchor kind. ok=false for any value outside the closed three-tier set (empty,
// non-dotted bare, or unknown dotted) — the caller rejects it with InvalidArgument.
func ScopeTypeFromDotted(dotted string) (bare string, ok bool) {
	bare, ok = scopeAnchorByDotted[dotted]
	return bare, ok
}

// DeriveFromResourceType — best-effort fallback for code paths that have
// resource_type but no explicit Scope (e.g. legacy callers that pre-date
// the W4 scope plumbing). Mirrors the BEFORE INSERT trigger of the schema; that
// the two agree is held by a probe, not by this sentence — см. §«Третье место»
// у [scopeVocabulary].
//
// Вид вне словаря даёт ярус проекта — самый узкий из трёх, то есть ошибка
// умолчания не расширяет доступ.
func DeriveFromResourceType(resourceType string) Scope {
	if k, ok := scopeVocabulary[resourceType]; ok {
		return k.tier
	}
	return ScopeProject
}
