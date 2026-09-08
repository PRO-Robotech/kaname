// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// target_membership.go — the materialized membership of a binding's
// target (selector byLabel or resources[] byName) + the pure containment
// predicate. Pure domain (stdlib only): no pgx/grpc.
//
// Membership rows live in kaname.access_binding_target_members; each carries a
// VerificationStatus. The reconciler computes the desired set from
// resource_mirror, applies the containment predicate below, and diffs it against
// the materialized rows.

// VerificationStatus — the observable per-member containment verdict.
type VerificationStatus string

const (
	// VerificationPending — the object is NOT yet in resource_mirror (the grant
	// raced ahead of the owner's RegisterResource). No FGA tuple is emitted; the
	// reconciler verifies it when the mirror row arrives.
	VerificationPending VerificationStatus = "PENDING_VERIFICATION"
	// VerificationActive — the object is in resource_mirror AND under the
	// binding's scope-anchor. The per-object FGA tuple IS emitted.
	VerificationActive VerificationStatus = "ACTIVE"
	// VerificationRejected — the object is in resource_mirror but NOT under scope
	// (mirror.parent_* ⋢ scope). No tuple; an audit event is written (not silent).
	VerificationRejected VerificationStatus = "REJECTED"
)

// TargetMember — one materialized member of a binding's target with its current
// verification status. object_type is a closed-table dotted key (e.g.
// "compute.instance"); object_id is an opaque cross-DB soft-ref.
//
// RuleFP attributes the member to the (role) RULE that produced it: the
// content-hash of the ARM_LABELS rule
// (domain.Rule.Fingerprint) for a role.rules-driven member, or the sentinel
// "legacy-selector" for a legacy binding.selector member. Keying membership by
// rule_fp (not a positional index) lets a Role.Update that removes one rule
// eager-revoke ONLY that rule's members and lets the SAME object
// be a member under two different rules at different tiers (distinct rows).
type TargetMember struct {
	BindingID          AccessBindingID
	RoleID             RoleID
	RuleFP             string
	ObjectType         string
	ObjectID           string
	VerificationStatus VerificationStatus
}

// MembershipTuple — a per-object FGA relation tuple the reconciler emits/revokes
// for a materialized membership (subject → tier → object). A flat value so the
// reconcile use-case stays transport/storage-agnostic; the pg adapter maps it to
// the fga_outbox payload.
type MembershipTuple struct {
	User     string // e.g. "user:usr-…", "group:grp-…#member"
	Relation string // tier relation (e.g. "editor")
	Object   string // e.g. "compute_instance:inst-1"
}

// ScopeAnchor — the resource the binding is scoped to (its containment anchor).
// Type is one of "project" | "account" | "cluster"; ID is the resource id.
type ScopeAnchor struct {
	Type string
	ID   string
}

// MirrorObject — the same-DB parent-scope projection of an owner object read from
// resource_mirror (β fed it; γ reads it). Pure value; the reader adapter fills it.
type MirrorObject struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	// ParentAccountIDs — АККАУНТЫ, под которыми лежит объект. Множественное
	// число здесь не запас на будущее: у ЛИЧНОСТИ принадлежность аккаунту
	// перестала быть свойством её строки и стала отдельной связью, которых у
	// человека бывает несколько (#470/#471), поэтому скалярное поле называло бы
	// ОДИН аккаунт из многих — и выдача второго аккаунта не находила бы своего
	// человека by construction (#1172).
	//
	// У всех прочих типов набор вырожден: ноль элементов (объект не лежит ни в
	// одном аккаунте) либо один. Пустые строки в набор НЕ КЛАДУТСЯ — «аккаунта
	// нет» выражается отсутствием элемента, а не элементом-пустышкой, иначе
	// область с пустым идентификатором совпала бы с ним.
	ParentAccountIDs []string
	Labels           map[string]string
}

// IsContainedIn reports whether a mirror object lies UNDER the given scope-anchor
// (the single containment predicate for byName AND byLabel — parity).
//
//	project:P ⊑ project:P                         (same project)
//	project:P ⊑ account:A  if A ∈ mirror.ParentAccountIDs
//	any       ⊑ cluster:*                          (cluster contains everything)
//
// A cluster-scoped binding contains every registered object. The cluster id is
// not compared (there is a single cluster root in the FGA model).
//
// This predicate is PURE (no DB): it trusts ParentAccountIDs to already carry the
// object's FULL account set. For a mirror-fed object registered with only its owning
// PROJECT, the reader adapter resolves the account through the project→account
// hierarchy same-DB (resource_mirror reader COALESCE) BEFORE filling ParentAccountIDs,
// so an account-scoped binding transitively contains an object nested in a project of
// its account even when the stored parent_account_id column was empty. The resolution
// is account-bounded (one project → one account), so this predicate never leaks across
// the account boundary.
//
// ЧЛЕНСТВО ЗДЕСЬ — «хотя бы одно», и это не послабление. У личности аккаунтов
// столько, сколько у человека членств (#1172): выдача аккаунта B накрывает его
// потому, что он состоит в B, и НИ ОДИН чужой аккаунт от этого его не накрывает
// — набор перечисляет ровно те аккаунты, связь с которыми существует строкой
// `kaname.memberships`.
//
// Пустая область (scope.ID == "") не совпадает ни с чем: набор пустых строк не
// содержит by construction (см. комментарий поля), но проверка стоит здесь же —
// сравнение «пусто с пусто» иначе давало бы истину на объекте без аккаунта.
func (m MirrorObject) IsContainedIn(scope ScopeAnchor) bool {
	switch scope.Type {
	case "project":
		return m.ParentProjectID != "" && m.ParentProjectID == scope.ID
	case "account":
		if scope.ID == "" {
			return false
		}
		for _, acc := range m.ParentAccountIDs {
			if acc == scope.ID {
				return true
			}
		}
		return false
	case "cluster":
		return true
	default:
		return false
	}
}

// MatchesLabels reports whether the mirror object's labels satisfy the
// AND-equality match set: for EVERY (k,v) in matchLabels the object must
// have labels[k]==v (superset allowed — the object may carry extra labels). This
// is the in-Go equivalent of the JSONB `labels @> matchLabels` probe used by the
// reader's SQL filter; kept here so the containment verdict is testable in pure
// domain and the reconciler can re-assert it on a candidate set.
func (m MirrorObject) MatchesLabels(matchLabels map[string]string) bool {
	for k, v := range matchLabels {
		got, ok := m.Labels[k]
		if !ok || got != v {
			return false
		}
	}
	return true
}
