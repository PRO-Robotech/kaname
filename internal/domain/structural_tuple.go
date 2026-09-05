// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "strings"

// structural_tuple.go — the SINGLE projection of a committed iam row into the
// structural relation triples the authorization model derives the super-access
// cascade over.
//
// There WERE two consumers, and the reason this lives in domain is that they had to
// agree:
//
//   - the emitter — access_binding/tuples.go::hierarchyParentTuple,
//     account/create.go::ownerTuples, project/create.go::projectStructuralTuples —
//     enqueues the triple into kacho_iam.fga_outbox inside the writer transaction,
//     out of which a trigger folds the direct fact in the SAME commit;
//   - the resolver — it supplied the SAME triple as a request-scoped tuple, so the
//     cascade resolved from committed state instead of waiting for a delivery.
//
// The second consumer went away with the external engine: the form reads the
// committed rows itself, so there is nothing left to hand it, and there is no
// delivery to outrun. The single-source rule outlives it for the emitters that
// remain — three call sites derive the same triple from the same columns, and
// writing it three times would let one of them drift. On AccessBinding the columns
// are immutable after Create (scopeType/scopeId), so they cannot differ over time.

// StructuralTuple — one relation triple. Transport-neutral on purpose: the emitter
// converts it to its repo tuple type, and domain stays free of that type.
type StructuralTuple struct {
	// User — the SOURCE of the relation: the parent object ("account:<id>") for a
	// parent-pointer, or the subject ("user:<id>") for the account owner.
	User string
	// Relation — the relation name on Object, named after the parent's type for a
	// pointer ("account"/"project"/"cluster") or "owner".
	Relation string
	// Object — the object the relation is written on ("iam_access_binding:<id>").
	Object string
}

// bindableScopes — the closed set of AccessBinding scopes that are hierarchy
// parents. A binding carries exactly ONE, named by resource_type.
//
// ВЛАДЕЛЕЦ НАБОРА ОДИН, и это существенно. Тот же набор решает, будет ли у
// привязки звено в цепи областей (StructuralParent ниже), — значит всякий, кто
// спрашивает «называет ли эта привязка предка», обязан спрашивать ЗДЕСЬ.
// Второй ответ на тот же вопрос уже существовал: план чтения материализации
// предка у привязки с областью «кластер» НЕ ДАЁТ (это его намеренное свойство,
// оговорённое его собственным комментарием), и перепись, взявшая предикат
// оттуда, объявляла законную строку «лишней». Перечень мест, где цепь законно
// расходится с планом чтения, ведётся поимённо — см. legalDifferences в
// scopeedgesource_gate_test.go.
var bindableScopes = []string{"project", "account", "cluster"}

// BindableScopes — копия закрытого набора областей выдачи, годных в предки.
// Копия, а не сам срез: набор закрыт, и вызывающий не вправе его пополнить.
func BindableScopes() []string {
	out := make([]string, len(bindableScopes))
	copy(out, bindableScopes)
	return out
}

func isBindableScope(scope string) bool {
	for _, s := range bindableScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// StructuralParent returns the binding's scope parent-pointer:
//
//	project:<resourceID>  →  project  →  iam_access_binding:<id>
//	account:<resourceID>  →  account  →  iam_access_binding:<id>
//	cluster:<resourceID>  →  cluster  →  iam_access_binding:<id>
//
// This triple is what `iam_access_binding.super_admin: super_admin from project or
// admin from account or any_admin from cluster` resolves over — the sole enabler of
// the cascade on a binding. ok=false when the scope is not a hierarchy parent, the
// binding has no id, or the scope has no id.
//
// The empty-scope-id case is unreachable through the API — validateScopeID pins the
// cluster tier to the singleton id and requires a non-empty account/project id — and
// the guard is here for what it prevents rather than for what it expects: without it
// such a row projects `cluster:` with an empty object id, which the store rejects, and
// a rejected write in the outbox is retried rather than dropped, so one malformed row
// would hold up its partition indefinitely.
//
// It is deliberately INDEPENDENT of status. A revoked binding keeps its row, and it
// is still a record that has to be readable and deletable by the administrator of its
// account; a status filter here would take that away precisely when the queue is
// behind. It cannot bring the grant back: what the grantee held were tuples on the
// SCOPE object, and this is a pointer at the binding, not a grant on the scope. Locked
// by service/cascade_queue_independence_integration_test.go
// (TestRevokedBindingStaysManageableAndGrantsNothing).
func (b AccessBinding) StructuralParent() (StructuralTuple, bool) {
	scope := strings.ToLower(string(b.ResourceType))
	if !isBindableScope(scope) || b.ID == "" || b.ResourceID == "" {
		return StructuralTuple{}, false
	}
	return StructuralTuple{
		User:     scope + ":" + b.ResourceID,
		Relation: scope,
		Object:   "iam_access_binding:" + string(b.ID),
	}, true
}

// StructuralFacts returns the two structural facts the model reads on `account`:
//
//	cluster:<singleton>  →  cluster  →  account:<id>     (levels 1-2 reach it here)
//	user:<owner>         →  owner    →  account:<id>
//
// The owner is a structural fact and not merely a materialized grant: an account is
// created by self-service, so tearing it down has to be as reliable as creating it,
// which is why `account`'s five verbs read `or owner` directly.
func (a Account) StructuralFacts() []StructuralTuple {
	if a.ID == "" {
		return nil
	}
	out := []StructuralTuple{{
		User:     "cluster:" + ClusterSingletonID,
		Relation: "cluster",
		Object:   "account:" + string(a.ID),
	}}
	if a.OwnerUserID != "" {
		out = append(out, StructuralTuple{
			User:     "user:" + string(a.OwnerUserID),
			Relation: "owner",
			Object:   "account:" + string(a.ID),
		})
	}
	return out
}

// StructuralFacts returns the project's cluster and account pointers — both of
// which `project.super_admin: admin from account or any_admin from cluster` reads.
func (p Project) StructuralFacts() []StructuralTuple {
	if p.ID == "" {
		return nil
	}
	out := []StructuralTuple{{
		User:     "cluster:" + ClusterSingletonID,
		Relation: "cluster",
		Object:   "project:" + string(p.ID),
	}}
	if p.AccountID != "" {
		out = append(out, StructuralTuple{
			User:     "account:" + string(p.AccountID),
			Relation: "account",
			Object:   "project:" + string(p.ID),
		})
	}
	return out
}

// AccountScopedStructuralFact is the one-line projection shared by the
// account-scoped iam types, whose cascade is `super_admin: admin from account`:
//
//	account:<accountID>  →  account  →  <objectType>:<objectID>
//
// An empty accountID yields nothing: a row with no owning account (a system role)
// must not become reachable from any account's administrator.
func AccountScopedStructuralFact(accountID, objectType, objectID string) (StructuralTuple, bool) {
	if accountID == "" || objectType == "" || objectID == "" {
		return StructuralTuple{}, false
	}
	return StructuralTuple{
		User:     "account:" + accountID,
		Relation: "account",
		Object:   objectType + ":" + objectID,
	}, true
}

// Проектно-скоупленной проекции здесь больше нет: единственным типом,
// выводившимся из проекта (`super_admin: super_admin from project`), был снятый
// ресурс условия. Функция без прод-вызывающих — не «задел на будущее», а
// мёртвый код, который следующий читатель примет за живой контракт. Когда
// появится настоящий проектно-скоупленный тип, она пишется под него — вместе с
// вызывающим.
