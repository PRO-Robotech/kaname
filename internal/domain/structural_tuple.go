// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import "strings"

// structural_tuple.go — the SINGLE projection of a committed iam row into the
// structural relation triples the authorization model derives the super-access
// cascade over.
//
// There are two consumers, and the reason this lives in domain is that they must
// never disagree:
//
//   - the emitter — access_binding/tuples.go, account/create.go, project/create.go
//     — enqueues the triple into kacho_iam.fga_outbox inside the writer transaction,
//     to be applied to OpenFGA by the drainer;
//   - the resolver — internal/authzcascade — supplies the SAME triple as a
//     request-scoped contextual tuple, so the cascade resolves from committed state
//     instead of waiting for that delivery.
//
// If those two projections were written twice, a change to one would silently
// change what the cascade means depending on whether the queue had caught up. With
// one function there is nothing to drift: the stored tuple and the contextual one
// are the same function of the same columns. On AccessBinding the columns are
// immutable after Create (scopeType/scopeId), so they cannot even differ over time.

// StructuralTuple — one relation triple. Transport-neutral on purpose: the emitter
// converts it to its repo tuple type and the resolver to its OpenFGA wire type, and
// domain stays free of both.
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
func isBindableScope(scope string) bool {
	switch scope {
	case "project", "account", "cluster":
		return true
	default:
		return false
	}
}

// StructuralParent returns the binding's scope parent-pointer:
//
//	project:<resourceID>  →  project  →  iam_access_binding:<id>
//	account:<resourceID>  →  account  →  iam_access_binding:<id>
//	cluster:<resourceID>  →  cluster  →  iam_access_binding:<id>
//
// This triple is what `iam_access_binding.super_admin: super_admin from project or
// admin from account or any_admin from cluster` resolves over — the sole enabler of
// the cascade on a binding. ok=false when the scope is not a hierarchy parent or the
// binding has no id.
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

// ProjectScopedStructuralFact is the same for the project-scoped iam types
// (`super_admin: super_admin from project`) — today iam_condition.
func ProjectScopedStructuralFact(projectID, objectType, objectID string) (StructuralTuple, bool) {
	if projectID == "" || objectType == "" || objectID == "" {
		return StructuralTuple{}, false
	}
	return StructuralTuple{
		User:     "project:" + projectID,
		Relation: "project",
		Object:   objectType + ":" + objectID,
	}, true
}
