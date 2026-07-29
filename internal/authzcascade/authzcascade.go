// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authzcascade derives, from iam's OWN committed rows, the structural
// facts the three-tier super-access cascade reads — so that cascade resolves at
// request time and does not depend on a queue having delivered anything.
//
// WHY THIS EXISTS
//
// The recorded decision (.claude/rules/security.md, "Три уровня супер-доступа")
// chose a cascade over per-object materialization on one argument: with a lagging
// or broken pipeline, a materialized top tier locks out the person who has to
// repair the platform. The property claimed is that the cascade "resolves at
// request time and works always, regardless of the state of the pipeline".
//
// The model carries that cascade over STRUCTURAL POINTERS — one computed relation
// per verb-bearing type, derived over the type's own parent pointer:
//
//	iam_access_binding.super_admin: super_admin from project or admin from account or any_admin from cluster
//	project.super_admin:            admin from account or any_admin from cluster
//	account.v_*:                    … or owner or super_admin
//
// Each of those pointers — and the account's `owner` relation — is an ordinary
// relation tuple that reaches OpenFGA only through the at-least-once outbox
// (`EmitRelationWrite` inside the writer transaction → `kacho_iam.fga_outbox` →
// drainer). So the cascade was as materialized as the flat index it was chosen
// over, only one indirection further out: between the commit of a row and the
// delivery of its pointer, the derivation has nothing to resolve over and every
// tier above the grantee is denied.
//
// WHAT THIS DOES INSTEAD
//
// The pointer is not new information. It is a projection of a column in a row iam
// has already committed — `access_bindings.resource_type/resource_id`,
// `projects.account_id`, `accounts.owner_user_id`, and so on. So the decision
// path reads the row and supplies the same triple as an OpenFGA CONTEXTUAL tuple,
// valid for that one Check. The cascade then resolves from committed state alone.
//
// It is not a second source of truth. The projection here and the projection the
// outbox emits are the same function of the same column, and on
// iam_access_binding that column is immutable after Create (update.go
// abImmutableFields: scopeType/scopeId), so the stored tuple and the contextual
// one cannot disagree for the whole life of the row. When the queue does deliver,
// the stored tuple is byte-identical and the contextual copy is redundant, not
// contradictory. On revoke the row is gone, so the fact stops being derivable at
// once — earlier than the stored tuple disappears, never later.
//
// A synchronous write after commit would not give the same property. OpenFGA
// cannot take part in the database transaction — that is why the outbox exists —
// so a post-commit write is an unreconciled second write that can fail, and on
// failure the window is back. What the decision asks for is INDEPENDENCE from
// delivery, not a shorter delay.
//
// BOUNDARY
//
// Only facts iam can prove from its own rows are derivable here. Object types
// owned by other services (vpc_*, compute_*, nlb_*, storage_*, registry_*) have
// their pointer written by their owner's register queue, and iam holds at most a
// queue-fed mirror of it — deriving from that would only move the dependency to
// another queue. Those remain delivery-dependent; the surviving radius is
// measured and named by cascade_coverage_test.go, which fails when a type is
// excluded that has become derivable.
//
// Levels 1-2 (cloud administrator / bootstrap identity) were already independent
// before this package existed: authorize_service resolves them with a flat
// super-gate Check on the cluster singleton, which reads a GRANT and no pointer.
// This package is what makes level 3 and the account owner behave the same way.
package authzcascade

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

// ConditionReader — narrow port over the pool-direct conditions repository (the
// only iam resource whose reader is not on kachorepo.Reader). Optional: when it
// is not wired, iam_condition is simply not derivable and the coverage gate says
// so.
type ConditionReader interface {
	Get(ctx context.Context, id domain.ConditionID) (domain.Condition, error)
}

// Resolver reads iam's committed rows and projects them into the structural
// tuples the cascade derives over.
type Resolver struct {
	repo       kachorepo.Repository
	conditions ConditionReader
}

// New builds a Resolver over iam's own repository.
func New(repo kachorepo.Repository) *Resolver {
	return &Resolver{repo: repo}
}

// WithConditions wires the conditions reader, making iam_condition derivable.
func (r *Resolver) WithConditions(c ConditionReader) *Resolver {
	r.conditions = c
	return r
}

// DerivableTypes — the FGA object types whose structural facts this package can
// prove from a committed iam row. Exported so the coverage gate can compare it
// against the model instead of restating it.
//
// Every entry is a type whose row lives in kacho_iam and carries its parent
// scope as a COLUMN, so the projection is a single authoritative read with no
// ambiguity. iam_condition is included only when the conditions reader is wired
// (see Derivable).
var DerivableTypes = map[string]struct{}{
	"iam_access_binding":  {},
	"account":             {},
	"project":             {},
	"iam_user":            {},
	"iam_group":           {},
	"iam_role":            {},
	"iam_service_account": {},
	"iam_condition":       {},
}

// Derivable reports whether StructuralFacts can say anything about this object
// type at all, WITHOUT touching the database. The decision path calls it first so
// a Check on an object iam does not own costs no read.
func (r *Resolver) Derivable(objectType string) bool {
	if objectType == "iam_condition" {
		return r.conditions != nil
	}
	_, ok := DerivableTypes[objectType]
	return ok
}

// StructuralFacts returns the structural tuples about `<objectType>:<objectID>`
// that iam can prove from its own committed rows.
//
// Contract, and the three outcomes must stay distinguishable:
//
//   - the type is not derivable, or the row does not exist → (nil, nil). Nothing
//     is claimed; the caller's deny stands. A missing row is NOT an error: iam
//     legitimately gets asked about ids that were never its own.
//   - the row exists → its facts, in a deterministic order.
//   - the read failed → (nil, err). The caller must NOT read this as "no facts":
//     the structural fact is part of the decision, so an unreadable row means the
//     answer is unknown, and unknown is an outage, not a denial.
func (r *Resolver) StructuralFacts(ctx context.Context, objectType, objectID string) ([]authztypes.ConditionalTuple, error) {
	if objectID == "" || !r.Derivable(objectType) {
		return nil, nil
	}
	if objectType == "iam_condition" {
		return r.conditionFacts(ctx, objectID)
	}
	if r.repo == nil {
		return nil, nil
	}
	rd, err := r.repo.Reader(ctx)
	if err != nil {
		return nil, fmt.Errorf("authzcascade reader: %w", err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	switch objectType {
	case "iam_access_binding":
		b, gerr := rd.AccessBindings().Get(ctx, domain.AccessBindingID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return bindingScopeFacts(b), nil
	case "account":
		a, gerr := rd.Accounts().Get(ctx, domain.AccountID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return accountFacts(a), nil
	case "project":
		p, gerr := rd.Projects().Get(ctx, domain.ProjectID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return projectFacts(p), nil
	case "iam_user":
		u, gerr := rd.Users().Get(ctx, domain.UserID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return accountPointer(string(u.AccountID), "iam_user", objectID), nil
	case "iam_group":
		g, gerr := rd.Groups().Get(ctx, domain.GroupID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return accountPointer(string(g.AccountID), "iam_group", objectID), nil
	case "iam_role":
		ro, gerr := rd.Roles().Get(ctx, domain.RoleID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		// A system role has no owning account (account_id IS NULL); nothing to
		// derive, and the account tier must not reach it.
		return accountPointer(string(ro.AccountID), "iam_role", objectID), nil
	case "iam_service_account":
		sa, gerr := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return accountPointer(string(sa.AccountID), "iam_service_account", objectID), nil
	}
	return nil, nil
}

func (r *Resolver) conditionFacts(ctx context.Context, objectID string) ([]authztypes.ConditionalTuple, error) {
	c, err := r.conditions.Get(ctx, domain.ConditionID(objectID))
	if err != nil {
		return nil, absentIsNotAnError(err)
	}
	if c.ProjectID == "" {
		return nil, nil
	}
	return []authztypes.ConditionalTuple{{
		User:     "project:" + c.ProjectID,
		Relation: "project",
		Object:   "iam_condition:" + objectID,
	}}, nil
}

// absentIsNotAnError collapses "no such row" to (nil, nil) and passes every other
// failure through. Keeping the two apart is the whole reason StructuralFacts has
// an error at all: an absent row is a fact ("iam knows nothing about this id"),
// an unreadable row is not.
func absentIsNotAnError(err error) error {
	if errors.Is(err, iamerr.ErrNotFound) {
		return nil
	}
	return err
}

// bindingScopeFacts projects an AccessBinding row into its scope parent-pointer.
//
// This MUST stay byte-identical to what the outbox emits for the same row —
// access_binding/tuples.go::hierarchyParentTuple. tuples_parity_test.go asserts
// that against the emitter itself rather than against a copy of its shape, so the
// two cannot drift apart silently.
func bindingScopeFacts(b domain.AccessBinding) []authztypes.ConditionalTuple {
	scope := strings.ToLower(string(b.ResourceType))
	switch scope {
	case "project", "account", "cluster":
	default:
		return nil
	}
	if b.ResourceID == "" {
		return nil
	}
	return []authztypes.ConditionalTuple{{
		User:     scope + ":" + b.ResourceID,
		Relation: scope,
		Object:   "iam_access_binding:" + string(b.ID),
	}}
}

// accountFacts projects an account row into the two structural facts the model
// reads on `account`: its cluster pointer (levels 1-2 reach the account over it)
// and its OWNER.
//
// The owner is here because the model says it is structural — "holds the instant
// the account exists and never waits for the reconciler" — while the `owner`
// tuple was itself outbox-delivered, so an account could not be torn down by the
// person who had just created it until the queue caught up. That is the exact
// asymmetry the owner refinement was written to remove.
func accountFacts(a domain.Account) []authztypes.ConditionalTuple {
	out := []authztypes.ConditionalTuple{{
		User:     "cluster:" + domain.ClusterSingletonID,
		Relation: "cluster",
		Object:   "account:" + string(a.ID),
	}}
	if a.OwnerUserID != "" {
		out = append(out, authztypes.ConditionalTuple{
			User:     "user:" + string(a.OwnerUserID),
			Relation: "owner",
			Object:   "account:" + string(a.ID),
		})
	}
	return out
}

// projectFacts projects a project row into its account and cluster pointers —
// both of which `project.super_admin` derives over.
func projectFacts(p domain.Project) []authztypes.ConditionalTuple {
	out := []authztypes.ConditionalTuple{{
		User:     "cluster:" + domain.ClusterSingletonID,
		Relation: "cluster",
		Object:   "project:" + string(p.ID),
	}}
	if p.AccountID != "" {
		out = append(out, authztypes.ConditionalTuple{
			User:     "account:" + string(p.AccountID),
			Relation: "account",
			Object:   "project:" + string(p.ID),
		})
	}
	return out
}

// accountPointer is the one-line projection shared by the account-scoped iam
// types (`<type>.super_admin: admin from account`). An empty accountID yields
// nothing — a row with no owning account must not become reachable from any
// account's administrator.
func accountPointer(accountID, objectType, objectID string) []authztypes.ConditionalTuple {
	if accountID == "" {
		return nil
	}
	return []authztypes.ConditionalTuple{{
		User:     "account:" + accountID,
		Relation: "account",
		Object:   objectType + ":" + objectID,
	}}
}
