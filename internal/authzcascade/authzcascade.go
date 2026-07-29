// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package authzcascade derives, from iam's OWN committed rows, the structural
// facts the three-tier super-access cascade reads — so that cascade resolves at
// request time and does not depend on a queue having delivered anything.
//
// # WHY THIS EXISTS
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
// # WHAT THIS DOES INSTEAD
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
// abImmutableFields: scopeType/scopeId), so the two projections cannot disagree about
// WHAT the pointer is for the whole life of the row. When the queue delivers, the
// stored tuple is byte-identical and the contextual copy is redundant.
//
// They DO diverge about WHETHER the pointer is present, in exactly one place, by
// design: Revoke deletes the emitted set (the parent pointer among it) while KEEPING
// the row (access_binding/revoke.go), so afterwards the store has no pointer and this
// package still derives one. That is intended — a revoked binding is still a record
// its account's administrator must be able to read and delete — and it cannot restore
// the grant, because what the grantee held were tuples on the SCOPE object and nothing
// here ever projects one. Delete removes the row, and then the fact stops being
// derivable at once. Locked by
// service/cascade_queue_independence_integration_test.go::TestRevokedBindingStaysManageableAndGrantsNothing.
//
// A synchronous write after commit would not give the same property. OpenFGA
// cannot take part in the database transaction — that is why the outbox exists —
// so a post-commit write is an unreconciled second write that can fail, and on
// failure the window is back. What the decision asks for is INDEPENDENCE from
// delivery, not a shorter delay.
//
// # BOUNDARY
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
	"time"

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

// PrimaryReaderSource opens a read-only transaction on the PRIMARY.
//
// It is deliberately NOT kachorepo.Repository, whose Reader() prefers a replica. The
// row this package reads is, by construction, one that was just committed — precisely
// what a replica lags on. Reading it from a replica would not remove the dependency on
// a delivery pipeline, only change which pipeline it is, and the package would then be
// claiming something it does not do. Satisfied by *repo/kacho/pg.Repository.
type PrimaryReaderSource interface {
	ReaderFromPrimary(ctx context.Context) (kachorepo.Reader, error)
}

// Resolver reads iam's committed rows and projects them into the structural
// tuples the cascade derives over.
type Resolver struct {
	repo       PrimaryReaderSource
	conditions ConditionReader
	// readTimeout bounds ONE structural read. The read sits on the request path of an
	// authorization decision, so an unresponsive database must cost a bounded wait and
	// a fail-closed answer rather than a held goroutine (architecture.md, per-call
	// deadline on every external call).
	readTimeout time.Duration
}

// defaultReadTimeout — the structural read is a handful of primary-key lookups; a
// second is already far beyond healthy, and the deny it produces on expiry is
// fail-closed.
const defaultReadTimeout = time.Second

// New builds a Resolver over iam's own primary.
func New(repo PrimaryReaderSource) *Resolver {
	return &Resolver{repo: repo, readTimeout: defaultReadTimeout}
}

// WithReadTimeout overrides the per-read deadline. Zero or negative leaves the
// default.
func (r *Resolver) WithReadTimeout(d time.Duration) *Resolver {
	if d > 0 {
		r.readTimeout = d
	}
	return r
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

// maxChainDepth bounds the walk below. The structural chain is
// leaf → project → account → cluster, and `cluster` derives nothing further, so
// three hops is the whole of it. The bound is here so a future pointer that
// accidentally closes a loop costs a stopped walk rather than a hung request.
const maxChainDepth = 4

// StructuralFacts returns the structural tuples the cascade needs in order to
// resolve `<objectType>:<objectID>` from committed state — the object's own parent
// pointer AND, TRANSITIVELY, the pointers of the objects that pointer names.
//
// The transitive part is not an optimisation, it is the requirement. A
// project-scoped access binding is reached by
// `super_admin from project` → `project.super_admin: admin from account`, so the
// account administrator's path runs over TWO pointers — binding→project and
// project→account — and both are outbox-delivered. Supplying only the first leaves
// the second hop with nothing to resolve over, and the cascade still denies. The
// walk therefore follows each derived pointer to its own row until it reaches the
// cluster, which points at nothing.
//
// Contract, and the three outcomes must stay distinguishable:
//
//   - the type is not derivable, or the row does not exist → (nil, nil). Nothing
//     is claimed; the caller's deny stands. A missing row is NOT an error: iam
//     legitimately gets asked about ids that were never its own.
//   - the row exists → its facts and its ancestors', in a deterministic order.
//   - the read failed → (nil, err). The caller must NOT read this as "no facts":
//     the structural fact is part of the decision, so an unreadable row means the
//     answer is unknown, and unknown is an outage, not a denial.
func (r *Resolver) StructuralFacts(ctx context.Context, objectType, objectID string) ([]authztypes.TupleKey, error) {
	if objectID == "" || !r.Derivable(objectType) {
		return nil, nil
	}
	// ONE reader transaction for the whole walk. Two reasons, and the second is
	// correctness: a chain read across separate transactions can see a TORN
	// hierarchy (the binding's project from before a move, that project's account
	// from after it), and the facts handed to OpenFGA would then describe a shape
	// that never existed. One snapshot cannot.
	if r.readTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.readTimeout)
		defer cancel()
	}
	var rd kachorepo.Reader
	if r.repo != nil {
		var err error
		rd, err = r.repo.ReaderFromPrimary(ctx)
		if err != nil {
			return nil, fmt.Errorf("authzcascade reader: %w", err)
		}
		defer func() { _ = rd.Rollback(ctx) }()
	}
	var (
		out     []authztypes.TupleKey
		visited = map[string]bool{}
		// worklist of objects still to project, breadth-first from the target.
		queue = []objectRef{{Type: objectType, ID: objectID}}
	)
	for depth := 0; depth < maxChainDepth && len(queue) > 0; depth++ {
		next := make([]objectRef, 0, len(queue))
		for _, ref := range queue {
			key := ref.Type + ":" + ref.ID
			if visited[key] || !r.Derivable(ref.Type) {
				continue
			}
			visited[key] = true
			facts, err := r.factsFor(ctx, rd, ref.Type, ref.ID)
			if err != nil {
				return nil, err
			}
			out = append(out, facts...)
			// Each derived pointer names a PARENT object; that parent's own pointer
			// is the next hop of the same chain.
			for _, f := range facts {
				if p, ok := parseObjectRef(f.User); ok && !visited[p.Type+":"+p.ID] {
					next = append(next, p)
				}
			}
		}
		queue = next
	}
	return out, nil
}

// objectRef — a typed FGA object the walk still has to project.
type objectRef struct {
	Type string
	ID   string
}

// parseObjectRef reads "<type>:<id>" produced by this package's own projections. A
// userset reference ("group:g#member") is refused outright; anything else is filtered
// by Derivable, which is what actually keeps the walk to objects iam owns — a
// subject ("user:<owner>") and the cluster singleton both fall out there, since
// neither is a derivable type.
func parseObjectRef(s string) (objectRef, bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 || strings.Contains(s, "#") {
		return objectRef{}, false
	}
	return objectRef{Type: s[:i], ID: s[i+1:]}, true
}

// factsFor projects ONE row, on the walk's shared snapshot. StructuralFacts is the
// transitive closure over it.
//
// The conditions reader is pool-direct (it is the one iam resource whose reader is
// not on kachorepo.Reader), so an iam_condition read is outside the snapshot. That is
// harmless here: a condition is a leaf of the chain — its project pointer is the last
// hop taken from it, and the project itself is then read on the snapshot.
func (r *Resolver) factsFor(
	ctx context.Context, rd kachorepo.Reader, objectType, objectID string,
) ([]authztypes.TupleKey, error) {
	if objectType == "iam_condition" {
		return r.conditionFacts(ctx, objectID)
	}
	if rd == nil {
		return nil, nil
	}
	switch objectType {
	case "iam_access_binding":
		b, gerr := rd.AccessBindings().Get(ctx, domain.AccessBindingID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditionalOne(b.StructuralParent()), nil
	case "account":
		a, gerr := rd.Accounts().Get(ctx, domain.AccountID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditional(a.StructuralFacts()), nil
	case "project":
		p, gerr := rd.Projects().Get(ctx, domain.ProjectID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditional(p.StructuralFacts()), nil
	case "iam_user":
		u, gerr := rd.Users().Get(ctx, domain.UserID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditionalOne(domain.AccountScopedStructuralFact(string(u.AccountID), "iam_user", objectID)), nil
	case "iam_group":
		g, gerr := rd.Groups().Get(ctx, domain.GroupID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditionalOne(domain.AccountScopedStructuralFact(string(g.AccountID), "iam_group", objectID)), nil
	case "iam_role":
		ro, gerr := rd.Roles().Get(ctx, domain.RoleID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		// account_id is NULL for TWO kinds of role, and neither yields a fact.
		// A system role has no owning account at all, and the account tier must not
		// reach it. A PROJECT-scoped custom role has a parent — its project — but
		// `iam_role` declares no `project` relation, so that arm of the cascade is
		// unreachable in the model rather than merely undelivered; see the note on
		// iam_role in cascade_coverage_test.go.
		return toConditionalOne(domain.AccountScopedStructuralFact(string(ro.AccountID), "iam_role", objectID)), nil
	case "iam_service_account":
		sa, gerr := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(objectID))
		if gerr != nil {
			return nil, absentIsNotAnError(gerr)
		}
		return toConditionalOne(domain.AccountScopedStructuralFact(string(sa.AccountID), "iam_service_account", objectID)), nil
	}
	return nil, nil
}

func (r *Resolver) conditionFacts(ctx context.Context, objectID string) ([]authztypes.TupleKey, error) {
	c, err := r.conditions.Get(ctx, domain.ConditionID(objectID))
	if err != nil {
		return nil, absentIsNotAnError(err)
	}
	return toConditionalOne(domain.ProjectScopedStructuralFact(c.ProjectID, "iam_condition", objectID)), nil
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

// toConditional maps the domain projection onto the OpenFGA wire shape. It is the
// ONLY place this package decides anything about tuple shape; what the triples ARE
// is decided once, in domain/structural_tuple.go, and the outbox emitter reads the
// same function. See that file for why.
func toConditional(sts []domain.StructuralTuple) []authztypes.TupleKey {
	if len(sts) == 0 {
		return nil
	}
	out := make([]authztypes.TupleKey, 0, len(sts))
	for _, st := range sts {
		out = append(out, authztypes.TupleKey{User: st.User, Relation: st.Relation, Object: st.Object})
	}
	return out
}

func toConditionalOne(st domain.StructuralTuple, ok bool) []authztypes.TupleKey {
	if !ok {
		return nil
	}
	return toConditional([]domain.StructuralTuple{st})
}
