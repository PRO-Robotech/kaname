// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// structural_facts_repo.go — the structural columns of MANY rows of one object type,
// read on ONE primary snapshot.
//
// # WHY A BATCH READ EXISTS AT ALL
//
// The per-object reader (Repository.ReaderFromPrimary, used by internal/authzcascade)
// costs one transaction and at most three primary-key lookups. That is the right shape
// for a gate about ONE object. It is the wrong shape for a page: page size is part of
// the contract (up to 1000), the page filter asks a per-object question for every row,
// and measuring it (authzcascade/page_cost_integration_test.go) put a page of 100
// denials at 200 transactions and 1000 statements. Multiplying that by ten — which the
// contract allows and narrowing the page to avoid is forbidden — leaves no request
// budget, so the page needs a read whose cost does not grow with it.
//
// # WHY IT IS POOL-DIRECT AND NOT ON kacho.Reader
//
// Adding a batch getter to each resource ReaderIface would change seven interfaces that
// every mock in the tree implements, for a caller that wants three columns and no
// entity. The conditions repository is already pool-direct for the same kind of reason.
// What matters for correctness is that the PROJECTION is not duplicated: this file reads
// columns and then calls the SAME domain functions the per-object resolver and the outbox
// emitter call (domain/structural_tuple.go). There is one statement of what a structural
// fact IS, and three readers of it.
//
// The equivalence is not left to inspection — authzcascade's batch test asserts that the
// batched facts and the per-object facts are IDENTICAL for the same ids, so a divergence
// between the two read paths fails a test rather than changing an authorization answer
// on pages only.
package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// StructuralFactsRepo opens read-only snapshots on the PRIMARY.
//
// Primary, never a replica, for the same reason the per-object reader is: the rows a
// cascade decision reads are by construction ones that were just committed, which is
// precisely what a replica lags on. Reading them from a replica would swap one delivery
// pipeline for another while claiming to depend on none.
type StructuralFactsRepo struct{ pool *pgxpool.Pool }

// NewStructuralFactsRepo — composition-root constructor. The pool is the MASTER pool.
func NewStructuralFactsRepo(pool *pgxpool.Pool) *StructuralFactsRepo {
	return &StructuralFactsRepo{pool: pool}
}

// StructuralSnapshot opens ONE read-only transaction. Several FactsByIDs calls on it see
// ONE state of the hierarchy — a chain read across separate transactions can see a torn
// one (a binding's project from before a move, that project's account from after it),
// and the facts handed to the relation store would then describe a shape that never
// existed.
//
// The caller MUST Close it.
func (r *StructuralFactsRepo) StructuralSnapshot(ctx context.Context) (*Snapshot, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	return &Snapshot{tx: tx}, nil
}

// Snapshot — one read-only transaction over the structural columns.
type Snapshot struct{ tx pgx.Tx }

// Close releases the connection. Read-only, so there is nothing to commit; errors are
// discarded deliberately — a failed rollback on a read-only transaction has no effect a
// caller could act on, and reporting it would displace the real error of the read.
func (s *Snapshot) Close(ctx context.Context) {
	if s == nil || s.tx == nil {
		return
	}
	_ = s.tx.Rollback(ctx)
}

// accountScopedTables — object types whose structural fact is a single account pointer,
// mapped to the table holding it. A CLOSED map, so the type name can never reach the
// statement text as anything but a key that was found here.
var accountScopedTables = map[string]string{
	"iam_user":            "users",
	"iam_group":           "groups",
	"iam_role":            "roles",
	"iam_service_account": "service_accounts",
}

// FactsByIDs returns the structural facts of the named rows, keyed by object id.
//
// Only ids that HAVE a row appear in the result. An id with no row is not an error —
// iam is legitimately asked about ids that were never its own — and its absence from the
// map is how the caller learns that.
//
// A row whose projection yields nothing (a system role with no owning account, an
// account with no owner recorded) appears with an EMPTY slice: "read, and there is
// nothing to say" is a different fact from "not read", and collapsing the two would make
// the caller pay a second read for every such row.
func (s *Snapshot) FactsByIDs(
	ctx context.Context, objectType string, ids []string,
) (map[string][]domain.StructuralTuple, error) {
	if s == nil || s.tx == nil || len(ids) == 0 {
		return nil, nil
	}
	switch objectType {
	case "account":
		return s.scan(ctx,
			`SELECT id, COALESCE(owner_user_id, '') FROM kacho_iam.accounts WHERE id = ANY($1)`, ids,
			func(id, owner string) []domain.StructuralTuple {
				return domain.Account{ID: domain.AccountID(id), OwnerUserID: domain.UserID(owner)}.StructuralFacts()
			})
	case "project":
		return s.scan(ctx,
			`SELECT id, COALESCE(account_id, '') FROM kacho_iam.projects WHERE id = ANY($1)`, ids,
			func(id, accountID string) []domain.StructuralTuple {
				return domain.Project{ID: domain.ProjectID(id), AccountID: domain.AccountID(accountID)}.StructuralFacts()
			})
	case "iam_access_binding":
		return s.scanBinding(ctx, ids)
	case "iam_condition":
		return s.scan(ctx,
			`SELECT id, COALESCE(project_id, '') FROM kacho_iam.conditions WHERE id = ANY($1)`, ids,
			func(id, projectID string) []domain.StructuralTuple {
				return oneFact(domain.ProjectScopedStructuralFact(projectID, "iam_condition", id))
			})
	}
	table, ok := accountScopedTables[objectType]
	if !ok {
		return nil, nil // not a type this repository can speak about
	}
	return s.scan(ctx,
		//nolint:gosec // table comes from the closed accountScopedTables map above, never from input.
		fmt.Sprintf(`SELECT id, COALESCE(account_id, '') FROM kacho_iam.%s WHERE id = ANY($1)`, table), ids,
		func(id, accountID string) []domain.StructuralTuple {
			return oneFact(domain.AccountScopedStructuralFact(accountID, objectType, id))
		})
}

// scan runs a two-column (id, parent) statement and projects each row.
func (s *Snapshot) scan(
	ctx context.Context, sql string, ids []string,
	project func(id, parent string) []domain.StructuralTuple,
) (map[string][]domain.StructuralTuple, error) {
	rows, err := s.tx.Query(ctx, sql, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]domain.StructuralTuple, len(ids))
	for rows.Next() {
		var id, parent string
		if serr := rows.Scan(&id, &parent); serr != nil {
			return nil, serr
		}
		facts := project(id, parent)
		if facts == nil {
			facts = []domain.StructuralTuple{}
		}
		out[id] = facts
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return out, nil
}

// scanBinding is the one three-column shape: a binding names its scope's TYPE as well as
// its id.
func (s *Snapshot) scanBinding(
	ctx context.Context, ids []string,
) (map[string][]domain.StructuralTuple, error) {
	rows, err := s.tx.Query(ctx,
		`SELECT id, COALESCE(resource_type, ''), COALESCE(resource_id, '')
		   FROM kacho_iam.access_bindings WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]domain.StructuralTuple, len(ids))
	for rows.Next() {
		var id, scopeType, scopeID string
		if serr := rows.Scan(&id, &scopeType, &scopeID); serr != nil {
			return nil, serr
		}
		out[id] = oneFact(domain.AccessBinding{
			ID:           domain.AccessBindingID(id),
			ResourceType: domain.ResourceType(scopeType),
			ResourceID:   scopeID,
		}.StructuralParent())
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	return out, nil
}

// oneFact normalises the (tuple, ok) projections into a slice, keeping "read, nothing to
// say" distinguishable from "not read" by returning an empty slice rather than nil.
func oneFact(st domain.StructuralTuple, ok bool) []domain.StructuralTuple {
	if !ok {
		return []domain.StructuralTuple{}
	}
	return []domain.StructuralTuple{st}
}
