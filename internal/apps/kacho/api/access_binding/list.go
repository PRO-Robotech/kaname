// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list.go — ListUseCase (redesign-2026 F11). The single, plain List that
// supersedes the legacy ListByScope/ListBySubject/ListByRole/ListByAccount family.
// Visibility is the caller's `viewer ∪ v_list` set on iam_access_binding, pushed
// down into the SQL as a VisibleIDs constraint so keyset pagination stays dense.
//
// Contract (IAM-1-32):
//   - cluster-admin (D-9 super-gate) → the UNFILTERED page (they hold no per-object
//     tuple after the access-cascade contraction; parity with every sibling read);
//   - anonymous / no visible bindings → empty page (never a leak, never an error);
//   - FGA error → UNAVAILABLE (fail-closed — never an unfiltered result);
//   - page format (page_token/page_size) is validated in the handler BEFORE this
//     use-case runs, so a garbage token / page_size>1000 is INVALID_ARGUMENT
//     independent of grant state.

import (
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"

	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ListUseCase struct {
	repo Repo
	// queries — FGA ListObjects port resolving the caller's viewer ∪ v_list
	// visible bindings. nil → the use-case fails closed to an empty page (no
	// visibility resolvable), never an unfiltered leak.
	queries clients.RelationQueries
	// relations — FGA Check port backing the D-9 cluster-admin super-gate. nil-safe
	// (unwired → the gate is never taken and only the per-object floor runs).
	relations clients.RelationStore
}

func NewListUseCase(r Repo) *ListUseCase {
	return &ListUseCase{repo: r}
}

// WithRelationQueries wires the FGA ListObjects port (viewer ∪ v_list floor).
func (u *ListUseCase) WithRelationQueries(q clients.RelationQueries) *ListUseCase {
	u.queries = q
	return u
}

// WithRelationStore wires the FGA Check port for the D-9 cluster-admin super-gate.
// After the access-cascade contraction a cluster super-admin holds NO per-object
// viewer/v_list tuple on iam_access_binding (helpers.go requireGrantAuthority Path 0),
// so the per-object push-down alone would hand them an empty page — diverging from
// Get / ListByScope / ListByAccount / ListByRole, which all run requireGrantAuthority.
// nil-safe.
//
// No logger parameter (unlike the sibling builders): IsClusterAdmin swallows the FGA
// error into a fail-closed false, so there is nothing here to diagnose — an unused
// field would be dead weight.
func (u *ListUseCase) WithRelationStore(relations clients.RelationStore) *ListUseCase {
	u.relations = relations
	return u
}

// Execute resolves the caller's visible binding set, pushes it into the repo List
// as a dense keyset constraint, and returns the filtered page. The predicate fields
// on f (subject/role/scope/scopeId) are AND-combined with the visibility set.
func (u *ListUseCase) Execute(ctx context.Context, f repoab.ListFilter) ([]domain.AccessBinding, string, error) {
	// D-9 flat super-gate (parity with Get / ListByScope / ListByAccount / ListByRole,
	// which all reach it through requireGrantAuthority Path 0): a cluster-admin
	// enumerates the UNFILTERED page. After the access-cascade contraction they hold
	// no per-object viewer/v_list tuple on iam_access_binding, so the per-object
	// push-down alone would answer "no grants exist" on the read that supersedes the
	// whole legacy family. Additive — it lifts VISIBILITY only: f.VisibleIDs stays nil
	// (the repo then drops the `id = ANY(...)` constraint and keeps the dense
	// (created_at,id) keyset), while the declarative subject/role/scope predicates
	// still narrow. nil-safe via the guard inside IsClusterAdmin.
	if u.relations != nil && authzguard.IsClusterAdmin(ctx, u.relations) {
		return readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
			return rd.AccessBindings().List(ctx, f)
		})
	}
	// viewer ∪ v_list on iam_access_binding. anonymous / unwired → empty (no leak);
	// FGA error → UNAVAILABLE (fail-closed).
	visible, ok, err := vlistVisibleBindingIDs(ctx, u.queries)
	if err != nil {
		return nil, "", err
	}
	if !ok || len(visible) == 0 {
		// No resolvable visibility → empty page (anonymous / no grants). Never an
		// error and never the unfiltered set.
		return []domain.AccessBinding{}, "", nil
	}
	f.VisibleIDs = visibleIDsSlice(visible)

	return readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().List(ctx, f)
	})
}

// visibleIDsSlice materializes the visible-id set as a (non-nil) slice for the
// SQL `id = ANY($n)` push-down.
func visibleIDsSlice(visible map[string]bool) []string {
	out := make([]string, 0, len(visible))
	for id := range visible {
		out = append(out, id)
	}
	return out
}
