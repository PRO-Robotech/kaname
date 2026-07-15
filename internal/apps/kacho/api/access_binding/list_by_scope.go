// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_by_scope.go — ListByScopeUseCase: the read enumerates the bindings on a
// SCOPE anchor (resource_type/resource_id), not a per-object resource target.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListByScopeUseCase struct {
	repo      Repo
	relations clients.RelationStore
	// queries — FGA ListObjects-порт для D-6 union-floor (viewer ∪ v_list на
	// iam_access_binding). nil → только self/granted-floor (back-compat).
	queries clients.RelationQueries
	logger  *slog.Logger
}

func NewListByScopeUseCase(r Repo) *ListByScopeUseCase {
	return &ListByScopeUseCase{repo: r}
}

// WithRelationStore wires the FGA client for the scope-authority check.
func (u *ListByScopeUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListByScopeUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithRelationQueries wires the FGA ListObjects port for the D-6 viewer ∪ v_list
// union floor (label-selectable binding visibility). nil → granted-floor only.
func (u *ListByScopeUseCase) WithRelationQueries(q clients.RelationQueries) *ListByScopeUseCase {
	u.queries = q
	return u
}

// Execute — D-6 visibility: a grant-authority on the scope (owner / FGA-admin /
// cluster-admin) enumerates ALL bindings on the scope (the existing granted-floor,
// NOT shrunk). A non-authority caller still sees the bindings on the scope made
// visible to them by a label-selector grant (viewer ∪ v_list on iam_access_binding) —
// the additive union floor. Anonymous → rejected. FGA error → UNAVAILABLE.
func (u *ListByScopeUseCase) Execute(ctx context.Context, resourceType domain.ResourceType, resourceID string, f repoab.PageFilter) ([]domain.AccessBinding, string, error) {
	// Reject anonymous callers — listing bindings on a scope leaks structure.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}
	// granted-floor: owner / FGA-admin / cluster-admin enumerate the FULL scope.
	hasAuthority := requireGrantAuthority(ctx, u.repo, u.relations, string(resourceType), resourceID) == nil

	rows, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListByScope(ctx, resourceType, resourceID, f)
	})
	if err != nil {
		return nil, "", err
	}
	if hasAuthority {
		return rows, next, nil
	}
	// Non-authority caller: surface only the v_list/viewer-visible subset (D-6 union
	// floor). Fail-closed on FGA error. A caller with NO label visibility at all
	// (empty set, or the resolver unwired) → PermissionDenied — preserving the
	// existing anti-leak contract (a total stranger must not learn the scope exists,
	// nor receive an empty 200 that distinguishes it from a forbidden one).
	visible, ok, verr := vlistVisibleBindingIDs(ctx, u.queries)
	if verr != nil {
		return nil, "", verr
	}
	if !ok || len(visible) == 0 {
		return nil, "", authzguard.PermissionDenied()
	}
	return filterVisibleBindings(rows, visible), next, nil
}

// filterVisibleBindings keeps only the bindings whose id is in the visible set.
func filterVisibleBindings(rows []domain.AccessBinding, visible map[string]bool) []domain.AccessBinding {
	out := rows[:0]
	for _, b := range rows {
		if visible[string(b.ID)] {
			out = append(out, b)
		}
	}
	return out
}
