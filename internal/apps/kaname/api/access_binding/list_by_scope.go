// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_scope.go — ListByScopeUseCase: the read enumerates the bindings on a
// SCOPE anchor (resource_type/resource_id), not a per-object resource target.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
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
// the additive union floor, resolved PER-OBJECT over the page (the previous
// ListObjects enumeration was silently capped at 1000 objects of the type in the
// store, which denied a legitimate grantee outright — internal/authzfilter).
// Anonymous → rejected. FGA error → UNAVAILABLE.
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
	// Non-authority caller: surface only the v_list/viewer-visible subset of the
	// PAGE (D-6 union floor), resolved per-object. Fail-closed on FGA error.
	visible, ok, verr := visibleBindingIDsOnPage(ctx, u.queries, bindingIDs(rows))
	if verr != nil {
		return nil, "", verr
	}
	out := []domain.AccessBinding{}
	if ok {
		out = filterVisibleBindings(rows, visible)
	}
	// Anti-leak deny. The authority precheck that decides it is `hasAuthority`
	// (requireGrantAuthority — owner / FGA scope-admin / cluster-admin), which asks
	// DIRECT per-object Checks and is therefore never truncated. It is combined with
	// "and the scope held nothing visible to you": a caller who is neither an
	// authority nor a grantee must not learn the scope exists, nor receive an empty
	// 200 that distinguishes it from a forbidden one.
	//
	// The second clause is evaluated only when this page is the LAST one
	// (next == ""), i.e. the whole scope has been examined. "Nothing visible ON THIS
	// PAGE" is NOT "no authority at all" — denying a mid-walk page would 403 a
	// legitimate grantee whose bindings simply sort onto a later page. A stranger
	// probing a scope issues an unpaginated first request, which still lands on the
	// deny (a scope smaller than one page has next == "").
	if len(out) == 0 && next == "" {
		return nil, "", authzguard.PermissionDenied()
	}
	return out, next, nil
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
