// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list.go — ListUseCase (redesign-2026 F11). The single, plain List that
// supersedes the legacy ListByScope/ListBySubject/ListByRole/ListByAccount family.
// Visibility is the caller's `viewer ∪ v_list` set on iam_access_binding, pushed
// down into the SQL as a VisibleIDs constraint so keyset pagination stays dense.
//
// Contract (IAM-1-32):
//   - anonymous / no visible bindings → empty page (never a leak, never an error);
//   - FGA error → UNAVAILABLE (fail-closed — never an unfiltered result);
//   - page format (page_token/page_size) is validated in the handler BEFORE this
//     use-case runs, so a garbage token / page_size>1000 is INVALID_ARGUMENT
//     independent of grant state.

import (
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"

	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ListUseCase struct {
	repo Repo
	// queries — FGA ListObjects port resolving the caller's viewer ∪ v_list
	// visible bindings. nil → the use-case fails closed to an empty page (no
	// visibility resolvable), never an unfiltered leak.
	queries clients.RelationQueries
}

func NewListUseCase(r Repo) *ListUseCase {
	return &ListUseCase{repo: r}
}

// WithRelationQueries wires the FGA ListObjects port (viewer ∪ v_list floor).
func (u *ListUseCase) WithRelationQueries(q clients.RelationQueries) *ListUseCase {
	u.queries = q
	return u
}

// Execute resolves the caller's visible binding set, pushes it into the repo List
// as a dense keyset constraint, and returns the filtered page. The predicate fields
// on f (subject/role/scope/scopeId) are AND-combined with the visibility set.
func (u *ListUseCase) Execute(ctx context.Context, f repoab.ListFilter) ([]domain.AccessBinding, string, error) {
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
