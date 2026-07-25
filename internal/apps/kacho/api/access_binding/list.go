// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list.go — ListUseCase (redesign-2026 F11). The single, plain List that
// supersedes the legacy ListByScope/ListBySubject/ListByRole/ListByAccount family.
// Visibility is the caller's `viewer ∪ v_list` set on iam_access_binding, resolved
// PER-OBJECT for the rows on the page.
//
// Order is load-bearing: the page is read from the iam database by cursor FIRST,
// and only its ids are then checked. The reverse order ("enumerate every visible
// binding, then narrow the SQL to that id-set") hit OpenFGA's hard ListObjects
// bound (OPENFGA_LIST_OBJECTS_MAX_RESULTS, default 1000, no continuation token)
// and made a tenant's own bindings vanish from List once the store held more
// objects of the type than the cap — see the internal/authzfilter package doc.
// Side effect of the new order: a page may come back SHORT (some rows filtered
// out). That is normal for cursor pagination — next_page_token is derived from
// the last row EXAMINED, so a full walk still skips nothing. The flip side, and
// it is a deliberate trade: that cursor encodes the (created_at, id) of a row
// the caller may not be able to READ, so a caller who decodes tokens learns one
// binding id + timestamp per page. Content stays gated (Get on such an id still
// answers 403), and this is the same shape kacho-vpc's authzfilter accepts —
// weighed against the alternative, which is the ListObjects cap making a
// tenant's OWN bindings permanently invisible.
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

// Execute reads the page from the iam database by cursor and returns the subset
// of it visible to the caller. The predicate fields on f (subject/role/scope/
// scopeId) narrow the page at the SQL layer; visibility is applied to the rows
// that page yields.
func (u *ListUseCase) Execute(ctx context.Context, f repoab.ListFilter) ([]domain.AccessBinding, string, error) {
	// D-9 flat super-gate (parity with Get / ListByScope / ListByAccount / ListByRole,
	// which all reach it through requireGrantAuthority Path 0): a cluster-admin
	// enumerates the UNFILTERED page. After the access-cascade contraction they hold
	// no per-object viewer/v_list tuple on iam_access_binding, so the per-object
	// filter alone would answer "no grants exist" on the read that supersedes the
	// whole legacy family. Additive — it lifts VISIBILITY only: the declarative
	// subject/role/scope predicates still narrow. nil-safe via the guard inside
	// IsClusterAdmin.
	if u.relations != nil && authzguard.IsClusterAdmin(ctx, u.relations) {
		return readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
			return rd.AccessBindings().List(ctx, f)
		})
	}
	// Page FIRST (the repo also validates page_token/page_size — a second,
	// grant-independent backstop behind the handler's sync guard), per-object
	// visibility SECOND.
	rows, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().List(ctx, f)
	})
	if err != nil {
		return nil, "", err
	}
	if len(rows) == 0 {
		return []domain.AccessBinding{}, next, nil
	}
	// viewer ∪ v_list on the page's iam_access_binding objects. anonymous / unwired
	// → empty (no leak); FGA error → UNAVAILABLE (fail-closed).
	visible, ok, verr := visibleBindingIDsOnPage(ctx, u.queries, bindingIDs(rows))
	if verr != nil {
		return nil, "", verr
	}
	if !ok {
		// Resolver unwired → no visibility is resolvable → empty page. Never an
		// error and never the unfiltered set.
		return []domain.AccessBinding{}, next, nil
	}
	return filterVisibleBindings(rows, visible), next, nil
}
