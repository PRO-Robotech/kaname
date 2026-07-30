// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// list.go — ListProjectsUseCase. RBAC list-filter: subjects
// see the UNION of (projects owned via the parent Account) +
// (projects granted via AccessBinding / FGA `viewer` ∪ `v_list` relations,
// rbac-2026 model).
//
// Resource-existence is never disclosed: a subject with neither
// ownership nor a grant gets an empty list (OK status), not 403.
// Anonymous callers also get an empty list (early-return; the gate is
// kept lenient because the api-gateway authz interceptor is the primary
// authentication boundary).
//
// List-filter behaviour:
//   - subject-prefix is derived from principal.Type (`user:` vs
//     `service_account:`). Hardcoding `"user:"+id` would make the
//     kacho-vpc-operator SA's ListObjects request resolve nothing → operator
//     sees 0 projects.
//   - the FGA branch is fail-closed: an FGA outage returns `Unavailable`, NOT
//     a silent degrade to owner-only (INV-7). A degraded list could
//     under-report to the operator (driving an erroneous ns-prune) or, for
//     FGA-derived visibility, leak/under-report for users.
//
// The owner-via-Account union is intra-account ownership resolution; it is
// retained (a user owning the parent Account sees every project in it), but
// the FGA viewer branch must fail closed.

import (
	"context"
	stderrors "errors"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
)

type ListProjectsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects port resolving AccessBinding/system-viewer
	// grants into project-id sets. When nil the FGA branch fails closed.
	relationQueries clients.RelationQueries
}

func NewListProjectsUseCase(r Repo) *ListProjectsUseCase {
	return &ListProjectsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client used to expand
// AccessBinding-grants / system-viewer into project-id sets.
func (u *ListProjectsUseCase) WithRelationStore(relations clients.RelationQueries) *ListProjectsUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListProjectsUseCase) Execute(ctx context.Context, f project.ListFilter) ([]domain.Project, string, error) {
	// Anonymous short-circuits to empty BEFORE any FGA call (INV-3); an FGA
	// outage never turns an anonymous request into Unavailable.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.Projects().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}

	// Resolve intra-account ownership for the accounts ON THIS PAGE.
	//
	// It used to LIST accounts — one page of them, cluster-wide, oldest first — and
	// keep the ones this principal owns. Two things were wrong with that. It read the
	// whole population to answer a question about at most a page's worth of accounts;
	// and because that read is itself a page, an owner whose account was not among the
	// oldest thousand in the cluster was silently not recognised as an owner at all,
	// so their own projects vanished from their own listing while the rows, the
	// account and the ownership all existed.
	//
	// Asking about the accounts the page actually names is exact and bounded: at most
	// one lookup per DISTINCT account on the page, and no answer depends on how many
	// accounts the cluster holds.
	owned, err := u.ownedAccountsOnPage(ctx, rd, principal, out)
	if err != nil {
		return nil, "", err
	}

	// Resolve FGA-granted visibility for the projects ON THIS PAGE (AccessBinding
	// viewer + SEC-L system-viewer). Fail-closed on FGA error (INV-7).
	granted, err := u.grantedProjectIDs(ctx, principal, projectIDsOf(out))
	if err != nil {
		return nil, "", err
	}

	filtered := out[:0]
	for _, p := range out {
		if owned[p.AccountID] || granted[string(p.ID)] {
			filtered = append(filtered, p)
		}
	}
	return filtered, next, nil
}

// grantedProjectIDs returns which of the given project ids the principal may see
// via the UNION of the FGA `viewer` and `v_list` relations on `project`
// (rbac-2026 model), asked DIRECTLY per object. The `v_list` branch surfaces
// object-only `iam.project.{get,list}` grants (see-in-selector-without-contents):
// the project is listed while a Check on a resource inside it still DENIES.
//
// It used to enumerate every visible project (`ListObjects`), which OpenFGA caps
// server-side at 1000 objects of the type in the store with no continuation
// token — past that population a tenant's own project fell outside the returned
// prefix and disappeared from List. Same predicate, bounded shape; see the
// internal/authzfilter package doc.
//
// Fail-closed: a nil FGA port or an FGA error on ANY object returns Unavailable
// (no silent owner-only degrade) — INV-7.
func (u *ListProjectsUseCase) grantedProjectIDs(ctx context.Context, principal operations.Principal, ids []string) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	granted, err := authzfilter.VisibleSet(ctx, u.relationQueries, subject, "project", ids)
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return granted, nil
}

// projectIDsOf projects a project page to its bare ids.
func projectIDsOf(rows []domain.Project) []string {
	out := make([]string, 0, len(rows))
	for _, p := range rows {
		out = append(out, string(p.ID))
	}
	return out
}

// principalSubject builds the FGA subject string from the principal type:
// `user:<id>` for users, `service_account:<id>` for SAs.
// Any other type yields "" (no resolvable subject → deny).
func principalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}

// ownedAccountsOnPage reports which of the accounts named by the page this
// principal owns, by asking about those accounts and nothing else.
//
// An account that cannot be read is treated as NOT owned rather than as an error:
// the row is then judged by the grant branch alone, which is the fail-closed
// direction. A transport failure of the grant branch still aborts the request — that
// one is the authority.
func (u *ListProjectsUseCase) ownedAccountsOnPage(
	ctx context.Context, rd kachorepo.Reader, principal operations.Principal, page []domain.Project,
) (map[domain.AccountID]bool, error) {
	owned := make(map[domain.AccountID]bool, len(page))
	if principal.ID == "" {
		return owned, nil
	}
	seen := make(map[domain.AccountID]struct{}, len(page))
	for _, p := range page {
		if p.AccountID == "" {
			continue
		}
		if _, dup := seen[p.AccountID]; dup {
			continue
		}
		seen[p.AccountID] = struct{}{}
		acct, err := rd.Accounts().Get(ctx, p.AccountID)
		if err != nil {
			if stderrors.Is(err, iamerr.ErrNotFound) {
				continue // dangling parent: the grant branch decides
			}
			return nil, shared.MapRepoErr(err)
		}
		if string(acct.OwnerUserID) == principal.ID {
			owned[acct.ID] = true
		}
	}
	return owned, nil
}
