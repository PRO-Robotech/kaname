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

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	accountrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
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

	// Resolve owner-visible accounts (intra-account ownership; unchanged).
	accts, _, err := rd.Accounts().List(ctx, accountListFilter())
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	owned := make(map[domain.AccountID]bool, len(accts))
	for _, a := range accts {
		if string(a.OwnerUserID) == principal.ID {
			owned[a.ID] = true
		}
	}

	// Resolve FGA-granted project ids (AccessBinding viewer + SEC-L
	// system-viewer). Fail-closed on FGA error (INV-7).
	granted, err := u.grantedProjectIDs(ctx, principal)
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

// grantedProjectIDs returns the project ids the principal may see via the UNION
// of the FGA `viewer` and `v_list` relation sets on `project` (rbac-2026 model).
// The `v_list` branch surfaces object-only `iam.project.{get,list}` grants
// (see-in-selector-without-contents): the project is listed while a Check
// on a resource inside it still DENIES. Fail-closed: a nil FGA port or an FGA
// error on EITHER relation returns Unavailable (no silent owner-only degrade) —
// INV-7.
func (u *ListProjectsUseCase) grantedProjectIDs(ctx context.Context, principal operations.Principal) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	granted := map[string]bool{}
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := u.relationQueries.ListObjects(ctx, subject, relation, "project", nil, 0)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			granted[id] = true
		}
	}
	return granted, nil
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

// accountListFilter — minimal ListFilter без pagination (для inline-load
// всех accounts при post-filter Projects.List).
func accountListFilter() accountrepo.ListFilter {
	return accountrepo.ListFilter{PageSize: 1000}
}
