// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// list.go — ListRolesUseCase: per-object scope-filtered RoleService.List.
//
// The Role catalog has TWO visibility layers:
//   - System roles (is_system) are the tenant-wide reference floor — every
//     authenticated principal sees them (RoleService.Get is <exempt>). They are
//     NOT subject to the per-object filter.
//   - CUSTOM roles are filtered per-object via the UNION of FGA
//     ListObjects(subject, "viewer", "iam_role") ∪ ListObjects(subject, "v_list",
//     "iam_role") — parity with account/project List. The `viewer` tier on
//     iam_role cascades from the ACCOUNT tier (account.admin→editor→viewer), so a
//     role's creator / account-admin resolves visibility on every role
//     hierarchy-linked to their account; the `v_list` branch surfaces an
//     OBJECT-ONLY selector grant (`iam_role:<id> # v_list @ subj`, no viewer
//     cascade) — the see-in-selector-without-content path. A foreign account
//     resolves neither (no existence leak). The visible-id set is pushed into the
//     repo `WHERE (is_system OR id = ANY(...))` (ListFilter.VisibleIDs) so keyset
//     pagination is dense over the filtered set, and the SAME resolver
//     backs RoleService.Get so List == Get for custom roles (read==enforce).
//
//     Design-B (flat-authz verb-bearing complete): v_* are DECOUPLED from the tier
//     relations (no viewer ⊇ v_list union in the FGA model), so a v_list-only
//     selector grant does NOT resolve `viewer`. A viewer-only filter therefore hid
//     such a grant from its grantee; the viewer ∪ v_list union surfaces it while
//     content (v_get) stays gated. The owner sees their own role via the viewer
//     branch (account-tier cascade).
//
// f.AccountID (set by the handler from req.account_id) scopes the catalog
// to system + that Account's custom roles at the SQL layer.
//
// Fail-closed: a nil FGA port or an FGA error → Unavailable (never an unfiltered
// catalog leak, never an owner-only fallback).

import (
	"context"
	"sort"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type ListRolesUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects port resolving the principal's `viewer`
	// (readable-role) set on iam_role. When nil the use-case fails closed.
	relationQueries clients.RelationQueries
}

func NewListRolesUseCase(r Repo) *ListRolesUseCase {
	return &ListRolesUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client used to resolve the
// principal's readable-role (`viewer` tier) set on iam_role. Mirrors
// ListAccountsUseCase / ListProjectsUseCase (which already filter by `viewer`).
func (u *ListRolesUseCase) WithRelationStore(relations clients.RelationQueries) *ListRolesUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListRolesUseCase) Execute(ctx context.Context, f reporole.ListFilter) ([]domain.Role, string, error) {
	// Anonymous → empty (default-deny) BEFORE any FGA call so an FGA outage never
	// turns an anonymous request into Unavailable.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	// Resolve the principal's per-object visible custom-role id set (fail-closed).
	// System roles bypass this set in the repo (catalog floor). The SAME resolver
	// backs RoleService.Get's custom-role enforcement, so List-visibility ==
	// Get-success for custom roles (read==enforce — single source of truth).
	visible, err := resolveVisibleRoleIDs(ctx, u.relationQueries, principal)
	if err != nil {
		return nil, "", err
	}
	f.VisibleIDs = visible

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.Roles().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	// redesign-2026 F6: present the canonical system-role catalog first — system
	// roles ahead of custom, and among system the canonical four in
	// viewer→editor→admin→owner order (domain.CanonicalRank). Stable, so the repo's
	// (created_at,id) keyset order is preserved within each rank group; this is a
	// presentation refinement over the authoritative keyset page.
	sortCatalogFirst(out)
	return out, next, nil
}

// sortCatalogFirst stably orders a role page: system roles first, then by canonical
// rank (viewer<editor<admin<owner<other), preserving the incoming (created_at,id)
// order within equal keys.
func sortCatalogFirst(roles []domain.Role) {
	sort.SliceStable(roles, func(i, j int) bool {
		si, sj := roles[i].IsSystemDerived(), roles[j].IsSystemDerived()
		if si != sj {
			return si // system roles first
		}
		return roles[i].CanonicalRank() < roles[j].CanonicalRank()
	})
}

// resolveVisibleRoleIDs returns the custom-role id set the principal can read —
// the UNION of the FGA `viewer` and `v_list` relation sets on iam_role:
//
//		visible(iam_role) = ListObjects(subject, "viewer", "iam_role")
//		                  ∪ ListObjects(subject, "v_list", "iam_role")
//
//	  - The `viewer` branch surfaces roles the principal resolves the viewer tier on
//	    (the account-admin's own roles via the account-tier cascade; viewer implies
//	    content access). On the decoupled Design-B model v_* are NOT union-ed into
//	    tier, so viewer alone never surfaces an object-only v_list grant.
//	  - The `v_list` branch surfaces roles granted ONLY `iam.roles.{get,list}` via a
//	    names/labels selector — an OBJECT-ONLY `iam_role:<id> # v_list @ subj` tuple
//	    with NO viewer-tier cascade (see-in-selector-without-content). The
//	    viewer-only pre-Design-B filter hid such a grant from its grantee.
//	  - The two sets are deduplicated; a role in both appears once.
//
// Returns a non-nil slice (possibly empty) so the repo applies the per-object
// constraint to custom roles. Fail-closed: a nil FGA port or an FGA error on
// EITHER relation → Unavailable; an unresolvable subject → empty set
// (system roles still served).
//
// Shared by ListRolesUseCase (filter custom roles) AND GetRoleUseCase (enforce a
// single custom role) so the two read surfaces draw from the IDENTICAL FGA query
// — Get can never serve a custom role absent from List (no existence leak).
func resolveVisibleRoleIDs(ctx context.Context, relationQueries clients.RelationQueries, principal operations.Principal) ([]string, error) {
	if relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return []string{}, nil // unknown principal → only system catalog floor
	}
	seen := map[string]struct{}{}
	out := []string{} // non-nil so the repo applies the per-object constraint
	// viewer ∪ v_list — both fail closed on error (never a partial/owner-only list).
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := relationQueries.ListObjects(ctx, subject, relation, "iam_role", nil, 0)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out, nil
}

// principalSubject builds the FGA subject string from the principal type:
// `user:<id>` for users, `service_account:<id>` for SAs. Any other type → ""
// (no resolvable subject → only the system catalog floor).
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
