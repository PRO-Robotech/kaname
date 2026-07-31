// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// list.go — ListRolesUseCase: per-object scope-filtered RoleService.List.
//
// The Role catalog has TWO visibility layers:
//   - System roles (is_system) are the tenant-wide reference floor — every
//     authenticated principal sees them (RoleService.Get is <exempt>). They are
//     NOT subject to the per-object filter.
//   - CUSTOM roles are filtered per-object via the UNION of the FGA `viewer` and
//     `v_list` relations on iam_role, asked DIRECTLY for the roles ON THE PAGE —
//     parity with account/project List. The `viewer` tier on
//     iam_role cascades from the ACCOUNT tier (account.admin→editor→viewer), so a
//     role's creator / account-admin resolves visibility on every role
//     hierarchy-linked to their account; the `v_list` branch surfaces an
//     OBJECT-ONLY selector grant (`iam_role:<id> # v_list @ subj`, no viewer
//     cascade) — the see-in-selector-without-content path. A foreign account
//     resolves neither (no existence leak). The SAME resolver backs
//     RoleService.Get so List == Get for custom roles (read==enforce).
//
//     Design-B (flat-authz verb-bearing complete): v_* are DECOUPLED from the tier
//     relations (no viewer ⊇ v_list union in the FGA model), so a v_list-only
//     selector grant does NOT resolve `viewer`. A viewer-only filter therefore hid
//     such a grant from its grantee; the viewer ∪ v_list union surfaces it while
//     content (v_get) stays gated. The owner sees their own role via the viewer
//     branch (account-tier cascade).
//
// Order is load-bearing: the page is read from the iam database by cursor FIRST,
// and only the CUSTOM roles it yields are then checked. The reverse order
// ("enumerate every visible role, then narrow the SQL to that id-set") hit
// OpenFGA's hard ListObjects bound (OPENFGA_LIST_OBJECTS_MAX_RESULTS, default
// 1000, no continuation token) and made a tenant's own custom roles vanish once
// the store held more iam_role objects than the cap — see the
// internal/authzfilter package doc. Side effect: a page may come back SHORT
// (some rows filtered out), which is normal for cursor pagination —
// next_page_token is derived from the last row EXAMINED, so a full walk still
// skips nothing.
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	reporole "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
)

type ListRolesUseCase struct {
	repo Repo
	// relationQueries — FGA port resolving the principal's `viewer ∪ v_list`
	// visibility on the iam_role objects of a page. When nil the use-case fails
	// closed.
	relationQueries clients.RelationQueries
}

func NewListRolesUseCase(r Repo) *ListRolesUseCase {
	return &ListRolesUseCase{repo: r}
}

// WithRelationStore wires the FGA client used to resolve the principal's
// readable-role visibility on iam_role. Mirrors ListAccountsUseCase /
// ListProjectsUseCase.
func (u *ListRolesUseCase) WithRelationStore(relations clients.RelationQueries) *ListRolesUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListRolesUseCase) Execute(ctx context.Context, f reporole.ListFilter) ([]domain.Role, string, error) {
	// Формат пагинации — ПЕРВЫМ стейтментом, до решения о том, кто спрашивает.
	//
	// Ниже стоит замыкание по личности: анонимный (в том числе непроброшенный)
	// вызывающий получает пустую страницу и до репозитория не доходит. Пока
	// формат курсора проверял только репозиторий, один и тот же мусорный
	// page_token получал разный ответ в зависимости от того, опознан ли
	// вызывающий, — то есть проверка ввода зависела от прав. Репозиторий
	// остаётся авторитетным на служимом пути.
	if err := shared.ValidatePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}
	// Anonymous → empty (default-deny) BEFORE any FGA call so an FGA outage never
	// turns an anonymous request into Unavailable.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	// Unwired FGA port → fail closed BEFORE touching the database: no visibility
	// is resolvable at all, so the page could only be served unfiltered (a catalog
	// leak) or discarded. This is NOT the grant-state short-circuit the pagination
	// convention orders after format validation — both page_size and page_token
	// are validated by the first statement of this use-case above (the repo
	// re-validates them on the served path).
	//
	// Прежняя редакция этого комментария относила обе проверки к хендлеру. Для
	// page_size это было верно, для page_token — нет: его не проверял никто до
	// репозитория, а до репозитория анонимный вызывающий не доходил.
	if u.relationQueries == nil {
		return nil, "", shared.MapRepoErr(iamerr.ErrUnavailable)
	}

	// Page FIRST, per-object visibility SECOND (see the file doc for why the
	// reverse order was unsound).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.Roles().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}

	// Resolve visibility for the CUSTOM roles on this page. System roles are the
	// tenant-wide catalog floor and bypass the filter entirely; a page carrying
	// only system roles costs no FGA call at all.
	visible, err := resolveVisibleRoleIDs(ctx, u.relationQueries, principal, customRoleIDs(out))
	if err != nil {
		return nil, "", err
	}
	filtered := out[:0]
	for _, r := range out {
		if r.IsSystem || visible[string(r.ID)] {
			filtered = append(filtered, r)
		}
	}
	// redesign-2026 F6: present the canonical system-role catalog first — system
	// roles ahead of custom, and among system the canonical four in
	// viewer→editor→admin→owner order (domain.CanonicalRank). Stable, so the repo's
	// (created_at,id) keyset order is preserved within each rank group; this is a
	// presentation refinement over the authoritative keyset page.
	sortCatalogFirst(filtered)
	return filtered, next, nil
}

// customRoleIDs projects a role page to the ids of its CUSTOM roles — the only
// ones subject to the per-object visibility filter (system roles are the catalog
// floor).
func customRoleIDs(roles []domain.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if !r.IsSystem {
			out = append(out, string(r.ID))
		}
	}
	return out
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

// resolveVisibleRoleIDs returns which of the given CUSTOM-role ids the principal
// can read — the UNION of the FGA `viewer` and `v_list` relations on iam_role,
// asked DIRECTLY per object:
//
//		visible(id) = Check(subject, "viewer", "iam_role:"+id)
//		            ∨ Check(subject, "v_list", "iam_role:"+id)
//
//	  - The `viewer` branch surfaces roles the principal resolves the viewer tier on
//	    (the account-admin's own roles via the account-tier cascade; viewer implies
//	    content access). On the decoupled Design-B model v_* are NOT union-ed into
//	    tier, so viewer alone never surfaces an object-only v_list grant.
//	  - The `v_list` branch surfaces roles granted ONLY `iam.roles.{get,list}` via a
//	    names/labels selector — an OBJECT-ONLY `iam_role:<id> # v_list @ subj` tuple
//	    with NO viewer-tier cascade (see-in-selector-without-content).
//
// The predicate is unchanged from the ListObjects enumeration this replaces
// (ListObjects returns, by definition, what Check would allow). What changed is
// the SHAPE: OpenFGA caps ListObjects server-side at 1000 objects of the type in
// the store with no continuation token, so past that population a role's own
// grantee fell outside the returned prefix — List dropped the role and Get
// answered NOT_FOUND, permanently (internal/authzfilter package doc).
//
// Fail-closed: a nil FGA port or an FGA error on ANY object → Unavailable; an
// unresolvable subject → empty set (system roles still served).
//
// Shared by ListRolesUseCase (filter the custom roles on a page) AND
// GetRoleUseCase (enforce a single custom role) so the two read surfaces draw
// from the IDENTICAL FGA question — Get can never serve a custom role absent
// from List (no existence leak).
func resolveVisibleRoleIDs(ctx context.Context, relationQueries clients.RelationQueries, principal operations.Principal, ids []string) (map[string]bool, error) {
	if relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil // unknown principal → only system catalog floor
	}
	visible, err := authzfilter.VisibleSet(ctx, relationQueries, subject, fgaRoleObjectType, ids)
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}

// fgaRoleObjectType — the OpenFGA object type of a Role.
const fgaRoleObjectType = "iam_role"

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
