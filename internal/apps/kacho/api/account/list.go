// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// list.go — ListAccountsUseCase. Sync read с pagination.
//
// The visibility filter is FGA-relation-driven. Instead of the legacy
// owner-only Go post-filter (`OwnerUserID == principal.ID`), the use-case asks
// OpenFGA which account ids the principal may see and returns only those rows.
//
// On the flat explicit model `account` is a verb-bearing
// resource with NO `from account` access-cascade. Visibility is the UNION of
// two direct-tuple sets:
//
//	visible(id) = Check(subject, "viewer", "account:"+id)
//	            ∨ Check(subject, "v_list", "account:"+id)
//
// asked for the accounts ON THE PAGE (the page is read from the iam database by
// cursor first). The previous shape — enumerate every visible account, then
// intersect — was silently truncated by OpenFGA's ListObjects cap; see the
// internal/authzfilter package doc.
//
//   - The `viewer` branch surfaces accounts the principal holds the viewer tier
//     on (owner-binding admin/editor/viewer write-authz anchor). A viewer grant
//     implies broader access.
//   - The `v_list` branch surfaces accounts granted ONLY `iam.account.{get,list}`
//     via a names/labels selector — an OBJECT-ONLY `account:<id> # v_list @ subj`
//     tuple with NO cascade into the account's contents (D-2). This is the
//     owner's original goal: "see the account in the selector WITHOUT access to
//     its contents" — the account is listed while a Check on a project/network
//     inside it still DENIES.
//   - The two sets are deduplicated; an account in both appears once.
//   - There is NO cluster-wide reader floor on this page, and this line used to
//     say the opposite. It claimed the kacho-vpc-operator SA "resolves viewer on
//     EVERY account → sees ALL accounts (floor intact)". That floor was the SEC-L
//     read-cascade `viewer … or system_viewer from cluster`, and Contract-A
//     REMOVED it — fga_model.fga says so on both `account` and `project`. What
//     replaced it was per-object materialisation from the operator's role rules,
//     and those rules resolve to nothing: every one of the four names its role
//     authors (`vpc.subnetses`, `vpc.networks`, `vpc.network_interfaces`,
//     `iam.projectses`) is absent from the closed object-type table, so the
//     reconciler emits no tuple for any of them. Measured, with a control, and
//     pinned by TestSeededRoleRulesResolveOrArePinned.
//     The retirement then happened at the seed, where it belonged: 0076 took the
//     role and its binding, 0081 the identity itself and the cluster tuple it
//     still held. Do NOT widen the predicate here to restore the sentence — a
//     cluster-wide reader floor is a grant, and grants are made at the seed, not
//     conceded by a list filter.
//   - Anonymous short-circuits to empty BEFORE any FGA call.
//   - FGA outage on EITHER relation → fail-closed `Unavailable`: never a
//     full-list leak, never a degraded/partial list.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// ListAccountsUseCase.
type ListAccountsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects port resolving the principal's viewer-set.
	// When nil the use-case fails closed (no unfiltered list ever leaves the
	// service); production wiring always injects it via WithRelationStore.
	relationQueries clients.RelationQueries
}

// NewListAccountsUseCase.
func NewListAccountsUseCase(r Repo) *ListAccountsUseCase {
	return &ListAccountsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client used to resolve the principal's
// `viewer`-relation account-id set. Mirrors ListProjectsUseCase.
func (u *ListAccountsUseCase) WithRelationStore(relations clients.RelationQueries) *ListAccountsUseCase {
	u.relationQueries = relations
	return u
}

// Execute — sync read + cursor pagination, filtered to the principal's FGA
// `viewer`-set. page_size валидируется repo-слоем (default 50, max 1000).
func (u *ListAccountsUseCase) Execute(ctx context.Context, f account.ListFilter) ([]domain.Account, string, error) {
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
	// Anonymous / non-principal → empty (default-deny). Short-circuits BEFORE
	// any FGA call so an FGA outage never turns an anonymous request into
	// Unavailable (INV-3).
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.Accounts().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}

	// Resolve visibility for the accounts ON THIS PAGE (per-object, uncapped).
	visible, err := u.visibleAccountIDs(ctx, principal, accountIDsOf(out))
	if err != nil {
		return nil, "", err
	}

	filtered := out[:0]
	for _, a := range out {
		if visible[string(a.ID)] {
			filtered = append(filtered, a)
		}
	}
	return filtered, next, nil
}

// visibleAccountIDs returns which of the given account ids the principal may
// view, per the UNION of the FGA `viewer` and `v_list` relations on `account`
// on the flat explicit model, asked DIRECTLY per object.
//
// It used to enumerate every visible account (`ListObjects`), which OpenFGA caps
// server-side at 1000 objects of the type in the store with no continuation
// token — past that population a tenant's own account fell outside the returned
// prefix and disappeared from List. The predicate is unchanged (ListObjects
// returns exactly what Check allows); only the shape is bounded to the page.
// See the internal/authzfilter package doc.
//
// Fail-closed: a nil FGA port or an FGA error on ANY object returns Unavailable
// (never an unfiltered/owner-only fallback).
func (u *ListAccountsUseCase) visibleAccountIDs(ctx context.Context, principal operations.Principal, ids []string) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		// Unknown principal type with no resolvable subject → deny.
		return map[string]bool{}, nil
	}
	visible, err := authzfilter.VisibleSet(ctx, u.relationQueries, subject, "account", ids)
	if err != nil {
		// FGA outage / timeout / non-200 → fail-closed Unavailable.
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}

// accountIDsOf projects an account page to its bare ids.
func accountIDsOf(rows []domain.Account) []string {
	out := make([]string, 0, len(rows))
	for _, a := range rows {
		out = append(out, string(a.ID))
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
