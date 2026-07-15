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
//	visible = ListObjects(subject, "viewer", "account")
//	        ∪ ListObjects(subject, "v_list", "account")
//
//   - The `viewer` branch surfaces accounts the principal holds the viewer tier
//     on (owner-binding admin/editor/viewer write-authz anchor; the operator's
//     system_viewer floor). A viewer grant implies broader access.
//   - The `v_list` branch surfaces accounts granted ONLY `iam.account.{get,list}`
//     via a names/labels selector — an OBJECT-ONLY `account:<id> # v_list @ subj`
//     tuple with NO cascade into the account's contents (D-2). This is the
//     owner's original goal: "see the account in the selector WITHOUT access to
//     its contents" — the account is listed while a Check on a project/network
//     inside it still DENIES.
//   - The two sets are deduplicated; an account in both appears once.
//   - The kacho-vpc-operator SA (seeded `system_viewer@cluster:cluster_kacho_root`)
//     resolves viewer on EVERY account → sees ALL accounts (floor intact).
//   - Anonymous short-circuits to empty BEFORE any FGA call.
//   - FGA outage on EITHER relation → fail-closed `Unavailable`: never a
//     full-list leak, never a degraded/partial list.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
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

	// Resolve the principal's FGA viewer-set and intersect with the page.
	visible, err := u.visibleAccountIDs(ctx, principal)
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

// visibleAccountIDs returns the set of account ids the principal may view,
// per the UNION of the FGA `viewer` and `v_list` relation sets on `account`
// on the flat explicit model. Fail-closed: a nil FGA port or an FGA error on
// EITHER relation returns Unavailable (never an unfiltered/owner-only fallback).
func (u *ListAccountsUseCase) visibleAccountIDs(ctx context.Context, principal operations.Principal) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		// Unknown principal type with no resolvable subject → deny.
		return map[string]bool{}, nil
	}
	visible := map[string]bool{}
	// viewer ∪ v_list — the v_list branch surfaces object-only grants
	// (see-in-selector-without-contents); both fail closed on error.
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := u.relationQueries.ListObjects(ctx, subject, relation, "account", nil, 0)
		if err != nil {
			// FGA outage / timeout / non-200 → fail-closed Unavailable.
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			visible[id] = true
		}
	}
	return visible, nil
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
