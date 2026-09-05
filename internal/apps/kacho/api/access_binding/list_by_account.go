// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_account.go — ListByAccountUseCase.
//
// Admin path: returns every AccessBinding inside an Account's scope (direct
// + project-attached) so an account-admin can audit every subject with any
// access to the account, not only their own grants.
//
// Authorisation (handler-level — catalog declares `admin` relation on
// `account` but we still enforce at the use-case layer in case the gateway
// catalog drifts):
//   - account owner — allowed via authzguard.IsSelf on Account.OwnerUserID.
//   - FGA `admin` on `account:<id>` — allowed via a Check against the rights
//     model (delegated administration; mirrors requireGrantAuthority's Path 2).
//   - everyone else — PermissionDenied.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
)

type ListByAccountUseCase struct {
	repo      Repo
	relations clients.RelationStore
	// queries — FGA ListObjects-порт для D-6 union-floor (viewer ∪ v_list на
	// iam_access_binding). nil → только account-admin floor (back-compat).
	queries clients.RelationQueries
	logger  *slog.Logger
}

func NewListByAccountUseCase(r Repo) *ListByAccountUseCase {
	return &ListByAccountUseCase{repo: r}
}

// WithRelationStore wires the FGA client for delegated-admin authority check.
// When unset (unit tests / degraded mode) only owner-based access is allowed.
func (u *ListByAccountUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListByAccountUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithRelationQueries wires the FGA ListObjects port for the D-6 viewer ∪ v_list
// union floor. nil → account-admin floor only.
func (u *ListByAccountUseCase) WithRelationQueries(q clients.RelationQueries) *ListByAccountUseCase {
	u.queries = q
	return u
}

// Execute — D-6 visibility on the account-audit list: an account-admin (owner /
// FGA-admin / cluster-admin) sees EVERY binding in the account (the existing admin
// floor, NOT shrunk). A non-admin caller sees only the bindings made visible by a
// label-selector grant (viewer ∪ v_list on iam_access_binding) — the additive union
// floor, resolved PER-OBJECT over the page rather than by the server-capped
// ListObjects enumeration it replaces (internal/authzfilter). Anonymous → rejected.
// FGA error → UNAVAILABLE.
func (u *ListByAccountUseCase) Execute(
	ctx context.Context,
	accountID string,
	f repoab.AccountPageFilter,
) ([]domain.AccessBinding, string, error) {
	if err := shared.ValidateResourceID(accountID, domain.PrefixAccount, "account"); err != nil {
		return nil, "", err
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}
	isAdmin := requireGrantAuthority(ctx, u.repo, u.relations, "account", accountID) == nil

	// E-34: fill subjects[] on the account-audit list too (shared read skeleton).
	rows, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListByAccount(ctx, domain.AccountID(accountID), f)
	})
	if err != nil {
		return nil, "", err
	}
	if isAdmin {
		return rows, next, nil
	}
	visible, ok, verr := visibleBindingIDsOnPage(ctx, u.queries, bindingIDs(rows))
	if verr != nil {
		return nil, "", verr
	}
	out := []domain.AccessBinding{}
	if ok {
		out = filterVisibleBindings(rows, visible)
	}
	// No admin floor and nothing visible in the WHOLE account (next == "" ⇒ the last
	// page) → existence-leak-safe deny (parity with the prior requireAccountAdmin →
	// PermissionDenied behaviour; a stranger must not learn the account exists nor get
	// an empty 200 distinguishing it). The authority precheck driving this is
	// requireGrantAuthority above — DIRECT per-object Checks, never a truncated
	// enumeration. See list_by_scope.go for why the emptiness clause is gated on the
	// last page rather than on any page.
	if len(out) == 0 && next == "" {
		return nil, "", authzguard.PermissionDenied()
	}
	return out, next, nil
}
